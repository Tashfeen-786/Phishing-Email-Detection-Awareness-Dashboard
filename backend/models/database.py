"""
backend/models/database.py
==========================
PURPOSE
-------
SQLite schema, connection handling and initialisation.

===========================================================================
SCHEMA AND RELATIONSHIPS
===========================================================================

  analyses (1) ----< (many) indicators
       |
       +----------< (many) url_analyses

  users  (optional, only used when authentication is enabled)

ANALYSES
    analysis_id     TEXT  PRIMARY KEY   UUID4 string
    sender_domain   TEXT                only the domain, never the full address
    subject         TEXT                truncated to SUBJECT_STORE_LIMIT chars
    risk_score      INTEGER             0-100
    classification  TEXT                one of the four bands
    created_at      TEXT                ISO-8601 UTC
    (plus safe operational metadata: rule/ML/hybrid scores, counts)

INDICATORS                              -> one row per explainable finding
    indicator_id    INTEGER PRIMARY KEY AUTOINCREMENT
    analysis_id     TEXT    FOREIGN KEY -> analyses(analysis_id) ON DELETE CASCADE
    indicator_type  TEXT
    description     TEXT
    severity        TEXT                HIGH | MEDIUM | LOW | INFO

URL_ANALYSES                            -> one row per URL inspected
    url_analysis_id        INTEGER PRIMARY KEY AUTOINCREMENT
    analysis_id            TEXT FOREIGN KEY -> analyses(analysis_id) ON DELETE CASCADE
    url_safe_representation TEXT         DEFANGED form (hxxp://1[.]2[.]3[.]4/)
    risk_score             INTEGER
    findings               TEXT          JSON array of finding descriptions

USERS (optional)
    user_id         TEXT PRIMARY KEY
    username        TEXT UNIQUE
    password_hash   TEXT                PBKDF2-HMAC-SHA256, salted, 200k iters
    role            TEXT                'analyst' | 'admin'
    created_at      TEXT

===========================================================================
PRIVACY BY DESIGN
===========================================================================
* The email BODY is NOT stored by default (``STORE_EMAIL_BODY=false``). Storing
  raw message bodies turns an analysis tool into a repository of other people's
  mail - an attractive target and a data-protection liability.
* Only the sender DOMAIN is stored, never the full sender address.
* The subject is truncated.
* Every stored URL is DEFANGED so that no row in the database can be clicked.
* ``PRAGMA foreign_keys = ON`` is enabled per connection so deleting an analysis
  cascades to its indicators and URL rows - no orphaned evidence is left behind.
"""

from __future__ import annotations

import sqlite3
from contextlib import contextmanager
from pathlib import Path
from typing import Iterator, Optional

from backend.config import settings
from backend.utils.logger import app_logger

SCHEMA_VERSION = 2

CREATE_ANALYSES = """
CREATE TABLE IF NOT EXISTS analyses (
    analysis_id       TEXT PRIMARY KEY,
    sender_domain     TEXT    NOT NULL DEFAULT '',
    subject           TEXT    NOT NULL DEFAULT '',
    risk_score        INTEGER NOT NULL DEFAULT 0,
    classification    TEXT    NOT NULL DEFAULT 'LOW RISK',
    risk_state        TEXT    NOT NULL DEFAULT 'SAFE',
    rule_score        INTEGER NOT NULL DEFAULT 0,
    ml_probability    REAL,
    hybrid_score      INTEGER,
    indicator_count   INTEGER NOT NULL DEFAULT 0,
    url_count         INTEGER NOT NULL DEFAULT 0,
    attachment_name   TEXT    NOT NULL DEFAULT '',
    attachment_risk   INTEGER NOT NULL DEFAULT 0,
    sender_risk_score INTEGER NOT NULL DEFAULT 0,
    source            TEXT    NOT NULL DEFAULT 'api',
    body_stored       INTEGER NOT NULL DEFAULT 0,
    body_preview      TEXT,
    created_at        TEXT    NOT NULL
);
"""

CREATE_INDICATORS = """
CREATE TABLE IF NOT EXISTS indicators (
    indicator_id   INTEGER PRIMARY KEY AUTOINCREMENT,
    analysis_id    TEXT NOT NULL,
    indicator_type TEXT NOT NULL,
    category       TEXT NOT NULL DEFAULT 'GENERAL',
    description    TEXT NOT NULL DEFAULT '',
    severity       TEXT NOT NULL DEFAULT 'INFO',
    FOREIGN KEY (analysis_id) REFERENCES analyses (analysis_id) ON DELETE CASCADE
);
"""

CREATE_URL_ANALYSES = """
CREATE TABLE IF NOT EXISTS url_analyses (
    url_analysis_id         INTEGER PRIMARY KEY AUTOINCREMENT,
    analysis_id             TEXT NOT NULL,
    url_safe_representation TEXT NOT NULL DEFAULT '',
    risk_score              INTEGER NOT NULL DEFAULT 0,
    findings                TEXT NOT NULL DEFAULT '[]',
    -- schema v2: the structured flags an analyst wants at a glance, so the
    -- stored report is as informative as the live one.
    hostname                TEXT NOT NULL DEFAULT '',
    is_ip                   INTEGER NOT NULL DEFAULT 0,
    uses_https              INTEGER NOT NULL DEFAULT 0,
    is_shortener            INTEGER NOT NULL DEFAULT 0,
    FOREIGN KEY (analysis_id) REFERENCES analyses (analysis_id) ON DELETE CASCADE
);
"""

CREATE_USERS = """
CREATE TABLE IF NOT EXISTS users (
    user_id       TEXT PRIMARY KEY,
    username      TEXT NOT NULL UNIQUE,
    password_hash TEXT NOT NULL,
    role          TEXT NOT NULL DEFAULT 'analyst',
    created_at    TEXT NOT NULL
);
"""

CREATE_META = """
CREATE TABLE IF NOT EXISTS schema_meta (
    key   TEXT PRIMARY KEY,
    value TEXT NOT NULL
);
"""

CREATE_INDEXES = [
    "CREATE INDEX IF NOT EXISTS idx_analyses_created_at     ON analyses (created_at DESC);",
    "CREATE INDEX IF NOT EXISTS idx_analyses_classification ON analyses (classification);",
    "CREATE INDEX IF NOT EXISTS idx_analyses_risk_score     ON analyses (risk_score DESC);",
    "CREATE INDEX IF NOT EXISTS idx_analyses_sender_domain  ON analyses (sender_domain);",
    "CREATE INDEX IF NOT EXISTS idx_indicators_analysis     ON indicators (analysis_id);",
    "CREATE INDEX IF NOT EXISTS idx_indicators_type         ON indicators (indicator_type);",
    "CREATE INDEX IF NOT EXISTS idx_url_analyses_analysis   ON url_analyses (analysis_id);",
]


def get_database_path() -> Path:
    """Current database path (re-read each call so tests can override it)."""
    return Path(settings.DATABASE_PATH)


def get_connection(db_path: Optional[Path] = None) -> sqlite3.Connection:
    """Open a SQLite connection with safe, consistent settings.

    * ``row_factory = sqlite3.Row`` -> dict-like rows
    * ``PRAGMA foreign_keys = ON``  -> cascading deletes actually work
    * ``PRAGMA journal_mode = WAL`` -> readers do not block the writer
    * parameterised queries everywhere -> no SQL injection
    """
    path = Path(db_path) if db_path else get_database_path()
    path.parent.mkdir(parents=True, exist_ok=True)
    conn = sqlite3.connect(str(path), timeout=15.0, check_same_thread=False)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA foreign_keys = ON;")
    try:
        conn.execute("PRAGMA journal_mode = WAL;")
    except sqlite3.DatabaseError:                       # pragma: no cover
        pass
    return conn


@contextmanager
def db_session(db_path: Optional[Path] = None) -> Iterator[sqlite3.Connection]:
    """Context manager that commits on success and rolls back on error."""
    conn = get_connection(db_path)
    try:
        yield conn
        conn.commit()
    except Exception:
        conn.rollback()
        raise
    finally:
        conn.close()


def _migrate(conn: sqlite3.Connection) -> None:
    """Add columns introduced after v1 to an existing database.

    SQLite cannot express "ADD COLUMN IF NOT EXISTS", so the existing columns
    are read first. This keeps an older database working instead of forcing the
    user to delete it, which is exactly the kind of breakage a beginner cannot
    debug.
    """
    existing = {row[1] for row in conn.execute("PRAGMA table_info(url_analyses)")}
    for column, ddl in (
        ("hostname", "TEXT NOT NULL DEFAULT ''"),
        ("is_ip", "INTEGER NOT NULL DEFAULT 0"),
        ("uses_https", "INTEGER NOT NULL DEFAULT 0"),
        ("is_shortener", "INTEGER NOT NULL DEFAULT 0"),
    ):
        if column not in existing:
            conn.execute(f"ALTER TABLE url_analyses ADD COLUMN {column} {ddl}")
            app_logger.info("Schema migration: added url_analyses.%s", column)


def init_db(db_path: Optional[Path] = None) -> Path:
    """Create all tables and indexes. Safe to call repeatedly (idempotent)."""
    path = Path(db_path) if db_path else get_database_path()
    with db_session(path) as conn:
        conn.execute(CREATE_ANALYSES)
        conn.execute(CREATE_INDICATORS)
        conn.execute(CREATE_URL_ANALYSES)
        conn.execute(CREATE_USERS)
        conn.execute(CREATE_META)
        _migrate(conn)
        for stmt in CREATE_INDEXES:
            conn.execute(stmt)
        conn.execute(
            "INSERT INTO schema_meta (key, value) VALUES ('schema_version', ?) "
            "ON CONFLICT(key) DO UPDATE SET value = excluded.value",
            (str(SCHEMA_VERSION),),
        )
    app_logger.info("Database initialised at %s (schema v%s)", path, SCHEMA_VERSION)
    return path


def reset_db(db_path: Optional[Path] = None) -> Path:
    """Drop and recreate every table. Used by ``scripts/seed_demo.py`` and tests."""
    path = Path(db_path) if db_path else get_database_path()
    with db_session(path) as conn:
        for table in ("indicators", "url_analyses", "analyses", "users", "schema_meta"):
            conn.execute(f"DROP TABLE IF EXISTS {table};")
    return init_db(path)


def table_names(db_path: Optional[Path] = None) -> list[str]:
    """Return the list of tables (used by the validation script and tests)."""
    with db_session(db_path) as conn:
        rows = conn.execute(
            "SELECT name FROM sqlite_master WHERE type='table' ORDER BY name"
        ).fetchall()
    return [r["name"] for r in rows]
