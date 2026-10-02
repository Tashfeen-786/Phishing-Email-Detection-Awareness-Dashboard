"""
backend/models/repository.py
============================
PURPOSE
-------
All database reads and writes live here (the repository pattern). Routes never
write SQL directly, which means:

  * every query is parameterised in exactly one place -> no SQL injection,
  * the privacy policy (what is stored) is enforced centrally,
  * the storage engine could be swapped without touching the API layer.

PRIVACY ENFORCEMENT
-------------------
:func:`save_analysis` stores only safe metadata. The email body is written only
when ``STORE_EMAIL_BODY=true`` is explicitly set, and even then only a
truncated preview. URLs are stored in DEFANGED form.
"""

from __future__ import annotations

import json
import uuid
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional

from backend.config import settings
from backend.models.database import db_session
from backend.utils.text_utils import sanitize_text, truncate

# Columns the history endpoint is allowed to sort by (whitelist -> no injection).
SORTABLE_COLUMNS = {
    "created_at": "created_at",
    "risk_score": "risk_score",
    "classification": "classification",
    "sender_domain": "sender_domain",
    "subject": "subject",
}


def _now() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


# ---------------------------------------------------------------------------
# CREATE
# ---------------------------------------------------------------------------
def save_analysis(result: Dict[str, Any], source: str = "api",
                  db_path: Optional[Path] = None) -> str:
    """Persist one analysis (+ its indicators and URL rows). Returns the id.

    Only safe metadata is stored - see the privacy notes in database.py.
    """
    analysis_id = str(uuid.uuid4())
    inp = result.get("input", {})
    ml = result.get("ml_detection", {}) or {}
    hybrid = result.get("hybrid_detection", {}) or {}

    subject = truncate(sanitize_text(inp.get("subject", "")), settings.SUBJECT_STORE_LIMIT)
    body_preview = None
    body_stored = 0
    if settings.STORE_EMAIL_BODY:
        body_preview = truncate(sanitize_text(inp.get("body_preview", "")), 500)
        body_stored = 1

    with db_session(db_path) as conn:
        conn.execute(
            """
            INSERT INTO analyses (
                analysis_id, sender_domain, subject, risk_score, classification,
                risk_state, rule_score, ml_probability, hybrid_score,
                indicator_count, url_count, attachment_name, attachment_risk,
                sender_risk_score, source, body_stored, body_preview, created_at
            ) VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)
            """,
            (
                analysis_id,
                sanitize_text(inp.get("sender_domain", ""), 253),
                subject,
                int(result.get("risk_score", 0)),
                sanitize_text(result.get("classification", "LOW RISK"), 40),
                sanitize_text(result.get("risk_state", "SAFE"), 40),
                int(result.get("risk_score", 0)),
                float(ml["probability"]) if ml.get("probability") is not None else None,
                int(hybrid["combined_score"]) if hybrid.get("combined_score") is not None else None,
                int(result.get("indicator_count", 0)),
                int(inp.get("url_count", 0)),
                sanitize_text(inp.get("attachment_name", ""), 255),
                int(result.get("attachment_analysis", {}).get("attachment_risk", 0)),
                int(result.get("sender_analysis", {}).get("sender_risk_score", 0)),
                sanitize_text(source, 32),
                body_stored,
                body_preview,
                _now(),
            ),
        )

        for finding in result.get("indicators", []):
            conn.execute(
                """
                INSERT INTO indicators (analysis_id, indicator_type, category, description, severity)
                VALUES (?,?,?,?,?)
                """,
                (
                    analysis_id,
                    sanitize_text(finding.get("indicator_type", "UNKNOWN"), 64),
                    sanitize_text(finding.get("category", "GENERAL"), 32),
                    truncate(sanitize_text(finding.get("description", "")), 500),
                    sanitize_text(finding.get("severity", "INFO"), 16),
                ),
            )

        for url_report in result.get("url_analysis", {}).get("url_reports", []):
            descriptions = [
                truncate(sanitize_text(f.get("description", "")), 200)
                for f in url_report.get("url_findings", [])
                if f.get("severity") != "INFO"
            ]
            conn.execute(
                """
                INSERT INTO url_analyses
                    (analysis_id, url_safe_representation, risk_score, findings,
                     hostname, is_ip, uses_https, is_shortener)
                VALUES (?,?,?,?,?,?,?,?)
                """,
                (
                    analysis_id,
                    sanitize_text(url_report.get("safe_representation", ""), 2048),
                    int(url_report.get("url_risk_score", 0)),
                    json.dumps(descriptions, ensure_ascii=False),
                    sanitize_text(url_report.get("hostname", ""), 255),
                    int(bool(url_report.get("is_ip"))),
                    int(bool(url_report.get("uses_https"))),
                    int(bool(url_report.get("is_shortener"))),
                ),
            )
    return analysis_id


# ---------------------------------------------------------------------------
# READ
# ---------------------------------------------------------------------------
def list_analyses(
    classification: Optional[str] = None,
    search: Optional[str] = None,
    min_score: Optional[int] = None,
    max_score: Optional[int] = None,
    sort_by: str = "created_at",
    order: str = "desc",
    limit: int = 50,
    offset: int = 0,
    db_path: Optional[Path] = None,
) -> Dict[str, Any]:
    """Return a filtered, sorted, paginated page of the analysis history."""
    where: List[str] = []
    params: List[Any] = []

    if classification:
        where.append("UPPER(classification) = UPPER(?)")
        params.append(classification)
    if search:
        where.append("(subject LIKE ? OR sender_domain LIKE ?)")
        like = f"%{sanitize_text(search, 100)}%"
        params.extend([like, like])
    if min_score is not None:
        where.append("risk_score >= ?")
        params.append(int(min_score))
    if max_score is not None:
        where.append("risk_score <= ?")
        params.append(int(max_score))

    where_sql = ("WHERE " + " AND ".join(where)) if where else ""
    sort_column = SORTABLE_COLUMNS.get(sort_by, "created_at")
    direction = "ASC" if str(order).lower() == "asc" else "DESC"
    limit = max(1, min(int(limit), 500))
    offset = max(0, int(offset))

    with db_session(db_path) as conn:
        total = conn.execute(f"SELECT COUNT(*) AS c FROM analyses {where_sql}", params).fetchone()["c"]
        rows = conn.execute(
            f"""SELECT * FROM analyses {where_sql}
                ORDER BY {sort_column} {direction}, created_at DESC
                LIMIT ? OFFSET ?""",
            (*params, limit, offset),
        ).fetchall()
        items = [dict(r) for r in rows]
        for item in items:
            counts = conn.execute(
                """SELECT severity, COUNT(*) AS c FROM indicators
                   WHERE analysis_id = ? AND severity != 'INFO' GROUP BY severity""",
                (item["analysis_id"],),
            ).fetchall()
            item["severity_counts"] = {r["severity"]: r["c"] for r in counts}

    return {"items": items, "total": int(total), "limit": limit, "offset": offset,
            "sort_by": sort_column, "order": direction.lower()}


def get_analysis(analysis_id: str, db_path: Optional[Path] = None) -> Optional[Dict[str, Any]]:
    """Return one analysis with its indicators and URL rows, or ``None``."""
    with db_session(db_path) as conn:
        row = conn.execute("SELECT * FROM analyses WHERE analysis_id = ?", (analysis_id,)).fetchone()
        if row is None:
            return None
        record = dict(row)
        record["indicators"] = [dict(r) for r in conn.execute(
            """SELECT indicator_id, indicator_type, category, description, severity
               FROM indicators WHERE analysis_id = ?
               ORDER BY CASE severity WHEN 'HIGH' THEN 0 WHEN 'MEDIUM' THEN 1
                                      WHEN 'LOW' THEN 2 ELSE 3 END, indicator_id""",
            (analysis_id,),
        ).fetchall()]
        url_rows = [dict(r) for r in conn.execute(
            """SELECT url_analysis_id, url_safe_representation, risk_score, findings,
                      hostname, is_ip, uses_https, is_shortener
               FROM url_analyses WHERE analysis_id = ? ORDER BY risk_score DESC""",
            (analysis_id,),
        ).fetchall()]
    for u in url_rows:
        try:
            u["findings"] = json.loads(u["findings"])
        except (TypeError, json.JSONDecodeError):       # pragma: no cover
            u["findings"] = []
    record["url_analyses"] = url_rows
    return record


def delete_analysis(analysis_id: str, db_path: Optional[Path] = None) -> bool:
    """Delete one analysis. Indicators and URL rows cascade. True when removed."""
    with db_session(db_path) as conn:
        cur = conn.execute("DELETE FROM analyses WHERE analysis_id = ?", (analysis_id,))
        return cur.rowcount > 0


def delete_all_analyses(db_path: Optional[Path] = None) -> int:
    """Delete every analysis (used by the demo-seed script). Returns the count."""
    with db_session(db_path) as conn:
        count = conn.execute("SELECT COUNT(*) AS c FROM analyses").fetchone()["c"]
        conn.execute("DELETE FROM analyses")
    return int(count)


# ---------------------------------------------------------------------------
# DASHBOARD AGGREGATES
# ---------------------------------------------------------------------------
def dashboard_stats(db_path: Optional[Path] = None) -> Dict[str, Any]:
    """Aggregate statistics for the dashboard cards and charts."""
    from backend.services.risk_engine import CLASSIFICATIONS

    with db_session(db_path) as conn:
        total = conn.execute("SELECT COUNT(*) AS c FROM analyses").fetchone()["c"]
        avg_row = conn.execute("SELECT AVG(risk_score) AS a FROM analyses").fetchone()
        avg_score = round(float(avg_row["a"]), 2) if avg_row["a"] is not None else 0.0

        class_rows = conn.execute(
            "SELECT classification, COUNT(*) AS c FROM analyses GROUP BY classification"
        ).fetchall()
        class_counts = {c: 0 for c in CLASSIFICATIONS}
        for r in class_rows:
            class_counts[r["classification"]] = class_counts.get(r["classification"], 0) + r["c"]

        # Risk-score histogram in ten 0-9 / 10-19 ... buckets.
        hist_rows = conn.execute(
            """SELECT CAST(MIN(risk_score, 99) / 10 AS INTEGER) AS bucket, COUNT(*) AS c
               FROM analyses GROUP BY bucket ORDER BY bucket"""
        ).fetchall()
        histogram = [{"range": f"{i*10}-{i*10+9}", "count": 0} for i in range(10)]
        for r in hist_rows:
            idx = int(r["bucket"])
            if 0 <= idx < 10:
                histogram[idx]["count"] = int(r["c"])

        trend_rows = conn.execute(
            """SELECT substr(created_at, 1, 10) AS day,
                      COUNT(*) AS total,
                      SUM(CASE WHEN classification IN ('HIGH RISK / LIKELY PHISHING','SUSPICIOUS')
                               THEN 1 ELSE 0 END) AS high,
                      ROUND(AVG(risk_score), 2) AS avg_score
               FROM analyses
               GROUP BY day ORDER BY day DESC LIMIT 14"""
        ).fetchall()
        trend = [dict(r) for r in reversed(trend_rows)]

        domain_rows = conn.execute(
            """SELECT sender_domain, COUNT(*) AS c, ROUND(AVG(risk_score),1) AS avg_score
               FROM analyses WHERE sender_domain != ''
               GROUP BY sender_domain ORDER BY avg_score DESC, c DESC LIMIT 10"""
        ).fetchall()

        recent = conn.execute(
            """SELECT analysis_id, sender_domain, subject, risk_score, classification, created_at
               FROM analyses ORDER BY created_at DESC LIMIT 8"""
        ).fetchall()

        phishing_like = class_counts.get("HIGH RISK / LIKELY PHISHING", 0)
        suspicious = class_counts.get("SUSPICIOUS", 0)
        moderate = class_counts.get("MODERATE RISK", 0)
        low = class_counts.get("LOW RISK", 0)

        url_row = conn.execute(
            """SELECT COUNT(*) AS c, SUM(CASE WHEN risk_score >= 30 THEN 1 ELSE 0 END) AS sus
               FROM url_analyses"""
        ).fetchone()

    return {
        "total_analyzed": int(total),
        "likely_phishing": int(phishing_like),
        "suspicious": int(suspicious),
        "moderate_risk": int(moderate),
        "low_risk": int(low),
        "average_risk_score": avg_score,
        "classification_distribution": [
            {"classification": k, "count": v} for k, v in class_counts.items()
        ],
        "phishing_vs_legitimate": [
            {"name": "Likely phishing / suspicious", "count": int(phishing_like + suspicious)},
            {"name": "Low / moderate risk", "count": int(low + moderate)},
        ],
        "risk_histogram": histogram,
        "detection_trend": trend,
        "top_sender_domains": [dict(r) for r in domain_rows],
        "recent_analyses": [dict(r) for r in recent],
        "urls_analyzed": int(url_row["c"] or 0),
        "suspicious_urls": int(url_row["sus"] or 0),
        "generated_at": _now(),
    }


def indicator_stats(limit: int = 12, db_path: Optional[Path] = None) -> Dict[str, Any]:
    """Top detected indicators + severity breakdown (dashboard charts)."""
    with db_session(db_path) as conn:
        top = conn.execute(
            """SELECT indicator_type, category, severity, COUNT(*) AS count
               FROM indicators WHERE severity != 'INFO'
               GROUP BY indicator_type ORDER BY count DESC, indicator_type LIMIT ?""",
            (max(1, min(int(limit), 50)),),
        ).fetchall()
        by_severity = conn.execute(
            """SELECT severity, COUNT(*) AS count FROM indicators
               WHERE severity != 'INFO' GROUP BY severity"""
        ).fetchall()
        by_category = conn.execute(
            """SELECT category, COUNT(*) AS count FROM indicators
               WHERE severity != 'INFO' GROUP BY category ORDER BY count DESC"""
        ).fetchall()
        total = conn.execute(
            "SELECT COUNT(*) AS c FROM indicators WHERE severity != 'INFO'"
        ).fetchone()["c"]
    return {
        "top_indicators": [dict(r) for r in top],
        "by_severity": [dict(r) for r in by_severity],
        "by_category": [dict(r) for r in by_category],
        "total_indicators": int(total),
    }


# ---------------------------------------------------------------------------
# USERS (optional authentication)
# ---------------------------------------------------------------------------
def create_user(username: str, password_hash: str, role: str = "analyst",
                db_path: Optional[Path] = None) -> Dict[str, Any]:
    """Insert a user. Raises ``sqlite3.IntegrityError`` when the name is taken."""
    user_id = str(uuid.uuid4())
    with db_session(db_path) as conn:
        conn.execute(
            "INSERT INTO users (user_id, username, password_hash, role, created_at) VALUES (?,?,?,?,?)",
            (user_id, sanitize_text(username, 64), password_hash, sanitize_text(role, 16), _now()),
        )
    return {"user_id": user_id, "username": username, "role": role}


def get_user(username: str, db_path: Optional[Path] = None) -> Optional[Dict[str, Any]]:
    """Fetch a user row by username (or ``None``)."""
    with db_session(db_path) as conn:
        row = conn.execute("SELECT * FROM users WHERE username = ?",
                           (sanitize_text(username, 64),)).fetchone()
    return dict(row) if row else None


def count_users(db_path: Optional[Path] = None) -> int:
    with db_session(db_path) as conn:
        return int(conn.execute("SELECT COUNT(*) AS c FROM users").fetchone()["c"])
