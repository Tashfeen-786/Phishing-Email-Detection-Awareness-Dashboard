"""
backend/config.py
=================
PURPOSE
-------
Single source of truth for configuration. Every value can be overridden with an
environment variable (see ``.env.example``) so that **no secret is ever
hard-coded in source control**.

Loading order
-------------
1. process environment variables (highest priority),
2. a ``.env`` file in the project root, if present,
3. the safe defaults defined here.

A tiny hand-written .env parser is used so the project has no dependency on
``python-dotenv``; the file format is the usual ``KEY=value`` with ``#`` comments.
"""

from __future__ import annotations

import os
import secrets
from pathlib import Path
from typing import List

# --------------------------------------------------------------------------
# Paths
# --------------------------------------------------------------------------
BASE_DIR = Path(__file__).resolve().parent.parent        # project root
BACKEND_DIR = BASE_DIR / "backend"
DATA_DIR = BASE_DIR / "data"
MODELS_DIR = BASE_DIR / "models"
REPORTS_DIR = BASE_DIR / "reports"
SCREENSHOTS_DIR = BASE_DIR / "screenshots"
SAMPLES_DIR = BASE_DIR / "samples"
LOGS_DIR = BASE_DIR / "logs"


def _load_dotenv(path: Path) -> None:
    """Populate ``os.environ`` from a .env file without overwriting real env vars."""
    if not path.exists():
        return
    try:
        for line in path.read_text(encoding="utf-8").splitlines():
            line = line.strip()
            if not line or line.startswith("#") or "=" not in line:
                continue
            key, _, value = line.partition("=")
            key = key.strip()
            value = value.strip().strip('"').strip("'")
            if key and key not in os.environ:
                os.environ[key] = value
    except OSError:
        pass


_load_dotenv(BASE_DIR / ".env")


def _get(name: str, default: str) -> str:
    return os.environ.get(name, default)


def _get_int(name: str, default: int) -> int:
    try:
        return int(os.environ.get(name, str(default)))
    except (TypeError, ValueError):
        return default


def _get_float(name: str, default: float) -> float:
    try:
        return float(os.environ.get(name, str(default)))
    except (TypeError, ValueError):
        return default


def _get_bool(name: str, default: bool) -> bool:
    return os.environ.get(name, str(default)).strip().lower() in {"1", "true", "yes", "on"}


class Settings:
    """Runtime settings object (instantiated once as ``settings`` below)."""

    # ---- application -----------------------------------------------------
    APP_NAME: str = _get("APP_NAME", "Phishing Email Detection & Awareness Dashboard")
    APP_VERSION: str = "1.0.0"
    ENVIRONMENT: str = _get("ENVIRONMENT", "development")
    DEBUG: bool = _get_bool("DEBUG", True)

    # ---- server ----------------------------------------------------------
    HOST: str = _get("BACKEND_HOST", "127.0.0.1")
    PORT: int = _get_int("BACKEND_PORT", 8000)

    # CORS: the Vite dev server origin. In production this must be an explicit
    # allow-list served over HTTPS - never "*" together with credentials.
    CORS_ORIGINS: List[str] = [
        o.strip() for o in _get(
            "CORS_ORIGINS",
            "http://localhost:5173,http://127.0.0.1:5173,http://localhost:4173,http://127.0.0.1:4173",
        ).split(",") if o.strip()
    ]
    CORS_ALLOW_ALL: bool = _get_bool("CORS_ALLOW_ALL", False)

    # ---- database --------------------------------------------------------
    DATABASE_PATH: Path = Path(_get("DATABASE_PATH", str(DATA_DIR / "phishing_analysis.db")))

    # ---- machine learning ------------------------------------------------
    MODEL_PATH: Path = Path(_get("MODEL_PATH", str(MODELS_DIR / "phishing_model.joblib")))
    ML_ENABLED: bool = _get_bool("ML_ENABLED", True)
    ML_DECISION_THRESHOLD: float = _get_float("ML_DECISION_THRESHOLD", 0.5)

    # ---- hybrid detection ------------------------------------------------
    # Weighted blend of the rule score and the ML probability. Documented as a
    # PROJECT ASSUMPTION - reports/ml_metrics.json shows the measured effect.
    HYBRID_RULE_WEIGHT: float = _get_float("HYBRID_RULE_WEIGHT", 0.6)
    HYBRID_ML_WEIGHT: float = _get_float("HYBRID_ML_WEIGHT", 0.4)

    # ---- privacy ---------------------------------------------------------
    # Email bodies are NOT stored by default. Only safe metadata is persisted.
    STORE_EMAIL_BODY: bool = _get_bool("STORE_EMAIL_BODY", False)
    SUBJECT_STORE_LIMIT: int = _get_int("SUBJECT_STORE_LIMIT", 200)

    # ---- uploads ---------------------------------------------------------
    MAX_UPLOAD_BYTES: int = _get_int("MAX_UPLOAD_BYTES", 262_144)      # 256 KB
    ALLOWED_UPLOAD_EXTENSIONS: List[str] = [
        e.strip().lower() for e in _get("ALLOWED_UPLOAD_EXTENSIONS", ".txt,.eml").split(",") if e.strip()
    ]

    # ---- rate limiting ---------------------------------------------------
    RATE_LIMIT_ENABLED: bool = _get_bool("RATE_LIMIT_ENABLED", True)
    RATE_LIMIT_REQUESTS: int = _get_int("RATE_LIMIT_REQUESTS", 120)
    RATE_LIMIT_WINDOW_SECONDS: int = _get_int("RATE_LIMIT_WINDOW_SECONDS", 60)

    # ---- authentication (optional) --------------------------------------
    # SECRET_KEY must be set explicitly in production. A random per-process key
    # is generated otherwise, which invalidates tokens on restart (safe default).
    SECRET_KEY: str = _get("SECRET_KEY", "") or secrets.token_urlsafe(48)
    TOKEN_TTL_SECONDS: int = _get_int("TOKEN_TTL_SECONDS", 3600)
    REQUIRE_AUTH: bool = _get_bool("REQUIRE_AUTH", False)

    # ---- logging ---------------------------------------------------------
    LOG_LEVEL: str = _get("LOG_LEVEL", "INFO")
    SECURITY_LOG_PATH: Path = Path(_get("SECURITY_LOG_PATH", str(LOGS_DIR / "security.log")))

    # ---- dataset ---------------------------------------------------------
    DATASET_PATH: Path = Path(_get("DATASET_PATH", str(DATA_DIR / "phishing_email_dataset.csv")))
    DATASET_SIZE: int = _get_int("DATASET_SIZE", 600)
    RANDOM_SEED: int = _get_int("RANDOM_SEED", 42)

    def ensure_directories(self) -> None:
        """Create every directory the application writes to."""
        for directory in (DATA_DIR, MODELS_DIR, REPORTS_DIR, SCREENSHOTS_DIR,
                          SAMPLES_DIR, LOGS_DIR):
            directory.mkdir(parents=True, exist_ok=True)
        self.DATABASE_PATH.parent.mkdir(parents=True, exist_ok=True)
        self.SECURITY_LOG_PATH.parent.mkdir(parents=True, exist_ok=True)


settings = Settings()
settings.ensure_directories()
