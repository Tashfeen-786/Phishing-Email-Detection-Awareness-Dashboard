"""
backend/utils/logger.py
=======================
PURPOSE
-------
Application and *security* logging.

WHY A SEPARATE SECURITY LOG?
----------------------------
In a SOC you need an auditable trail that answers "who did what, when".
This project logs security-relevant events (analysis performed, upload
rejected, rate limit hit, login failure, record deleted) to
``logs/security.log`` in a stable, greppable format.

PRIVACY
-------
The security log records METADATA only: sender domain, truncated subject,
risk score, classification, client IP. It never records the email body, and
never records passwords or tokens.
"""

from __future__ import annotations

import logging
from logging.handlers import RotatingFileHandler
from typing import Any, Dict

from backend.config import settings

_FORMAT = "%(asctime)s | %(levelname)-8s | %(name)s | %(message)s"
_DATEFMT = "%Y-%m-%d %H:%M:%S"


def _build_logger(name: str, filename, level: str) -> logging.Logger:
    logger = logging.getLogger(name)
    if logger.handlers:                      # already configured
        return logger
    logger.setLevel(getattr(logging, level.upper(), logging.INFO))
    logger.propagate = False

    formatter = logging.Formatter(_FORMAT, datefmt=_DATEFMT)

    console = logging.StreamHandler()
    console.setFormatter(formatter)
    logger.addHandler(console)

    try:
        filename.parent.mkdir(parents=True, exist_ok=True)
        file_handler = RotatingFileHandler(
            filename, maxBytes=1_048_576, backupCount=3, encoding="utf-8"
        )
        file_handler.setFormatter(formatter)
        logger.addHandler(file_handler)
    except OSError:
        # Logging must never take the application down.
        pass
    return logger


app_logger = _build_logger("phishguard.app", settings.SECURITY_LOG_PATH.parent / "app.log", settings.LOG_LEVEL)
security_logger = _build_logger("phishguard.security", settings.SECURITY_LOG_PATH, settings.LOG_LEVEL)


def log_security_event(event: str, **fields: Any) -> None:
    """Write one structured security event.

    Example
    -------
    >>> log_security_event("analysis.completed", sender_domain="example.org",
    ...                    risk_score=12, classification="LOW RISK")
    2026-09-30 10:00:00 | INFO | phishguard.security | event=analysis.completed
    sender_domain=example.org risk_score=12 classification='LOW RISK'
    """
    safe: Dict[str, Any] = {}
    for key, value in fields.items():
        if key.lower() in {"password", "token", "secret", "authorization", "body", "body_text"}:
            safe[key] = "<redacted>"
        elif isinstance(value, str) and len(value) > 200:
            safe[key] = value[:197] + "..."
        else:
            safe[key] = value
    payload = " ".join(f"{k}={v!r}" if isinstance(v, str) else f"{k}={v}" for k, v in safe.items())
    security_logger.info("event=%s %s", event, payload)
