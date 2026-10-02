"""
backend/routes/dashboard_routes.py
==================================
Dashboard analytics endpoints.

===========================================================================
API CONTRACT
===========================================================================

GET /api/dashboard/stats
    Purpose        Everything the dashboard cards and charts need, in one call.
    Request        none
    Response 200   {
                     total_analyzed, likely_phishing, suspicious, moderate_risk,
                     low_risk, average_risk_score,
                     classification_distribution[], phishing_vs_legitimate[],
                     risk_histogram[], detection_trend[], top_sender_domains[],
                     recent_analyses[], urls_analyzed, suspicious_urls,
                     ml { available, model_name, test_metrics, ... }
                   }
    Auth           Not required.        Errors: 500 on database failure.

GET /api/dashboard/indicators
    Purpose        Top detected indicators and severity/category breakdown.
    Query          limit (1-50, default 12)
    Response 200   {top_indicators[], by_severity[], by_category[],
                    total_indicators, keyword_frequency[]}

GET /api/dashboard/keywords
    Purpose        "Most common suspicious keywords" chart. Derived from the
                   stored indicator types (the project does not store email
                   bodies, so keyword frequency is reconstructed from the
                   indicators that actually fired - this is stated in the UI).
    Response 200   {keywords: [{keyword, count, category}], source: "..."}

GET /api/dashboard/rules
    Purpose        Publish the rule weights and classification thresholds so
                   the scoring model is fully transparent to the user.
    Response 200   {rule_weights, bands, thresholds, assumption_note}
"""

from __future__ import annotations

from fastapi import APIRouter, Query

from backend.models import repository
from backend.models.database import db_session
from backend.services import ml_service
from backend.services.risk_engine import (
    BAND_MEANING,
    CLASSIFICATION_BANDS,
    RULE_LABELS,
    RULE_WEIGHTS,
)
from backend.services.attachment_analyzer import ATTACHMENT_SUSPICIOUS_THRESHOLD
from backend.services.sender_analyzer import SENDER_SUSPICIOUS_THRESHOLD
from backend.services.url_analyzer import URL_SUSPICIOUS_THRESHOLD

router = APIRouter(prefix="/api/dashboard", tags=["Dashboard"])

#: Maps a stored indicator type to the human phrase shown in the keyword chart.
_INDICATOR_TO_KEYWORD = {
    "URGENCY_LANGUAGE": ("urgent / act now", "URGENCY"),
    "THREAT_FEAR_LANGUAGE": ("account suspended / legal action", "FEAR"),
    "CREDENTIAL_REQUEST": ("verify your password", "CREDENTIALS"),
    "PERSONAL_INFO_REQUEST": ("confirm personal details", "PERSONAL DATA"),
    "FINANCIAL_PRESSURE": ("invoice / payment due", "FINANCIAL"),
    "REWARD_BAIT": ("you have won / prize", "REWARD"),
    "SUSPICIOUS_CALL_TO_ACTION": ("click here / open attached", "CALL TO ACTION"),
    "GENERIC_GREETING": ("dear customer / dear user", "GREETING"),
    "SUSPICIOUS_URL_KEYWORDS": ("login / verify inside URL", "URL"),
    "RAW_IP_URL": ("raw IP address link", "URL"),
    "NO_HTTPS": ("http:// link", "URL"),
    "URL_SHORTENER": ("shortened link", "URL"),
    "EXCESSIVE_SUBDOMAINS": ("deep subdomain chain", "URL"),
    "DECEPTIVE_URL_STRUCTURE": ("trust words in subdomain", "URL"),
    "SUSPICIOUS_SENDER_DOMAIN": ("security words in sender domain", "SENDER"),
    "DISPLAY_NAME_MISMATCH": ("display name mismatch", "SENDER"),
    "POSSIBLE_LOOKALIKE_DOMAIN": ("look-alike domain", "SENDER"),
    "EXECUTABLE_ATTACHMENT": (".exe / .scr attachment", "ATTACHMENT"),
    "SCRIPT_ATTACHMENT": (".js / .vbs / .ps1 attachment", "ATTACHMENT"),
    "DOUBLE_EXTENSION": ("invoice.pdf.exe", "ATTACHMENT"),
    "SUSPICIOUS_ARCHIVE": ("archive attachment", "ATTACHMENT"),
    "MACRO_ENABLED_DOCUMENT": ("macro-enabled document", "ATTACHMENT"),
    "FORMATTING_ANOMALY": ("SHOUTING / !!!", "FORMATTING"),
    "GRAMMAR_ANOMALY": ("writing anomalies", "GRAMMAR"),
}


@router.get("/stats", summary="Dashboard cards and chart data")
def dashboard_stats():
    """Aggregate statistics plus the real ML model status."""
    stats = repository.dashboard_stats()
    stats["ml"] = ml_service.model_info()
    return stats


@router.get("/indicators", summary="Top detected indicators")
def dashboard_indicators(limit: int = Query(default=12, ge=1, le=50)):
    """Most frequently triggered indicators, with severity and category splits."""
    data = repository.indicator_stats(limit=limit)
    data["labels"] = {k: v for k, v in RULE_LABELS.items()}
    return data


@router.get("/keywords", summary="Most common suspicious keyword categories")
def dashboard_keywords(limit: int = Query(default=10, ge=1, le=30)):
    """Frequency chart of the suspicious wording categories that actually fired.

    NOTE ON HONESTY: the project does not store email bodies (privacy by
    design), so this chart is built from the stored INDICATOR TYPES rather than
    from raw text. Each indicator type maps to the phrase family that triggered
    it. The ``source`` field states this in the response and the UI repeats it.
    """
    with db_session() as conn:
        rows = conn.execute(
            """SELECT indicator_type, COUNT(*) AS count FROM indicators
               WHERE severity != 'INFO' GROUP BY indicator_type ORDER BY count DESC"""
        ).fetchall()
    keywords = []
    for row in rows:
        mapping = _INDICATOR_TO_KEYWORD.get(row["indicator_type"])
        if mapping:
            keywords.append({"keyword": mapping[0], "category": mapping[1],
                             "count": int(row["count"]), "indicator_type": row["indicator_type"]})
    keywords.sort(key=lambda k: k["count"], reverse=True)
    return {
        "keywords": keywords[:limit],
        "source": ("Derived from stored indicator types. Email bodies are not stored, so raw "
                   "word frequencies are intentionally unavailable."),
    }


@router.get("/rules", summary="Published rule weights and thresholds")
def dashboard_rules():
    """Expose the entire scoring model so nothing about the score is hidden."""
    return {
        "rule_weights": RULE_WEIGHTS,
        "rule_labels": RULE_LABELS,
        "max_raw_score": sum(RULE_WEIGHTS.values()),
        "score_cap": 100,
        "bands": [{"min": lo, "max": hi, "label": lb, "meaning": BAND_MEANING[lb]}
                  for lo, hi, lb in CLASSIFICATION_BANDS],
        "analyzer_thresholds": {
            "sender_suspicious_at": SENDER_SUSPICIOUS_THRESHOLD,
            "url_suspicious_at": URL_SUSPICIOUS_THRESHOLD,
            "attachment_suspicious_at": ATTACHMENT_SUSPICIOUS_THRESHOLD,
        },
        "assumption_note": (
            "These weights and thresholds are PROJECT ASSUMPTIONS defined for this educational "
            "build, not values learned from production mail. They must be calibrated with "
            "representative validation data and analyst feedback before operational use."
        ),
    }
