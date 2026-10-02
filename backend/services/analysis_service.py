"""
backend/services/analysis_service.py
====================================
PURPOSE
-------
The ORCHESTRATOR. This module runs the complete detection workflow defined in
the project brief, in order, exactly once per request:

    Email Input
        -> Preprocessing
        -> Sender Analysis
        -> Subject Analysis
        -> Content Analysis
        -> URL Analysis            (static, never fetched)
        -> Attachment Analysis     (filename only, never executed)
        -> Feature Extraction
        -> Rule-Based Detection
        -> Machine Learning Detection   (optional)
        -> Hybrid Detection             (optional)
        -> Risk Score
        -> Classification
        -> Explainable Findings
        -> Security Recommendations
        -> Database / History
        -> Dashboard

The API layer stays thin: it validates input, calls :func:`analyze_email`, and
serialises the result.
"""

from __future__ import annotations

from datetime import datetime, timezone
from typing import Any, Dict, List, Optional

from backend.config import settings
from backend.services import ml_service
from backend.services.content_analyzer import analyze_subject
from backend.services.feature_extractor import extract_email_features
from backend.services.risk_engine import (
    build_recommendations,
    calculate_phishing_score,
)
from backend.utils.text_utils import defang_url, truncate
from backend.utils.logger import log_security_event


def _collect_indicators(sender_report, content_report, url_report, attachment_report) -> List[Dict[str, Any]]:
    """Flatten every analyzer's findings into one explainable indicator list."""
    indicators: List[Dict[str, Any]] = []
    indicators.extend(sender_report.get("sender_findings", []))
    indicators.extend(content_report.get("content_findings", []))
    for report in url_report.get("url_reports", []):
        for finding in report.get("url_findings", []):
            item = dict(finding)
            item["url"] = report["safe_representation"]
            indicators.append(item)
    indicators.extend(attachment_report.get("attachment_findings", []))

    severity_order = {"HIGH": 0, "MEDIUM": 1, "LOW": 2, "INFO": 3}
    indicators.sort(key=lambda f: severity_order.get(f.get("severity", "INFO"), 4))
    return indicators


def analyze_email(
    sender: str,
    subject: str,
    body: str,
    urls: Optional[str | List[str]] = None,
    attachment_name: Optional[str] = None,
    display_name: Optional[str] = None,
    use_ml: bool = True,
) -> Dict[str, Any]:
    """Run the complete phishing analysis workflow for one email.

    Returns a JSON-serialisable dictionary containing every stage of the
    pipeline. Nothing is persisted here - the route layer decides whether to
    save, which keeps this function usable from tests and scripts.
    """
    started = datetime.now(timezone.utc)

    # ---- 1-7: preprocessing + all analyzers + feature extraction -----------
    features = extract_email_features(
        sender=sender, subject=subject, body=body, urls=urls,
        attachment_name=attachment_name, display_name=display_name,
        return_analyses=True,
    )
    analyses = features.pop("_analyses")
    pre = analyses["preprocessed"]
    sender_report = analyses["sender"]
    content_report = analyses["content"]
    url_report = analyses["urls"]
    attachment_report = analyses["attachment"]
    subject_report = analyze_subject(pre["subject"])

    # ---- 8: rule-based detection ------------------------------------------
    risk = calculate_phishing_score(
        sender_report, content_report, url_report, attachment_report, features
    )

    # ---- 9: machine learning (optional) -----------------------------------
    if use_ml and settings.ML_ENABLED:
        ml_result = ml_service.predict_email(pre["ml_text"], features)
    else:
        ml_result = {"available": False, "reason": "ML disabled for this request.",
                     "probability": None, "prediction": None}

    # ---- 10: hybrid detection ---------------------------------------------
    hybrid = ml_service.hybrid_score(risk["risk_score"], ml_result)

    # ---- 11: explainable findings -----------------------------------------
    indicators = _collect_indicators(sender_report, content_report, url_report, attachment_report)

    # ---- 12: recommendations ----------------------------------------------
    recommendations = build_recommendations(
        risk["classification"],
        risk["triggered_rules"],
        has_urls=url_report["url_count"] > 0,
        has_attachment=bool(pre["attachment_name"]),
    )

    duration_ms = int((datetime.now(timezone.utc) - started).total_seconds() * 1000)

    log_security_event(
        "analysis.completed",
        sender_domain=pre["sender_domain"] or "<none>",
        subject=truncate(pre["subject"], 80),
        risk_score=risk["risk_score"],
        classification=risk["classification"],
        url_count=url_report["url_count"],
        attachment=pre["attachment_name"] or "<none>",
        ml_available=bool(ml_result.get("available")),
        duration_ms=duration_ms,
    )

    return {
        "analyzed_at": started.isoformat(),
        "duration_ms": duration_ms,

        # ---------------- input echo (safe, defanged) ----------------------
        "input": {
            "sender": pre["sender"],
            "sender_domain": pre["sender_domain"],
            "sender_display_name": pre["sender_display_name"],
            "subject": pre["subject"],
            "body_preview": truncate(pre["body"], 400),
            "body_length": len(pre["body"]),
            "attachment_name": pre["attachment_name"],
            "urls_safe": [defang_url(u) for u in pre["urls"]],
            "url_count": pre["url_count"],
        },

        # ---------------- scoring ------------------------------------------
        "risk_score": risk["risk_score"],
        "raw_score": risk["raw_score"],
        "cap_applied": risk["cap_applied"],
        "classification": risk["classification"],
        "risk_state": risk["risk_state"],
        "band_meaning": risk["band_meaning"],
        "why": risk["why"],
        "triggered_rules": risk["triggered_rules"],
        "rule_contributions": risk["rule_contributions"],
        "rule_weights": risk["rule_weights"],
        "thresholds": risk["thresholds"],
        "bands": risk["bands"],
        "assumption_note": risk["assumption_note"],

        # ---------------- per-analyzer detail -------------------------------
        "sender_analysis": sender_report,
        "subject_analysis": subject_report,
        "content_analysis": content_report,
        "url_analysis": url_report,
        "attachment_analysis": attachment_report,

        # ---------------- features / ML -------------------------------------
        "features": features,
        "ml_detection": ml_result,
        "hybrid_detection": hybrid,

        # ---------------- explainability -------------------------------------
        "indicators": indicators,
        "indicator_count": len([i for i in indicators if i.get("severity") != "INFO"]),
        "recommendations": recommendations,

        # ---------------- honesty notes ---------------------------------------
        "detection_notes": [
            "No single indicator proves that an email is phishing. This assessment combines "
            "sender, subject, body, URL and attachment signals.",
            "URLs were analysed as text only. The application never opens or resolves a link.",
            "Attachments were assessed from the filename alone. Nothing was downloaded, "
            "unpacked or executed.",
            "A low score is not a guarantee of safety: a carefully written phishing email can "
            "avoid every indicator checked here (a false negative).",
            "A high score is not proof: legitimate mail can be urgent and can contain links "
            "(a false positive). Analyst judgement remains the final step.",
        ],
    }


def analyze_single_url(url: str, display_text: Optional[str] = None) -> Dict[str, Any]:
    """Static analysis of one URL for the dedicated /api/analyze/url endpoint."""
    from backend.services.url_analyzer import analyze_url

    report = analyze_url(url, display_text)
    log_security_event(
        "url_analysis.completed",
        url_safe=report["safe_representation"],
        risk_score=report["url_risk_score"],
        suspicious=report["suspicious"],
    )
    report["notes"] = [
        "This analysis is purely static. The URL was never opened, resolved or fetched.",
        "HTTPS only means the connection is encrypted. It does not mean the site is genuine - "
        "certificates are free and automated, so phishing sites use HTTPS too.",
        "Read a hostname from the right: the registrable domain immediately before the first "
        "single slash is the real owner of the page.",
    ]
    return report
