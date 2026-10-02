"""
backend/services/risk_engine.py
===============================
PURPOSE
-------
The transparent, rule-based phishing risk engine.

    calculate_phishing_score(...)  ->  score 0-100 + per-rule contributions
    classify_risk(score)           ->  classification band
    build_recommendations(...)     ->  actionable defensive guidance

===========================================================================
RULE WEIGHTS (exactly as specified in the project brief)
===========================================================================
    Suspicious Sender        +15
    Urgency                  +10
    Credential Request       +20
    Suspicious URL           +20
    Suspicious Attachment    +25
    Generic Greeting          +5
    Threat / Fear Language   +10
    ------------------------------
    theoretical maximum      105  -> capped at 100

===========================================================================
CLASSIFICATION THRESHOLDS (exactly as specified in the project brief)
===========================================================================
      0 - 20   LOW RISK
     21 - 40   MODERATE RISK
     41 - 70   SUSPICIOUS
     71 - 100  HIGH RISK / LIKELY PHISHING

A supplementary ``risk_state`` of "SAFE" is reported when the score is exactly
0 (no rule fired at all). SAFE is a *label inside* the 0-20 LOW RISK band, not
a new threshold - no unsupported boundary has been invented.

===========================================================================
>>> THESE NUMBERS ARE PROJECT ASSUMPTIONS <<<
===========================================================================
The weights and the band boundaries were specified for this educational
project. They were NOT derived from a labelled corpus of real mail. Before any
production use they must be calibrated against representative validation data
and analyst feedback, because the right operating point depends entirely on how
an organisation values a false positive against a false negative.
``ml/evaluation.py`` measures how this fixed rule set actually performs on the
held-out test split, so the assumption is at least quantified.

The score is a TRIAGE AID. It is never proof. The engine therefore always
returns *why* it scored what it scored.
"""

from __future__ import annotations

from typing import Any, Dict, List, Optional

from backend.services.attachment_analyzer import ATTACHMENT_SUSPICIOUS_THRESHOLD
from backend.services.sender_analyzer import SENDER_SUSPICIOUS_THRESHOLD
from backend.services.url_analyzer import URL_SUSPICIOUS_THRESHOLD

# ---------------------------------------------------------------------------
# Rule weights - the seven weights defined by the project brief
# ---------------------------------------------------------------------------
RULE_WEIGHTS: Dict[str, int] = {
    "SUSPICIOUS_SENDER": 15,
    "URGENCY": 10,
    "CREDENTIAL_REQUEST": 20,
    "SUSPICIOUS_URL": 20,
    "SUSPICIOUS_ATTACHMENT": 25,
    "GENERIC_GREETING": 5,
    "THREAT_FEAR_LANGUAGE": 10,
}

MAX_RAW_SCORE = sum(RULE_WEIGHTS.values())          # 105
SCORE_CAP = 100

#: Classification bands - (inclusive_low, inclusive_high, label)
CLASSIFICATION_BANDS = [
    (0, 20, "LOW RISK"),
    (21, 40, "MODERATE RISK"),
    (41, 70, "SUSPICIOUS"),
    (71, 100, "HIGH RISK / LIKELY PHISHING"),
]

CLASSIFICATIONS = [band[2] for band in CLASSIFICATION_BANDS]

#: Short, plain-English meaning for each band (shown in the dashboard).
BAND_MEANING = {
    "LOW RISK": "No strong phishing indicators were found. Normal caution still applies.",
    "MODERATE RISK": "Some indicators were found. Verify anything the email asks you to do.",
    "SUSPICIOUS": "Several indicators combine here. Do not act on this email without "
                  "independent verification; report it if it claims to be from your organisation.",
    "HIGH RISK / LIKELY PHISHING": "A strong combination of indicators was detected. Treat this "
                                   "as phishing: do not click, do not reply, do not open "
                                   "attachments - report it.",
}

#: Human-readable rule names for the UI.
RULE_LABELS = {
    "SUSPICIOUS_SENDER": "Suspicious sender pattern",
    "URGENCY": "Urgent language detected",
    "CREDENTIAL_REQUEST": "Credential request detected",
    "SUSPICIOUS_URL": "Suspicious URL structure",
    "SUSPICIOUS_ATTACHMENT": "Attachment requires caution",
    "GENERIC_GREETING": "Generic greeting used",
    "THREAT_FEAR_LANGUAGE": "Threat / fear language detected",
}


def classify_risk(score: int) -> str:
    """Map a 0-100 score to its classification band."""
    score = max(0, min(SCORE_CAP, int(round(score))))
    for low, high, label in CLASSIFICATION_BANDS:
        if low <= score <= high:
            return label
    return CLASSIFICATION_BANDS[-1][2]                # pragma: no cover


def risk_state(score: int) -> str:
    """Supplementary state. 'SAFE' only when nothing at all fired."""
    return "SAFE" if int(round(score)) == 0 else classify_risk(score)


def calculate_phishing_score(
    sender_report: Dict[str, Any],
    content_report: Dict[str, Any],
    url_report: Dict[str, Any],
    attachment_report: Dict[str, Any],
    features: Optional[Dict[str, Any]] = None,
) -> Dict[str, Any]:
    """Combine analyzer outputs into an explainable rule-based risk score.

    Parameters
    ----------
    sender_report:      output of ``analyze_sender``
    content_report:     output of ``analyze_email_content``
    url_report:         output of ``analyze_urls``
    attachment_report:  output of ``analyze_attachment`` (or ``analyze_attachments``)
    features:           optional feature dict (only used for extra context strings)

    Returns
    -------
    dict with
        ``risk_score``      int 0-100 (capped)
        ``raw_score``       int, uncapped sum (shows when the cap engaged)
        ``classification``  one of :data:`CLASSIFICATIONS`
        ``risk_state``      classification, or "SAFE" when the score is 0
        ``triggered_rules`` list of dicts: rule, label, weight, reason, evidence
        ``rule_contributions`` {rule: weight} for the chart
        ``why``             list[str] - the "WHY?" bullet list
        ``band_meaning``    plain-English meaning of the band
        ``cap_applied``     bool
        ``assumption_note`` the calibration disclaimer
    """
    flags = content_report.get("flags", {})
    triggered: List[Dict[str, Any]] = []

    def fire(rule: str, reason: str, evidence: str = "") -> None:
        triggered.append({
            "rule": rule,
            "label": RULE_LABELS[rule],
            "weight": RULE_WEIGHTS[rule],
            "reason": reason,
            "evidence": evidence[:200],
        })

    # ------------------------------------------------ 1. Suspicious sender +15
    sender_score = int(sender_report.get("sender_risk_score", 0))
    if sender_score >= SENDER_SUSPICIOUS_THRESHOLD:
        top = [f for f in sender_report.get("sender_findings", []) if f.get("severity") in ("HIGH", "MEDIUM")]
        reason = (f"The sender analyzer scored {sender_score}/100 "
                  f"(threshold {SENDER_SUSPICIOUS_THRESHOLD}). "
                  + (top[0]["description"].split(".")[0] + "." if top else ""))
        fire("SUSPICIOUS_SENDER", reason, sender_report.get("address", ""))

    # -------------------------------------------------------- 2. Urgency +10
    if flags.get("urgency"):
        kws = content_report["categories"]["URGENCY"]["keywords"][:4]
        fire("URGENCY",
             "Time-pressure wording was found in the subject or body. Urgency is used to stop "
             "the reader from verifying before acting.",
             ", ".join(kws))

    # --------------------------------------------- 3. Credential request +20
    if flags.get("credential_request"):
        ev = content_report["categories"]["CREDENTIAL_REQUEST"]["keywords"][:2]
        fire("CREDENTIAL_REQUEST",
             "The email asks the reader to verify, confirm, re-enter or reset credentials. "
             "Legitimate organisations do not request passwords, OTPs or PINs by email.",
             "; ".join(ev))

    # --------------------------------------------------- 4. Suspicious URL +20
    max_url_risk = int(url_report.get("max_url_risk", 0))
    if max_url_risk >= URL_SUSPICIOUS_THRESHOLD:
        worst = max(url_report.get("url_reports", []),
                    key=lambda r: r["url_risk_score"], default=None)
        ev = worst["safe_representation"] if worst else ""
        fire("SUSPICIOUS_URL",
             f"At least one URL reached a static risk score of {max_url_risk}/100 "
             f"(threshold {URL_SUSPICIOUS_THRESHOLD}). The link was analysed as text only - "
             "it was never opened.",
             ev)

    # -------------------------------------------- 5. Suspicious attachment +25
    attach_risk = int(attachment_report.get("attachment_risk", 0))
    if attach_risk >= ATTACHMENT_SUSPICIOUS_THRESHOLD:
        fire("SUSPICIOUS_ATTACHMENT",
             f"The attachment filename scored {attach_risk}/100 "
             f"(threshold {ATTACHMENT_SUSPICIOUS_THRESHOLD}). Only the filename was inspected; "
             "the file was never opened or executed.",
             attachment_report.get("filename", ""))

    # ------------------------------------------------- 6. Generic greeting +5
    if flags.get("generic_greeting"):
        fire("GENERIC_GREETING",
             "An impersonal greeting was used. Organisations that hold your record usually "
             "address you by name.",
             ", ".join(content_report["categories"]["GENERIC_GREETING"]["keywords"][:3]))

    # ------------------------------------------------ 7. Threat / fear +10
    if flags.get("threat"):
        fire("THREAT_FEAR_LANGUAGE",
             "Consequence or fear language was detected (suspension, closure, legal action). "
             "Fear is used to override the reader's normal caution.",
             ", ".join(content_report["categories"]["THREAT"]["keywords"][:4]))

    raw_score = sum(t["weight"] for t in triggered)
    score = min(SCORE_CAP, raw_score)
    classification = classify_risk(score)

    why: List[str] = [f"{t['label']} (+{t['weight']})" for t in triggered]
    if not why:
        why = ["No rule-based phishing indicator was triggered."]

    return {
        "risk_score": score,
        "raw_score": raw_score,
        "max_possible_raw_score": MAX_RAW_SCORE,
        "cap_applied": raw_score > SCORE_CAP,
        "classification": classification,
        "risk_state": risk_state(score),
        "band_meaning": BAND_MEANING[classification],
        "triggered_rules": triggered,
        "rule_contributions": {t["rule"]: t["weight"] for t in triggered},
        "rule_weights": dict(RULE_WEIGHTS),
        "thresholds": {
            "sender": SENDER_SUSPICIOUS_THRESHOLD,
            "url": URL_SUSPICIOUS_THRESHOLD,
            "attachment": ATTACHMENT_SUSPICIOUS_THRESHOLD,
        },
        "bands": [{"min": lo, "max": hi, "label": lb} for lo, hi, lb in CLASSIFICATION_BANDS],
        "why": why,
        "assumption_note": (
            "These weights and thresholds are PROJECT ASSUMPTIONS defined for this educational "
            "build. They were not learned from a labelled corpus of production mail and must be "
            "calibrated with representative validation data and analyst feedback before "
            "operational use. The score supports human judgement - it does not replace it."
        ),
    }


def build_recommendations(
    classification: str,
    triggered_rules: List[Dict[str, Any]],
    has_urls: bool = False,
    has_attachment: bool = False,
) -> List[Dict[str, str]]:
    """Produce prioritised, defensive recommendations for the user/analyst.

    Recommendations are always ACTIONS THE READER CAN TAKE SAFELY. The project
    never tells a user to open a link "to check", never suggests replying to
    confirm, and never suggests running an attachment in any environment.
    """
    recs: List[Dict[str, str]] = []
    fired = {t["rule"] for t in triggered_rules}

    if classification in ("HIGH RISK / LIKELY PHISHING", "SUSPICIOUS"):
        recs.append({
            "priority": "CRITICAL",
            "action": "Do not click any link in this email",
            "detail": "The links were analysed as text only. Opening one can deliver a "
                      "credential-harvesting page or a drive-by download.",
        })
        recs.append({
            "priority": "CRITICAL",
            "action": "Do not open or download any attachment",
            "detail": "Attachment risk was assessed from the filename alone. Opening the file "
                      "is what executes malicious content.",
        })
        recs.append({
            "priority": "HIGH",
            "action": "Report the email to your security team or IT helpdesk",
            "detail": "Use the 'Report Phishing' button in your mail client, or forward the "
                      "message as an attachment so the headers are preserved.",
        })
        recs.append({
            "priority": "HIGH",
            "action": "Do not reply and do not use contact details from the email",
            "detail": "Phone numbers and addresses inside a phishing email lead back to the "
                      "attacker. Use contact details you already trust.",
        })
    elif classification == "MODERATE RISK":
        recs.append({
            "priority": "HIGH",
            "action": "Verify before you act",
            "detail": "Some indicators were found. Confirm the request through a channel you "
                      "already trust before doing anything the email asks.",
        })
        recs.append({
            "priority": "MEDIUM",
            "action": "Avoid clicking links until verified",
            "detail": "Navigate to the organisation's website by typing the address you "
                      "already know, or use its official app.",
        })
    else:
        recs.append({
            "priority": "INFO",
            "action": "No strong indicators - keep normal caution",
            "detail": "A low score is not a guarantee of safety. A well-written phishing email "
                      "can avoid every indicator this tool checks (a false negative).",
        })

    if "CREDENTIAL_REQUEST" in fired:
        recs.append({
            "priority": "CRITICAL",
            "action": "Never enter credentials from an email link",
            "detail": "Open the organisation's official website or app directly and sign in "
                      "there. If you already entered your password, change it now from a "
                      "device you trust and check your account's active sessions.",
        })
    if "SUSPICIOUS_SENDER" in fired:
        recs.append({
            "priority": "HIGH",
            "action": "Verify the sender out-of-band",
            "detail": "Contact the person or organisation using a number or address you "
                      "already have. Display names and 'From' addresses are trivially spoofed.",
        })
    if "SUSPICIOUS_URL" in fired or has_urls:
        recs.append({
            "priority": "MEDIUM",
            "action": "Inspect links before trusting them",
            "detail": "Hover on desktop (long-press on mobile) to reveal the real destination, "
                      "and read the hostname from the RIGHT: the registrable domain just "
                      "before the first single slash is the real owner.",
        })
    if "SUSPICIOUS_ATTACHMENT" in fired or has_attachment:
        recs.append({
            "priority": "HIGH",
            "action": "Confirm unexpected attachments with the sender",
            "detail": "Ask through a separate channel whether they really sent the file. "
                      "Turn on 'show file extensions' in Windows Explorer so a double "
                      "extension such as invoice.pdf.exe cannot hide.",
        })
    if "URGENCY" in fired or "THREAT_FEAR_LANGUAGE" in fired:
        recs.append({
            "priority": "MEDIUM",
            "action": "Slow down - pressure is the attack",
            "detail": "Urgency and threats exist to stop you from checking. Genuine "
                      "organisations allow you time to verify through official channels.",
        })
    if "GENERIC_GREETING" in fired:
        recs.append({
            "priority": "LOW",
            "action": "Note the impersonal greeting",
            "detail": "A service that holds your account details would normally use your name. "
                      "On its own this proves nothing - some genuine bulk mail is impersonal too.",
        })

    recs.append({
        "priority": "INFO",
        "action": "Use the organisation's official website or app directly",
        "detail": "Typing a known address, or using a saved bookmark, removes the link from "
                  "the attacker's control entirely. This single habit defeats most phishing.",
    })

    # De-duplicate while preserving priority order.
    seen, unique = set(), []
    for r in recs:
        if r["action"] not in seen:
            seen.add(r["action"])
            unique.append(r)
    return unique
