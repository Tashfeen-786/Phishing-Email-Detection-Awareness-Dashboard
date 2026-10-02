"""
backend/services/content_analyzer.py
====================================
PURPOSE
-------
Analyse the SUBJECT and BODY of an email for social-engineering language and
return explainable findings plus per-category counts.

CATEGORIES DETECTED
-------------------
URGENCY              "act now", "within 24 hours"
FEAR / THREAT        "your account will be suspended", "legal action"
FINANCIAL PRESSURE   "outstanding payment", "invoice due", payment redirects
CREDENTIAL REQUEST   "verify your password", "confirm your account"
REWARD               "you have won", "claim your prize"
PERSONAL INFORMATION "confirm your personal details"
SUSPICIOUS CTA       "click here", "open the attached"
GENERIC GREETING     "Dear Customer"
GRAMMAR ANOMALIES    repeated punctuation, missing spaces, mixed casing
FORMATTING ANOMALIES shouting, exclamation spam, hidden HTML/script markers

PRECISION DESIGN
----------------
Credential, personal-information and financial-pressure detections are driven
by CONTEXTUAL REGEX (the act of *asking*), not by bare keywords. That is why:

    "The workshop covers password hygiene."        -> NOT a credential request
    "Verify your password within 24 hours."        -> credential request

Keyword counts are still produced (they feed the ML feature vector and the
"most common suspicious keywords" chart), but they do not by themselves raise a
high-severity finding.

IMPORTANT
---------
No single category proves phishing. A legitimate HR email can legitimately be
urgent. The rule engine combines categories; the UI always explains why.
"""

from __future__ import annotations

import re
from typing import Any, Dict, List

from backend.utils.keywords import (
    CREDENTIAL_KEYWORDS,
    CREDENTIAL_REQUEST_PATTERNS,
    FINANCIAL_KEYWORDS,
    FINANCIAL_PRESSURE_PATTERNS,
    GENERIC_GREETINGS,
    PERSONAL_INFO_KEYWORDS,
    PERSONAL_INFO_REQUEST_PATTERNS,
    REWARD_KEYWORDS,
    SUSPICIOUS_CTA_KEYWORDS,
    THREAT_KEYWORDS,
    THREAT_REGEXES,
    URGENCY_KEYWORDS,
)
from backend.utils.text_utils import (
    exclamation_count,
    find_patterns,
    find_labeled_patterns,
    find_phrases,
    sanitize_text,
    uppercase_ratio,
)

# Severity mapping per category (project assumption).
_SEVERITY = {
    "URGENCY": "MEDIUM",
    "THREAT": "HIGH",
    "FINANCIAL": "MEDIUM",
    "CREDENTIAL_REQUEST": "HIGH",
    "REWARD": "MEDIUM",
    "PERSONAL_INFO_REQUEST": "HIGH",
    "SUSPICIOUS_CTA": "MEDIUM",
    "GENERIC_GREETING": "LOW",
    "GRAMMAR_ANOMALY": "LOW",
    "FORMATTING_ANOMALY": "LOW",
}

# Thresholds (project assumptions - documented in docs/RISK_SCORING.md)
URGENCY_MIN_HITS = 1
THREAT_MIN_HITS = 1
FINANCIAL_MIN_HITS = 1
UPPERCASE_RATIO_THRESHOLD = 0.30
EXCLAMATION_THRESHOLD = 3
MIN_TEXT_FOR_CASE_CHECK = 40

_HTML_RISK_MARKERS = re.compile(
    r"<\s*(script|iframe|object|embed|form|input|svg|link|meta)\b|javascript:|on\w+\s*=",
    re.IGNORECASE,
)


def _finding(indicator_type: str, description: str, severity: str,
             evidence: str = "", count: int = 0) -> Dict[str, Any]:
    return {
        "category": "CONTENT",
        "indicator_type": indicator_type,
        "description": description,
        "severity": severity,
        "evidence": sanitize_text(evidence, 200),
        "count": count,
    }


def _grammar_anomalies(text: str) -> List[str]:
    """Heuristic grammar / typography anomalies.

    These are WEAK signals: professional phishing has perfect grammar, and many
    legitimate emails are written in a hurry. They are reported at LOW severity
    and contribute nothing to the rule score on their own.
    """
    issues: List[str] = []
    if re.search(r"[!?]{2,}", text):
        issues.append("repeated punctuation (!! or ??)")
    if re.search(r"[a-z]{2,}[A-Z][a-z]{2,}", text) and not re.search(r"\b(?:iPhone|eBay|PayPal|YouTube)\b", text):
        issues.append("mixed capitalisation inside words")
    if re.search(r"[a-zA-Z],[a-zA-Z]", text):
        issues.append("missing space after a comma")
    if re.search(r"\b(kindly do the needful|revert back|do the needful)\b", text, re.IGNORECASE):
        issues.append("stock phrasing frequently seen in bulk mail")
    if re.search(r"\s{3,}", text):
        issues.append("irregular spacing")
    if re.search(r"\b(?:recieve|acount|verifiy|securty|informations|pls|kindly urgent)\b", text, re.IGNORECASE):
        issues.append("common misspellings of security words")
    return issues


def analyze_email_content(subject: str, body: str) -> Dict[str, Any]:
    """Analyse subject + body text and return explainable social-engineering findings.

    Parameters
    ----------
    subject : str
    body    : str

    Returns
    -------
    dict with keys:
        ``content_findings``   list[dict]  - explainable findings
        ``categories``         dict        - {"URGENCY": {...}, ...}
        ``counts``             dict        - raw keyword counts used as ML features
        ``matched_keywords``   list[str]   - distinct phrases matched (for charts)
        ``flags``              dict[bool]  - booleans consumed by the rule engine
        ``summary``            str
    """
    subject = sanitize_text(subject)
    body = sanitize_text(body)
    combined = f"{subject}\n{body}".strip()

    findings: List[Dict[str, Any]] = []
    matched_keywords: List[str] = []

    # ------------------------------------------------------------ keyword hits
    urgency_hits = find_phrases(combined, URGENCY_KEYWORDS)
    threat_hits = find_phrases(combined, THREAT_KEYWORDS)
    financial_hits = find_phrases(combined, FINANCIAL_KEYWORDS)
    reward_hits = find_phrases(combined, REWARD_KEYWORDS)
    credential_hits = find_phrases(combined, CREDENTIAL_KEYWORDS)
    personal_hits = find_phrases(combined, PERSONAL_INFO_KEYWORDS)
    cta_hits = find_phrases(combined, SUSPICIOUS_CTA_KEYWORDS)
    greeting_hits = find_phrases(combined, GENERIC_GREETINGS)

    # --------------------------------------------------------- pattern matches
    credential_patterns = find_patterns(combined, CREDENTIAL_REQUEST_PATTERNS)
    personal_patterns = find_patterns(combined, PERSONAL_INFO_REQUEST_PATTERNS)
    financial_patterns = find_patterns(combined, FINANCIAL_PRESSURE_PATTERNS)
    # Fixed phrases miss "will be PERMANENTLY closed"; the regexes tolerate
    # adverbs between the auxiliary verb and the consequence.
    threat_patterns = find_labeled_patterns(combined, THREAT_REGEXES)

    def _count(hits) -> int:
        return sum(c for _, c in hits)

    counts = {
        "urgent_keyword_count": _count(urgency_hits),
        "threat_keyword_count": _count(threat_hits) + len(threat_patterns),
        "financial_keyword_count": _count(financial_hits),
        "reward_keyword_count": _count(reward_hits),
        "credential_keyword_count": _count(credential_hits),
        "personal_info_keyword_count": _count(personal_hits),
        "cta_keyword_count": _count(cta_hits),
        "generic_greeting_count": _count(greeting_hits),
    }

    for hits in (urgency_hits, threat_hits, financial_hits, reward_hits,
                 credential_hits, personal_hits, cta_hits, greeting_hits):
        for phrase, _ in hits:
            if phrase not in matched_keywords:
                matched_keywords.append(phrase)

    # =====================================================  URGENCY
    urgency_flag = counts["urgent_keyword_count"] >= URGENCY_MIN_HITS
    if urgency_flag:
        evidence = ", ".join(sorted({p for p, _ in urgency_hits})[:5])
        findings.append(_finding(
            "URGENCY_LANGUAGE",
            "Time-pressure language was detected. Urgency is the most common "
            "social-engineering lever: it pushes the reader to act before verifying. "
            "Note that legitimate business email can also be urgent, so this is a signal, "
            "not proof.",
            _SEVERITY["URGENCY"], evidence, counts["urgent_keyword_count"],
        ))

    # =====================================================  FEAR / THREAT
    threat_flag = counts["threat_keyword_count"] >= THREAT_MIN_HITS
    if threat_flag:
        evidence_parts = sorted({p for p, _ in threat_hits})
        evidence_parts += [label for label, _ in threat_patterns]
        evidence = ", ".join(evidence_parts[:5])
        findings.append(_finding(
            "THREAT_FEAR_LANGUAGE",
            "Threat or consequence language was detected (loss of access, suspension, "
            "penalties). Fear narrows attention and is used to suppress the reader's "
            "normal verification habits.",
            _SEVERITY["THREAT"], evidence, counts["threat_keyword_count"],
        ))

    # =====================================================  FINANCIAL PRESSURE
    financial_flag = bool(financial_patterns) or counts["financial_keyword_count"] >= 2
    if financial_flag:
        evidence = "; ".join(financial_patterns[:3]) or ", ".join(sorted({p for p, _ in financial_hits})[:5])
        findings.append(_finding(
            "FINANCIAL_PRESSURE",
            "Payment or invoice pressure was detected. Invoice fraud and payment-redirect "
            "scams rely on a believable money request arriving at a plausible moment.",
            _SEVERITY["FINANCIAL"], evidence, counts["financial_keyword_count"],
        ))
    elif counts["financial_keyword_count"] == 1:
        findings.append(_finding(
            "FINANCIAL_TOPIC_MENTIONED",
            "A single money-related word appears. On its own this is normal business "
            "vocabulary and adds no risk.",
            "INFO", ", ".join(p for p, _ in financial_hits), 1,
        ))

    # =====================================================  CREDENTIAL REQUEST
    credential_flag = bool(credential_patterns)
    if credential_flag:
        findings.append(_finding(
            "CREDENTIAL_REQUEST",
            "The message asks the reader to verify, confirm, re-enter or reset credentials. "
            "Legitimate organisations do not ask for passwords, OTPs or PINs by email. "
            "This is one of the strongest single phishing indicators.",
            _SEVERITY["CREDENTIAL_REQUEST"], "; ".join(credential_patterns[:3]),
            len(credential_patterns),
        ))
    elif counts["credential_keyword_count"] > 0:
        findings.append(_finding(
            "CREDENTIAL_TOPIC_MENTIONED",
            "Credential-related words appear, but the message does not actually ask for "
            "them (for example, security-awareness training content). No risk is added.",
            "INFO", ", ".join(sorted({p for p, _ in credential_hits})[:5]),
            counts["credential_keyword_count"],
        ))

    # =====================================================  PERSONAL INFORMATION
    personal_flag = bool(personal_patterns)
    if personal_flag:
        findings.append(_finding(
            "PERSONAL_INFO_REQUEST",
            "The message asks for personal or financial details. Data of this kind is used "
            "for identity theft and account takeover, and is rarely collected over email.",
            _SEVERITY["PERSONAL_INFO_REQUEST"], "; ".join(personal_patterns[:3]),
            len(personal_patterns),
        ))

    # =====================================================  REWARD
    reward_flag = counts["reward_keyword_count"] >= 1
    if reward_flag:
        findings.append(_finding(
            "REWARD_BAIT",
            "Prize, reward or 'you have won' wording was detected. Greed is used the same "
            "way fear is - to short-circuit verification.",
            _SEVERITY["REWARD"], ", ".join(sorted({p for p, _ in reward_hits})[:5]),
            counts["reward_keyword_count"],
        ))

    # =====================================================  SUSPICIOUS CTA
    cta_flag = counts["cta_keyword_count"] >= 1
    if cta_flag:
        findings.append(_finding(
            "SUSPICIOUS_CALL_TO_ACTION",
            "The message pushes a single immediate action ('click here', 'open the "
            "attached'). Phishing needs exactly one click, so the call to action is always "
            "prominent and always away from the official channel.",
            _SEVERITY["SUSPICIOUS_CTA"], ", ".join(sorted({p for p, _ in cta_hits})[:5]),
            counts["cta_keyword_count"],
        ))

    # =====================================================  GENERIC GREETING
    greeting_flag = counts["generic_greeting_count"] >= 1
    if greeting_flag:
        findings.append(_finding(
            "GENERIC_GREETING",
            "An impersonal greeting was used. Organisations that already hold your record "
            "usually address you by name; bulk phishing cannot.",
            _SEVERITY["GENERIC_GREETING"], ", ".join(p for p, _ in greeting_hits),
            counts["generic_greeting_count"],
        ))

    # =====================================================  GRAMMAR
    grammar_issues = _grammar_anomalies(combined)
    if grammar_issues:
        findings.append(_finding(
            "GRAMMAR_ANOMALY",
            "Writing-quality anomalies were detected: " + "; ".join(grammar_issues[:4]) +
            ". This is a weak signal - well-resourced attackers write flawless English.",
            _SEVERITY["GRAMMAR_ANOMALY"], "; ".join(grammar_issues[:4]), len(grammar_issues),
        ))

    # =====================================================  FORMATTING
    up_ratio = uppercase_ratio(combined) if len(combined) >= MIN_TEXT_FOR_CASE_CHECK else 0.0
    excl = exclamation_count(combined)
    formatting_issues: List[str] = []
    if up_ratio >= UPPERCASE_RATIO_THRESHOLD:
        formatting_issues.append(f"{up_ratio * 100:.0f}% of letters are upper-case (shouting)")
    if excl >= EXCLAMATION_THRESHOLD:
        formatting_issues.append(f"{excl} exclamation marks")
    html_markers = _HTML_RISK_MARKERS.findall(body)
    if html_markers:
        formatting_issues.append("active HTML markup (script/iframe/form/event handler)")
    if formatting_issues:
        findings.append(_finding(
            "FORMATTING_ANOMALY",
            "Presentation anomalies were detected: " + "; ".join(formatting_issues) +
            ". The dashboard renders email text as escaped plain text, never as live HTML.",
            "MEDIUM" if html_markers else _SEVERITY["FORMATTING_ANOMALY"],
            "; ".join(formatting_issues), len(formatting_issues),
        ))

    if not findings:
        findings.append(_finding(
            "NO_CONTENT_INDICATORS",
            "No social-engineering language patterns were detected in the subject or body. "
            "A clean body does not guarantee the email is safe - always consider context.",
            "INFO", "", 0,
        ))

    categories = {
        "URGENCY": {"detected": urgency_flag, "count": counts["urgent_keyword_count"],
                    "keywords": sorted({p for p, _ in urgency_hits})},
        "THREAT": {"detected": threat_flag, "count": counts["threat_keyword_count"],
                   "keywords": sorted({p for p, _ in threat_hits}),
                   "patterns": [label for label, _ in threat_patterns]},
        "FINANCIAL": {"detected": financial_flag, "count": counts["financial_keyword_count"],
                      "keywords": sorted({p for p, _ in financial_hits})},
        "CREDENTIAL_REQUEST": {"detected": credential_flag, "count": len(credential_patterns),
                               "keywords": credential_patterns[:5]},
        "REWARD": {"detected": reward_flag, "count": counts["reward_keyword_count"],
                   "keywords": sorted({p for p, _ in reward_hits})},
        "PERSONAL_INFO_REQUEST": {"detected": personal_flag, "count": len(personal_patterns),
                                  "keywords": personal_patterns[:5]},
        "SUSPICIOUS_CTA": {"detected": cta_flag, "count": counts["cta_keyword_count"],
                           "keywords": sorted({p for p, _ in cta_hits})},
        "GENERIC_GREETING": {"detected": greeting_flag, "count": counts["generic_greeting_count"],
                             "keywords": [p for p, _ in greeting_hits]},
    }

    flags = {
        "urgency": urgency_flag,
        "threat": threat_flag,
        "financial_pressure": financial_flag,
        "credential_request": credential_flag,
        "reward_bait": reward_flag,
        "personal_info_request": personal_flag,
        "suspicious_cta": cta_flag,
        "generic_greeting": greeting_flag,
        "grammar_anomaly": bool(grammar_issues),
        "formatting_anomaly": bool(formatting_issues),
        "active_html": bool(html_markers),
    }

    triggered = [k for k, v in flags.items() if v and k not in ("grammar_anomaly", "formatting_anomaly")]
    summary = (f"{len(triggered)} social-engineering category(ies) detected: "
               f"{', '.join(triggered)}." if triggered
               else "No social-engineering language categories were detected.")

    return {
        "content_findings": findings,
        "categories": categories,
        "counts": counts,
        "matched_keywords": matched_keywords,
        "flags": flags,
        "uppercase_ratio": up_ratio,
        "exclamation_count": excl,
        "grammar_issues": grammar_issues,
        "formatting_issues": formatting_issues,
        "summary": summary,
    }


def analyze_subject(subject: str) -> Dict[str, Any]:
    """Subject-line-only analysis (used for the dedicated 'subject indicators' view).

    Detects the PDF's subject indicator list: urgent language, account-suspension
    threats, payment pressure, prize claims, password-reset pressure and
    verification requests.
    """
    subject = sanitize_text(subject, 998)
    low = subject.lower()
    indicators: List[str] = []
    if find_phrases(subject, URGENCY_KEYWORDS):
        indicators.append("urgent language")
    if re.search(r"\b(suspend|suspended|suspension|deactivat|disabled|locked|closure|closed)\b", low):
        indicators.append("account suspension threat")
    if re.search(r"\b(payment|invoice|overdue|unpaid|billing|refund|due)\b", low):
        indicators.append("payment pressure")
    if re.search(r"\b(won|winner|prize|reward|lottery|gift|congratulations)\b", low):
        indicators.append("prize/reward claim")
    if re.search(r"\b(password|passcode)\b.*\b(expire|expiry|reset|change|update)\b|"
                 r"\b(reset|change|update)\b.*\b(password|passcode)\b", low):
        indicators.append("password reset pressure")
    if re.search(r"\b(verify|verification|confirm|validate|re-?activate|authenticate)\b", low):
        indicators.append("verification request")
    if subject.strip() == "":
        indicators.append("empty subject")
    return {
        "subject": subject,
        "subject_length": len(subject),
        "subject_indicators": indicators,
        "detected": bool(indicators),
    }
