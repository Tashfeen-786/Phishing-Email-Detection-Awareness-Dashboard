"""
backend/services/feature_extractor.py
=====================================
PURPOSE
-------
``extract_email_features()`` - the single reusable function that converts an
email into a flat, numeric feature dictionary.

It is used in THREE places, which is why it has to be one function:

  1. the rule engine (booleans/thresholds derived from these numbers),
  2. the ML pipeline (the structured half of the feature matrix),
  3. the dashboard (the "features" panel shown to the analyst).

===========================================================================
FEATURE DICTIONARY - every feature documented
===========================================================================
urgent_keyword_count           int    Occurrences of time-pressure phrases
                                      ("act now", "within 24 hours"). Urgency is
                                      the most used social-engineering lever.
credential_keyword_count       int    Occurrences of credential *words*
                                      (password, OTP, PIN). Topic only.
credential_request_count       int    Occurrences of credential *requests*
                                      matched by contextual regex. This is the
                                      high-value feature; the word count alone
                                      produces false positives on training mail.
financial_keyword_count        int    Money words (invoice, payment, refund).
threat_keyword_count           int    Consequence/fear phrases ("account will be
                                      suspended", "legal action").
reward_keyword_count           int    Prize/greed bait ("you have won").
personal_info_request_count    int    Contextual requests for personal data.
suspicious_cta_count           int    "click here" / "open the attached".
url_count                      int    Number of distinct URLs found.
suspicious_url_count           int    URLs whose static risk score >= 30.
max_url_risk                   int    Highest single URL risk (0-100).
has_ip_url                     0/1    Any URL whose host is a raw IP literal.
has_shortened_url_pattern      0/1    Any URL on a known shortener domain.
has_non_https_url              0/1    Any URL using plain HTTP / no scheme.
sender_domain_length           int    Characters in the sender domain.
subdomain_count                int    Levels in front of the registrable domain.
sender_risk_score              int    Output of the sender analyzer (0-100).
sender_domain_has_digits       0/1    Digit/letter mixing = look-alike shape.
sender_domain_hyphens          int    Hyphens in the registrable domain.
sender_valid_format            0/1    Sender parses as a valid address.
display_name_mismatch          0/1    Display name contradicts the domain.
suspicious_attachment          0/1    Attachment risk >= 40.
attachment_risk                int    Attachment analyzer score (0-100).
has_double_extension           0/1    invoice.pdf.exe pattern.
has_executable_attachment      0/1    .exe/.scr/.bat/... as the real extension.
generic_greeting               0/1    "Dear Customer" style salutation.
contains_password_request      0/1    Contextual credential request present.
contains_personal_info_request 0/1    Contextual personal-data request present.
exclamation_count              int    '!' characters - pressure/shouting.
uppercase_ratio                float  Share of letters in upper case (0-1).
body_length                    int    Characters in the body.
subject_length                 int    Characters in the subject.
word_count                     int    Words in subject+body.
avg_word_length                float  Mean word length - crude style signal.
digit_ratio                    float  Share of digits in the text.
link_density                   float  URLs per 100 words.
grammar_anomaly_count          int    Heuristic writing-quality issues.
empty_subject                  0/1    Subject is blank.
empty_body                     0/1    Body is blank.
===========================================================================

All values are non-negative numbers, which lets the same matrix feed
Multinomial Naive Bayes as well as Logistic Regression and Random Forest.
"""

from __future__ import annotations

from typing import Any, Dict, List, Optional

from backend.services.attachment_analyzer import analyze_attachment
from backend.services.content_analyzer import analyze_email_content
from backend.services.preprocessing import preprocess_email
from backend.services.sender_analyzer import analyze_sender
from backend.services.url_analyzer import analyze_urls

#: Canonical ordered feature list. The ML pipeline stores this order with the
#: model so training-time and inference-time vectors can never drift apart.
FEATURE_NAMES: List[str] = [
    "urgent_keyword_count",
    "credential_keyword_count",
    "credential_request_count",
    "financial_keyword_count",
    "threat_keyword_count",
    "reward_keyword_count",
    "personal_info_request_count",
    "suspicious_cta_count",
    "url_count",
    "suspicious_url_count",
    "max_url_risk",
    "has_ip_url",
    "has_shortened_url_pattern",
    "has_non_https_url",
    "sender_domain_length",
    "subdomain_count",
    "sender_risk_score",
    "sender_domain_has_digits",
    "sender_domain_hyphens",
    "sender_valid_format",
    "display_name_mismatch",
    "suspicious_attachment",
    "attachment_risk",
    "has_double_extension",
    "has_executable_attachment",
    "generic_greeting",
    "contains_password_request",
    "contains_personal_info_request",
    "exclamation_count",
    "uppercase_ratio",
    "body_length",
    "subject_length",
    "word_count",
    "avg_word_length",
    "digit_ratio",
    "link_density",
    "grammar_anomaly_count",
    "empty_subject",
    "empty_body",
]


def extract_email_features(
    sender: str,
    subject: str,
    body: str,
    urls: Optional[str | List[str]] = None,
    attachment_name: Optional[str] = None,
    display_name: Optional[str] = None,
    return_analyses: bool = False,
) -> Dict[str, Any]:
    """Extract the full numeric feature dictionary for one email.

    Parameters
    ----------
    sender, subject, body:
        Raw email fields.
    urls:
        Optional extra URLs (string or list). URLs inside the body are always
        extracted automatically.
    attachment_name:
        Optional attachment FILENAME (never file content).
    display_name:
        Optional sender display name.
    return_analyses:
        When ``True`` the returned dict also contains the full analyzer reports
        under ``"_analyses"``. The API uses this so the analyzers run once.

    Returns
    -------
    dict - keys are exactly :data:`FEATURE_NAMES` (plus ``"_analyses"`` when
    requested). Every value is a non-negative int/float.
    """
    pre = preprocess_email(sender, subject, body, urls, attachment_name, display_name)

    sender_report = analyze_sender(pre["sender"], pre["sender_display_name"] or display_name)
    content_report = analyze_email_content(pre["subject"], pre["body"])
    url_report = analyze_urls(pre["urls"])
    attachment_report = analyze_attachment(pre["attachment_name"])

    counts = content_report["counts"]
    categories = content_report["categories"]
    flags = content_report["flags"]

    text = pre["combined_text"]
    words = text.split()
    word_count = len(words)
    avg_word_length = round(sum(len(w) for w in words) / word_count, 3) if word_count else 0.0
    digit_ratio = round(sum(c.isdigit() for c in text) / len(text), 4) if text else 0.0
    link_density = round((url_report["url_count"] / word_count) * 100, 3) if word_count else 0.0

    domain = pre["sender_domain"]
    registrable = sender_report["registrable_domain"]
    reg_body = registrable.rsplit(".", 1)[0] if "." in registrable else registrable

    display_mismatch = any(
        f["indicator_type"] == "DISPLAY_NAME_MISMATCH" for f in sender_report["sender_findings"]
    )

    features: Dict[str, Any] = {
        "urgent_keyword_count": counts["urgent_keyword_count"],
        "credential_keyword_count": counts["credential_keyword_count"],
        "credential_request_count": categories["CREDENTIAL_REQUEST"]["count"],
        "financial_keyword_count": counts["financial_keyword_count"],
        "threat_keyword_count": counts["threat_keyword_count"],
        "reward_keyword_count": counts["reward_keyword_count"],
        "personal_info_request_count": categories["PERSONAL_INFO_REQUEST"]["count"],
        "suspicious_cta_count": counts["cta_keyword_count"],
        "url_count": url_report["url_count"],
        "suspicious_url_count": url_report["suspicious_url_count"],
        "max_url_risk": url_report["max_url_risk"],
        "has_ip_url": int(url_report["has_ip_url"]),
        "has_shortened_url_pattern": int(url_report["has_shortened_url_pattern"]),
        "has_non_https_url": int(url_report["has_non_https_url"]),
        "sender_domain_length": len(domain),
        "subdomain_count": sender_report["subdomain_count"],
        "sender_risk_score": sender_report["sender_risk_score"],
        "sender_domain_has_digits": int(any(c.isdigit() for c in reg_body)),
        "sender_domain_hyphens": reg_body.count("-"),
        "sender_valid_format": int(sender_report["is_valid_format"]),
        "display_name_mismatch": int(display_mismatch),
        "suspicious_attachment": int(attachment_report["suspicious"]),
        "attachment_risk": attachment_report["attachment_risk"],
        "has_double_extension": int(attachment_report["has_double_extension"]),
        "has_executable_attachment": int(attachment_report["is_executable"] or attachment_report["is_script"]),
        "generic_greeting": int(flags["generic_greeting"]),
        "contains_password_request": int(flags["credential_request"]),
        "contains_personal_info_request": int(flags["personal_info_request"]),
        "exclamation_count": content_report["exclamation_count"],
        "uppercase_ratio": content_report["uppercase_ratio"],
        "body_length": len(pre["body"]),
        "subject_length": len(pre["subject"]),
        "word_count": word_count,
        "avg_word_length": avg_word_length,
        "digit_ratio": digit_ratio,
        "link_density": link_density,
        "grammar_anomaly_count": len(content_report["grammar_issues"]),
        "empty_subject": int(pre["is_subject_empty"]),
        "empty_body": int(pre["is_body_empty"]),
    }

    # Guarantee the canonical order/content contract.
    features = {name: features[name] for name in FEATURE_NAMES}

    if return_analyses:
        features["_analyses"] = {
            "preprocessed": pre,
            "sender": sender_report,
            "content": content_report,
            "urls": url_report,
            "attachment": attachment_report,
        }
    return features


def features_to_vector(features: Dict[str, Any]) -> List[float]:
    """Convert a feature dict into a list ordered exactly like :data:`FEATURE_NAMES`."""
    return [float(features.get(name, 0) or 0) for name in FEATURE_NAMES]


def describe_features() -> Dict[str, str]:
    """Return a human-readable description of each feature (used by /api/features)."""
    return {
        "urgent_keyword_count": "Occurrences of time-pressure phrases such as 'act now' or 'within 24 hours'.",
        "credential_keyword_count": "Occurrences of credential words (password, OTP, PIN) - topic only.",
        "credential_request_count": "Contextual matches where the email actually ASKS for credentials.",
        "financial_keyword_count": "Money-related words (invoice, payment, refund, billing).",
        "threat_keyword_count": "Fear/consequence phrases ('account will be suspended', 'legal action').",
        "reward_keyword_count": "Prize/greed bait ('you have won', 'claim your reward').",
        "personal_info_request_count": "Contextual requests for personal or financial details.",
        "suspicious_cta_count": "Calls to action such as 'click here' or 'open the attached'.",
        "url_count": "Number of distinct URLs found in subject + body.",
        "suspicious_url_count": "URLs whose static risk score reaches the suspicion threshold (30).",
        "max_url_risk": "Highest static risk score among all URLs (0-100).",
        "has_ip_url": "1 when any URL points at a raw IP address instead of a hostname.",
        "has_shortened_url_pattern": "1 when any URL uses a known URL-shortening service.",
        "has_non_https_url": "1 when any URL uses plain HTTP or has no scheme.",
        "sender_domain_length": "Character length of the sender domain.",
        "subdomain_count": "Number of subdomain levels in front of the registrable domain.",
        "sender_risk_score": "Composite sender analyzer score (0-100).",
        "sender_domain_has_digits": "1 when digits are mixed with letters in the registrable domain.",
        "sender_domain_hyphens": "Number of hyphens in the registrable domain.",
        "sender_valid_format": "1 when the sender address parses as a valid email address.",
        "display_name_mismatch": "1 when the display name contradicts the sending domain.",
        "suspicious_attachment": "1 when the attachment filename risk reaches 40/100.",
        "attachment_risk": "Attachment filename risk score (0-100) - filename only, never executed.",
        "has_double_extension": "1 for the invoice.pdf.exe pattern.",
        "has_executable_attachment": "1 when the real extension is executable or a script.",
        "generic_greeting": "1 when an impersonal salutation such as 'Dear Customer' is used.",
        "contains_password_request": "1 when a contextual credential request was detected.",
        "contains_personal_info_request": "1 when a contextual personal-data request was detected.",
        "exclamation_count": "Number of '!' characters.",
        "uppercase_ratio": "Share of alphabetic characters written in upper case (0.0-1.0).",
        "body_length": "Characters in the email body.",
        "subject_length": "Characters in the subject line.",
        "word_count": "Words in subject + body.",
        "avg_word_length": "Mean word length - a crude writing-style signal.",
        "digit_ratio": "Share of digit characters in the text.",
        "link_density": "URLs per 100 words.",
        "grammar_anomaly_count": "Count of heuristic writing-quality anomalies (weak signal).",
        "empty_subject": "1 when the subject is blank.",
        "empty_body": "1 when the body is blank.",
    }
