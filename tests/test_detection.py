"""
tests/test_detection.py
=======================
The 25 scenarios required by the project brief, plus supporting checks.

Each test is named after its scenario number so the mapping to the brief is
obvious in the pytest output:

     1 legitimate email              14 executable attachment
     2 urgent phishing-style email   15 double extension
     3 credential request            16 empty subject
     4 financial request             17 empty body
     5 generic greeting              18 invalid sender
     6 safe URL                      19 high uppercase ratio
     7 raw IP URL                    20 multiple exclamation marks
     8 non-HTTPS URL                 21 rule-score boundary
     9 excessive subdomains          22 database save
    10 suspicious keyword in URL     23 API validation
    11 no URL                        24 ML prediction if enabled
    12 multiple URLs                 25 analysis-history retrieval
    13 normal attachment

Run from the project root:

    pytest -v
"""

from __future__ import annotations

import pytest

from backend.services.analysis_service import analyze_email, analyze_single_url
from backend.services.attachment_analyzer import analyze_attachment
from backend.services.content_analyzer import analyze_email_content
from backend.services.feature_extractor import FEATURE_NAMES, extract_email_features
from backend.services.risk_engine import calculate_phishing_score
from backend.services.sender_analyzer import analyze_sender
from backend.services.url_analyzer import analyze_url


# =========================================================================
# 1. Legitimate email
# =========================================================================
def test_01_legitimate_email_scores_low(legitimate_email):
    result = analyze_email(**legitimate_email, use_ml=False)
    assert result["risk_score"] <= 20
    assert result["classification"] == "LOW RISK"
    assert result["triggered_rules"] == []


def test_01b_awareness_content_does_not_trigger_credential_rule(legitimate_email):
    """A workshop about "password hygiene" must not be read as asking for a password.

    This is the precision test that separates a contextual detector from a
    keyword matcher. It is the single most valuable test in this file.
    """
    result = analyze_email(**legitimate_email, use_ml=False)
    triggered = {t["rule"] for t in result["triggered_rules"]}
    assert "CREDENTIAL_REQUEST" not in triggered
    info_types = {i["indicator_type"] for i in result["indicators"]}
    assert "CREDENTIAL_TOPIC_MENTIONED" in info_types


# =========================================================================
# 2. Urgent phishing-style email
# =========================================================================
def test_02_urgent_phishing_email_scores_high(phishing_email):
    result = analyze_email(**phishing_email, use_ml=False)
    assert result["risk_score"] >= 71
    assert result["classification"] == "HIGH RISK / LIKELY PHISHING"
    triggered = {t["rule"] for t in result["triggered_rules"]}
    assert "URGENCY" in triggered


def test_02b_urgency_alone_is_reported_as_a_signal_not_proof():
    result = analyze_email(
        sender="pm@example.com", subject="Urgent: please review before 5pm today",
        body="Hi, this is urgent - the client needs the deck immediately. Thanks.",
        use_ml=False,
    )
    assert result["risk_score"] < 41, "urgency alone must not reach the escalation band"


# =========================================================================
# 3. Credential request
# =========================================================================
def test_03_credential_request_detected():
    content = analyze_email_content(
        "Action needed",
        "Please confirm your password and enter your login credentials to continue.",
    )
    assert content["flags"]["credential_request"] is True


def test_03b_credential_request_adds_twenty_points():
    result = analyze_email(
        sender="noreply@example.com", subject="Account notice",
        body="Please verify your password immediately to keep your access.",
        use_ml=False,
    )
    weights = {t["rule"]: t["weight"] for t in result["triggered_rules"]}
    assert weights.get("CREDENTIAL_REQUEST") == 20


# =========================================================================
# 4. Financial request
# =========================================================================
def test_04_financial_request_detected():
    content = analyze_email_content(
        "Invoice overdue",
        "Your outstanding payment is overdue. Please release payment via wire transfer "
        "to the new beneficiary account number today.",
    )
    assert content["flags"]["financial_pressure"] is True


# =========================================================================
# 5. Generic greeting
# =========================================================================
def test_05_generic_greeting_detected_and_weighted():
    result = analyze_email(
        sender="noreply@example.net", subject="Notice",
        body="Dear Customer, your statement is ready.", use_ml=False,
    )
    weights = {t["rule"]: t["weight"] for t in result["triggered_rules"]}
    assert weights.get("GENERIC_GREETING") == 5


def test_05b_named_greeting_is_not_flagged():
    content = analyze_email_content("Hello", "Hi Priya, here is the file you asked for.")
    assert content["flags"]["generic_greeting"] is False


# =========================================================================
# 6. Safe URL
# =========================================================================
def test_06_safe_https_url_scores_low():
    report = analyze_url("https://example.org/library/renew")
    assert report["url_risk_score"] < 30
    assert report["uses_https"] is True
    assert report["is_ip"] is False
    assert report["suspicious"] is False


# =========================================================================
# 7. Raw IP URL
# =========================================================================
def test_07_raw_ip_url_flagged():
    report = analyze_url("http://198.51.100.10/verify-account")
    assert report["is_ip"] is True
    assert report["suspicious"] is True
    assert any(f["indicator_type"] == "RAW_IP_URL" for f in report["url_findings"])


def test_07b_ip_url_is_defanged_in_the_safe_representation():
    """The UI and database must never show a clickable attacker URL."""
    report = analyze_url("http://198.51.100.10/verify-account")
    assert "hxxp" in report["safe_representation"]
    assert "198[.]51[.]100[.]10" in report["safe_representation"]


# =========================================================================
# 8. Non-HTTPS URL
# =========================================================================
def test_08_plain_http_url_flagged():
    report = analyze_url("http://example.com/login")
    assert report["uses_https"] is False
    assert any(f["indicator_type"] == "NO_HTTPS" for f in report["url_findings"])


# =========================================================================
# 9. Excessive subdomains
# =========================================================================
def test_09_excessive_subdomains_flagged():
    report = analyze_url("http://secure.login.verify.account.example.com/session")
    types = {f["indicator_type"] for f in report["url_findings"]}
    assert "EXCESSIVE_SUBDOMAINS" in types


# =========================================================================
# 10. Suspicious keyword in URL
# =========================================================================
def test_10_suspicious_keyword_in_url_path():
    report = analyze_url("https://example.net/secure/verify-account/password-reset")
    types = {f["indicator_type"] for f in report["url_findings"]}
    assert "SUSPICIOUS_URL_KEYWORDS" in types


# =========================================================================
# 11. No URL
# =========================================================================
def test_11_email_without_urls_handled():
    result = analyze_email(
        sender="colleague@example.com", subject="Lunch?",
        body="Are you free for lunch at 1?", urls="", use_ml=False,
    )
    assert result["url_analysis"]["url_count"] == 0
    assert result["features"]["url_count"] == 0
    triggered = {t["rule"] for t in result["triggered_rules"]}
    assert "SUSPICIOUS_URL" not in triggered


# =========================================================================
# 12. Multiple URLs
# =========================================================================
def test_12_multiple_urls_all_analyzed():
    result = analyze_email(
        sender="news@example.net", subject="Update",
        body="See https://example.net/a and https://example.org/b and http://198.51.100.5/c",
        use_ml=False,
    )
    assert result["url_analysis"]["url_count"] == 3
    assert len(result["url_analysis"]["url_reports"]) == 3
    assert result["url_analysis"]["has_ip_url"] is True


def test_12b_urls_are_extracted_from_the_body_when_not_listed():
    """A user pasting only the body must still get the links analysed."""
    result = analyze_email(
        sender="a@example.com", subject="hi",
        body="Please open https://example.org/page now.", urls="", use_ml=False,
    )
    assert result["url_analysis"]["url_count"] == 1


# =========================================================================
# 13. Normal attachment
# =========================================================================
def test_13_normal_attachment_low_risk():
    report = analyze_attachment("workshop_agenda.pdf")
    assert report["extension"] == ".pdf"
    assert report["is_executable"] is False
    assert report["suspicious"] is False
    assert report["attachment_risk"] < 40


# =========================================================================
# 14. Executable attachment
# =========================================================================
def test_14_executable_attachment_high_risk():
    report = analyze_attachment("invoice.exe")
    assert report["is_executable"] is True
    assert report["suspicious"] is True
    assert report["attachment_risk"] >= 40


@pytest.mark.parametrize("filename", ["a.exe", "b.scr", "c.js", "d.vbs", "e.bat", "f.ps1"])
def test_14b_dangerous_extensions_all_flagged(filename):
    assert analyze_attachment(filename)["suspicious"] is True


# =========================================================================
# 15. Double extension
# =========================================================================
def test_15_double_extension_detected():
    report = analyze_attachment("invoice.pdf.exe")
    assert report["has_double_extension"] is True
    assert report["suspicious"] is True


def test_15b_double_extension_triggers_the_attachment_rule():
    result = analyze_email(
        sender="billing@example.com", subject="Invoice",
        body="Statement attached.", attachment_name="statement.pdf.exe", use_ml=False,
    )
    weights = {t["rule"]: t["weight"] for t in result["triggered_rules"]}
    assert weights.get("SUSPICIOUS_ATTACHMENT") == 25


# =========================================================================
# 16. Empty subject
# =========================================================================
def test_16_empty_subject_handled():
    result = analyze_email(sender="a@example.com", subject="", body="Some text here.",
                           use_ml=False)
    assert isinstance(result["risk_score"], int)
    assert result["input"]["subject"] == ""


# =========================================================================
# 17. Empty body
# =========================================================================
def test_17_empty_body_handled():
    result = analyze_email(sender="a@example.com", subject="Hello", body="", use_ml=False)
    assert isinstance(result["risk_score"], int)
    assert 0 <= result["risk_score"] <= 100


def test_17b_completely_empty_input_does_not_crash():
    result = analyze_email(sender="", subject="", body="", use_ml=False)
    assert result["risk_score"] >= 0


# =========================================================================
# 18. Invalid sender
# =========================================================================
def test_18_invalid_sender_format_detected():
    report = analyze_sender("not-an-email-address")
    assert report["is_valid_format"] is False


def test_18b_valid_sender_format_accepted():
    report = analyze_sender("training@example.org")
    assert report["is_valid_format"] is True
    assert report["domain"] == "example.org"


# =========================================================================
# 19. High uppercase ratio
# =========================================================================
def test_19_high_uppercase_ratio_detected():
    content = analyze_email_content(
        "ACT NOW", "YOUR ACCOUNT IS LOCKED AND YOU MUST RESPOND IMMEDIATELY TODAY")
    assert content["uppercase_ratio"] > 0.5
    assert content["flags"]["formatting_anomaly"] is True
    finding = next(f for f in content["content_findings"]
                   if f["indicator_type"] == "FORMATTING_ANOMALY")
    assert "upper-case" in finding["description"]


def test_19b_normal_text_has_low_uppercase_ratio():
    content = analyze_email_content("Meeting", "Hi, the meeting moved to 4 PM. Thanks.")
    assert content["uppercase_ratio"] < 0.3


# =========================================================================
# 20. Multiple exclamation marks
# =========================================================================
def test_20_multiple_exclamation_marks_detected():
    content = analyze_email_content("Win!!!", "You have won!!! Claim now!!!")
    assert content["exclamation_count"] >= 3
    assert content["flags"]["formatting_anomaly"] is True
    finding = next(f for f in content["content_findings"]
                   if f["indicator_type"] == "FORMATTING_ANOMALY")
    assert "exclamation marks" in finding["description"]


# =========================================================================
# 21. Rule-score boundary
# =========================================================================
def test_21_score_is_capped_at_100():
    """Every rule firing at once must still produce a score of exactly 100.

    The seven weights add up to 105 (15+10+20+20+25+5+10), so this also proves
    the cap is real rather than coincidental.
    """
    from backend.services.url_analyzer import analyze_urls

    sender = analyze_sender("security-alert@account-verify-login.invalid.test")
    content = analyze_email_content(
        "URGENT: Dear Customer, verify your account now!!!",
        "Dear Customer, your account has been suspended. Confirm your password and login "
        "credentials immediately or your account will be permanently closed. "
        "Click here: http://198.51.100.10/verify",
    )
    urls = analyze_urls(["http://198.51.100.10/verify-account-login"])
    attachment = analyze_attachment("invoice.pdf.exe")

    result = calculate_phishing_score(sender, content, urls, attachment)
    assert result["max_possible_raw_score"] == 105
    assert result["raw_score"] == 105, result["triggered_rules"]
    assert result["risk_score"] == 100
    assert result["cap_applied"] is True
    assert len(result["triggered_rules"]) == 7


@pytest.mark.parametrize("score,expected", [
    (0, "LOW RISK"), (20, "LOW RISK"),
    (21, "MODERATE RISK"), (40, "MODERATE RISK"),
    (41, "SUSPICIOUS"), (70, "SUSPICIOUS"),
    (71, "HIGH RISK / LIKELY PHISHING"), (100, "HIGH RISK / LIKELY PHISHING"),
])
def test_21b_band_boundaries_are_exact(score, expected):
    """Boundary values must land in the documented band, not one either side."""
    from backend.services.risk_engine import classify_risk
    assert classify_risk(score) == expected


def test_21c_zero_score_reports_the_safe_state():
    from backend.services.risk_engine import risk_state
    from backend.services.url_analyzer import analyze_urls

    result = calculate_phishing_score(
        analyze_sender("training@example.org"),
        analyze_email_content("Team lunch", "Hi Priya, lunch is at 1 PM in the canteen."),
        analyze_urls([]),
        analyze_attachment(""),
    )
    assert result["risk_score"] == 0
    assert result["triggered_rules"] == []
    assert risk_state(0) == "SAFE"
    assert result["risk_state"] == "SAFE"


# =========================================================================
# 22. Database save
# =========================================================================
def test_22_analysis_is_saved_and_retrievable(temp_db, phishing_email):
    from backend.models.repository import get_analysis, save_analysis

    result = analyze_email(**phishing_email, use_ml=False)
    analysis_id = save_analysis(result)
    stored = get_analysis(analysis_id)

    assert stored is not None
    assert stored["analysis_id"] == analysis_id
    assert stored["risk_score"] == result["risk_score"]
    assert len(stored["indicators"]) > 0
    assert len(stored["url_analyses"]) == 1


def test_22b_deleting_an_analysis_cascades_to_its_children(temp_db, phishing_email):
    import sqlite3

    from backend.models.repository import delete_analysis, save_analysis

    result = analyze_email(**phishing_email, use_ml=False)
    analysis_id = save_analysis(result)

    assert delete_analysis(analysis_id) is True
    conn = sqlite3.connect(temp_db)
    for table in ("indicators", "url_analyses"):
        remaining = conn.execute(
            f"SELECT COUNT(*) FROM {table} WHERE analysis_id = ?", (analysis_id,)
        ).fetchone()[0]
        assert remaining == 0, f"{table} rows were orphaned by the delete"
    conn.close()


def test_22c_the_raw_body_is_not_stored_by_default(temp_db, phishing_email):
    """Privacy: the full message body must not land in the database unless asked."""
    import sqlite3

    from backend.models.repository import save_analysis

    result = analyze_email(**phishing_email, use_ml=False)
    analysis_id = save_analysis(result)
    conn = sqlite3.connect(temp_db)
    row = conn.execute(
        "SELECT body_stored, body_preview FROM analyses WHERE analysis_id = ?",
        (analysis_id,),
    ).fetchone()
    conn.close()
    assert row[0] == 0
    assert not row[1]


# =========================================================================
# 23. API validation
# =========================================================================
def test_23_api_rejects_an_empty_payload(client):
    assert client.post("/api/analyze", json={}).status_code == 422


def test_23b_api_returns_404_for_an_unknown_analysis(client):
    assert client.get("/api/analyses/no-such-id").status_code == 404
    assert client.delete("/api/analyses/no-such-id").status_code == 404


def test_23c_api_analyze_returns_the_documented_shape(client, phishing_email):
    response = client.post("/api/analyze", json=phishing_email)
    assert response.status_code == 200
    body = response.json()
    for key in ("analysis_id", "risk_score", "classification", "why",
                "indicators", "recommendations", "triggered_rules"):
        assert key in body, f"missing key: {key}"
    assert body["classification"] == "HIGH RISK / LIKELY PHISHING"


def test_23d_url_endpoint_never_returns_a_clickable_link(client):
    response = client.post("/api/analyze/url",
                           json={"url": "http://198.51.100.10/verify-account"})
    assert response.status_code == 200
    assert "hxxp" in response.json()["safe_representation"]


def test_23e_health_endpoint_reports_status(client):
    body = client.get("/api/health").json()
    assert body["status"] == "healthy"
    assert "ml_available" in body


# =========================================================================
# 24. ML prediction if enabled
# =========================================================================
def test_24_ml_prediction_when_a_model_is_present(phishing_email):
    """Skips cleanly when no model has been trained - it never fakes a result."""
    from backend.services import ml_service

    ml_service.reload_model()
    if not ml_service.is_available():
        pytest.skip("no trained model on disk - run ml/train_model.py to enable this test")

    result = analyze_email(**phishing_email, use_ml=True)
    ml = result["ml_detection"]
    assert ml["available"] is True
    assert 0.0 <= ml["probability"] <= 1.0
    assert ml["prediction"] in {"PHISHING", "LEGITIMATE"}

    hybrid = result["hybrid_detection"]
    assert 0 <= hybrid["combined_score"] <= 100


def test_24b_analysis_still_works_with_ml_disabled(phishing_email):
    """The rule engine must never depend on the model being present."""
    result = analyze_email(**phishing_email, use_ml=False)
    assert result["risk_score"] >= 71
    assert result["ml_detection"]["available"] is False


# =========================================================================
# 25. Analysis-history retrieval
# =========================================================================
def test_25_history_listing_filters_and_sorts(client, phishing_email, legitimate_email):
    client.post("/api/analyze", json=phishing_email)
    client.post("/api/analyze", json=legitimate_email)

    listing = client.get("/api/analyses?limit=10").json()
    assert listing["total"] == 2

    high_only = client.get(
        "/api/analyses?classification=HIGH RISK / LIKELY PHISHING").json()
    assert high_only["total"] == 1

    by_score = client.get("/api/analyses?sort_by=risk_score&order=desc").json()
    scores = [i["risk_score"] for i in by_score["items"]]
    assert scores == sorted(scores, reverse=True)

    searched = client.get("/api/analyses?search=Workshop").json()
    assert searched["total"] == 1


def test_25b_history_rejects_an_unknown_sort_column(client):
    """A sort column is interpolated into SQL, so it must be whitelisted."""
    response = client.get("/api/analyses?sort_by=risk_score;DROP TABLE analyses")
    assert response.status_code in (400, 422)


def test_25c_dashboard_stats_reflect_saved_analyses(client, phishing_email):
    client.post("/api/analyze", json=phishing_email)
    stats = client.get("/api/dashboard/stats").json()
    assert stats["total_analyzed"] == 1
    assert stats["likely_phishing"] == 1
    assert stats["average_risk_score"] > 0


# =========================================================================
# Feature extraction contract
# =========================================================================
def test_feature_extractor_returns_every_named_feature(phishing_email):
    features = extract_email_features(
        sender=phishing_email["sender"], subject=phishing_email["subject"],
        body=phishing_email["body"], urls=phishing_email["urls"],
        attachment_name=phishing_email["attachment_name"],
    )
    assert set(features) == set(FEATURE_NAMES)
    assert all(isinstance(v, (int, float)) for v in features.values())


def test_feature_extraction_is_deterministic(phishing_email):
    """Same input, same vector - otherwise training and inference cannot agree."""
    a = extract_email_features(
        sender=phishing_email["sender"], subject=phishing_email["subject"],
        body=phishing_email["body"], urls=phishing_email["urls"], attachment_name="")
    b = extract_email_features(
        sender=phishing_email["sender"], subject=phishing_email["subject"],
        body=phishing_email["body"], urls=phishing_email["urls"], attachment_name="")
    assert a == b


# =========================================================================
# Safety guarantees - these protect the project's ethical promises
# =========================================================================
def test_safety_url_analysis_makes_no_network_call(monkeypatch):
    """Fail loudly if anyone ever adds a request to the URL analyzer."""
    import socket

    def blocked(*args, **kwargs):                       # pragma: no cover
        raise AssertionError("URL analysis attempted a network connection")

    monkeypatch.setattr(socket.socket, "connect", blocked)
    monkeypatch.setattr(socket, "create_connection", blocked)
    monkeypatch.setattr(socket, "gethostbyname", blocked)

    report = analyze_url("http://198.51.100.10/verify-account")
    assert report["url_risk_score"] > 0


def test_safety_attachment_analysis_never_touches_the_filesystem(monkeypatch):
    """The analyzer reads a filename string; it must not open a file."""
    import builtins

    real_open = builtins.open

    def guarded(file, *args, **kwargs):
        if str(file).endswith((".exe", ".pdf", ".docm")):   # pragma: no cover
            raise AssertionError(f"attachment analysis tried to open {file}")
        return real_open(file, *args, **kwargs)

    monkeypatch.setattr(builtins, "open", guarded)
    assert analyze_attachment("invoice.pdf.exe")["suspicious"] is True


def test_safety_single_url_helper_defangs_output():
    report = analyze_single_url("http://198.51.100.10/login")
    assert "http://198.51.100.10" not in report["safe_representation"]
