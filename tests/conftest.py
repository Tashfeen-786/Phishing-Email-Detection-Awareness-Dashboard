"""
tests/conftest.py
=================
Shared fixtures.

Every test runs against a TEMPORARY SQLite file, never the real
data/phishing_analysis.db. That means running the suite can never destroy the
history you built up in the dashboard, and tests cannot pass or fail because of
rows left behind by a previous run.
"""

from __future__ import annotations

import sys
from pathlib import Path

import pytest

PROJECT_ROOT = Path(__file__).resolve().parent.parent
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))


@pytest.fixture()
def temp_db(tmp_path, monkeypatch):
    """Point the whole application at a throwaway database for one test."""
    from backend import config
    from backend.models import database

    db_path = tmp_path / "test_analysis.db"
    # database.get_database_path() re-reads settings on every call, so patching
    # the single settings object is enough to redirect the whole application.
    monkeypatch.setattr(config.settings, "DATABASE_PATH", db_path, raising=False)
    database.init_db(db_path)
    assert database.get_database_path() == db_path
    yield db_path


@pytest.fixture()
def client(temp_db, monkeypatch):
    """FastAPI test client bound to the temporary database."""
    from fastapi.testclient import TestClient

    from backend.app import app
    from backend.utils import security

    security.clear_revocations()
    # A rate limiter tuned for a human would make the test suite flaky.
    monkeypatch.setattr(security.analysis_limiter, "max_calls", 100_000, raising=False)
    with TestClient(app) as test_client:
        yield test_client


@pytest.fixture(scope="session")
def phishing_email():
    """The documented high-risk demo case."""
    return {
        "sender": "security-alert@account-check.invalid.test",
        "subject": "URGENT: Verify Your Account Immediately",
        "body": (
            "Dear Customer,\n\nYour account has been temporarily suspended due to unusual "
            "activity. You must verify your identity within 24 hours or your account will be "
            "permanently closed.\n\nClick here to confirm your password and login details: "
            "http://198.51.100.10/verify-account\n\nFailure to act will result in immediate "
            "termination of service.\n\nAccount Security Team"
        ),
        "urls": "http://198.51.100.10/verify-account",
        "attachment_name": "",
    }


@pytest.fixture(scope="session")
def legitimate_email():
    """The documented low-risk demo case."""
    return {
        "sender": "training@example.org",
        "subject": "Cybersecurity Workshop Reminder",
        "body": (
            "Hello,\n\nThis is a reminder that our internal cybersecurity workshop takes place "
            "on Thursday at 3 PM in Training Room B. We will cover password hygiene and safe "
            "browsing habits.\n\nThe agenda is attached. No registration is needed.\n\n"
            "Best regards,\nLearning and Development"
        ),
        "urls": "",
        "attachment_name": "workshop_agenda.pdf",
    }
