"""Admin sign-in, sessions, and what approving a report is allowed to do."""

import asyncio
import base64
import sys
import time
from datetime import datetime
from pathlib import Path
from unittest.mock import AsyncMock, Mock

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from app import admin, policy, totp
from app.config import settings
from app.models import PageResult, PageSignals, ThreatIntel

PASSWORD = "correct horse battery staple"


@pytest.fixture
def admin_config(monkeypatch):
    secret = totp.new_secret()
    monkeypatch.setattr(settings, "admin_email", "admin@example.com")
    monkeypatch.setattr(settings, "admin_password_hash", admin.hash_password(PASSWORD))
    monkeypatch.setattr(settings, "admin_totp_secret", secret)
    monkeypatch.setattr(settings, "admin_session_secret", "session-key-for-tests")
    monkeypatch.setattr(settings, "admin_session_minutes", 60)
    admin._attempts.clear()
    admin._spent_codes.clear()
    yield secret
    admin._attempts.clear()
    admin._spent_codes.clear()


def current(secret):
    return totp.code_at(secret, int(time.time() // totp.PERIOD))


def test_totp_matches_the_rfc_6238_vector():
    # The published vector for the SHA-1 suite: counter 1 is 287082.
    secret = base64.b32encode(b"12345678901234567890").decode().rstrip("=")
    assert totp.code_at(secret, 1) == "287082"


def test_a_code_is_accepted_one_step_either_side_and_no_further():
    secret = totp.new_secret()
    now = time.time()
    counter = int(now // totp.PERIOD)
    for step in (-1, 0, 1):
        assert totp.verify(secret, totp.code_at(secret, counter + step), now=now) == counter + step
    for step in (-2, 2):
        assert totp.verify(secret, totp.code_at(secret, counter + step), now=now) is None


@pytest.mark.parametrize("code", ["", "12345", "1234567", "abcdef", None])
def test_malformed_codes_are_refused_without_comparing(code):
    assert totp.verify(totp.new_secret(), code) is None


def test_password_verifier_round_trips_and_rejects_near_misses():
    stored = admin.hash_password(PASSWORD)
    assert stored.startswith("pbkdf2_sha256$")
    assert PASSWORD not in stored  # The password itself is never written down.
    assert admin.verify_password(PASSWORD, stored)
    assert not admin.verify_password(PASSWORD + " ", stored)
    assert not admin.verify_password("", stored)
    assert not admin.verify_password(PASSWORD, "garbage")


def test_sign_in_needs_all_three_factors(admin_config):
    secret = admin_config
    for email, password, code in [
        ("wrong@example.com", PASSWORD, current(secret)),
        ("admin@example.com", "wrong", current(secret)),
        ("admin@example.com", PASSWORD, "000000"),
    ]:
        with pytest.raises(admin.AdminError) as refused:
            admin.sign_in(email, password, code, client=f"test-{email}-{password}")
        assert refused.value.status == 401
        # One message for all three, so a failure never says which factor was wrong.
        assert str(refused.value) == "Wrong email, password or code."


def test_a_code_cannot_be_used_twice_inside_its_window(admin_config):
    code = current(admin_config)
    assert admin.sign_in("admin@example.com", PASSWORD, code, client="first")["token"]
    with pytest.raises(admin.AdminError):
        admin.sign_in("admin@example.com", PASSWORD, code, client="second")


def test_wrong_answers_are_rate_limited_per_client(admin_config):
    for _ in range(admin.MAX_ATTEMPTS):
        with pytest.raises(admin.AdminError) as refused:
            admin.sign_in("admin@example.com", "wrong", "000000", client="attacker")
        assert refused.value.status == 401
    with pytest.raises(admin.AdminError) as locked:
        admin.sign_in("admin@example.com", PASSWORD, current(admin_config), client="attacker")
    assert locked.value.status == 429
    # The lockout is per client, so one attacker cannot lock the real admin out.
    assert admin.sign_in("admin@example.com", PASSWORD, current(admin_config), client="admin")["token"]


def test_sessions_are_signed_and_expire(admin_config):
    token = admin.issue_session("admin@example.com")["token"]
    assert admin.session_email(token) == "admin@example.com"
    body, signature = token.split(".", 1)
    assert admin.session_email(f"{body}.{'0' * len(signature)}") is None  # Forged.
    assert admin.session_email("not-a-token") is None
    with pytest.raises(admin.AdminError):
        admin.require_session("")


def test_a_session_signed_with_another_key_is_refused(admin_config, monkeypatch):
    token = admin.issue_session("admin@example.com")["token"]
    monkeypatch.setattr(settings, "admin_session_secret", "a-different-key")
    assert admin.session_email(token) is None


def test_sign_in_is_closed_when_the_server_is_not_configured(monkeypatch):
    monkeypatch.setattr(settings, "admin_email", "")
    with pytest.raises(admin.AdminError) as refused:
        admin.sign_in("admin@example.com", PASSWORD, "123456", client="test")
    assert refused.value.status == 503


# --- what an approval does to a scan ----------------------------------------

def approved_row(**changes):
    row = {"SiteId": 1, "NormalizedUrl": "https://intranet.example/portal",
           "Host": "intranet.example", "FirstScannedAt": None, "LastScannedAt": None,
           "ScanCount": 2, "MaliciousCount": 1, "SafeCount": 0, "PotentiallyUnsafeCount": 0,
           "UnknownCount": 0, "EverMalicious": True, "LastVerdict": "malicious",
           "EffectiveVerdict": "malicious", "LastScore": .9, "LastDecisionStage": "page",
           "LastScanRef": "scan_old", "LastClassification": "phishing",
           "ApprovedAt": datetime(2026, 10, 2, 9, 0), "ApprovedBy": "admin@example.com"}
    return row | changes


@pytest.fixture
def approved(monkeypatch):
    monkeypatch.setattr(policy.history, "record", Mock())
    monkeypatch.setattr(policy, "remember", Mock())
    monkeypatch.setattr(policy.history, "lookup", lambda url: approved_row())
    monkeypatch.setattr(policy, "_registration_with_progress", AsyncMock(return_value=None))
    lookup = AsyncMock(return_value=ThreatIntel(matched=False, source="URLhaus"))
    monkeypatch.setattr(policy.urlhaus, "lookup", lookup)
    return lookup


def test_an_approved_address_is_cleared_without_fetching_the_page(approved):
    classify = AsyncMock()
    result = asyncio.run(policy.analyze("https://intranet.example/portal", "web"))
    assert result.decision_stage == "approved"
    assert result.classification == "benign"
    assert result.risk_score == 0.0
    assert result.page.status == "skipped"
    assert any("administrator" in signal for signal in result.signals)
    classify.assert_not_awaited()


def test_an_approval_never_overrides_a_live_threat_listing(approved, monkeypatch):
    approved.return_value = ThreatIntel(matched=True, source="URLhaus", match_kind="url")
    result = asyncio.run(policy.analyze("https://intranet.example/portal", "web"))
    # Neither the approval nor the archive may answer here: the feed wins.
    assert result.decision_stage == "urlhaus"
    assert result.classification == "malware"
    assert result.risk_score == 1.0


def test_a_listed_approved_address_is_not_released_by_a_stale_benign_archive(approved, monkeypatch):
    approved.return_value = ThreatIntel(matched=True, source="URLhaus", match_kind="url")
    monkeypatch.setattr(policy.history, "lookup",
                        lambda url: approved_row(LastVerdict="safe", EffectiveVerdict="safe",
                                                 LastClassification="benign", EverMalicious=False))
    result = asyncio.run(policy.analyze("https://intranet.example/portal", "web"))
    assert result.classification == "malware"


def test_an_approval_is_not_honoured_while_the_threat_feed_is_down(approved, monkeypatch):
    from app.urlhaus import UrlhausError
    approved.side_effect = UrlhausError("timeout")
    monkeypatch.setattr(policy.page_stage, "classify", AsyncMock(return_value=PageResult(
        label="benign", confidence=90, phishing_score=.2, status="ok", page_signals=PageSignals())))
    result = asyncio.run(policy.analyze("https://intranet.example/portal", "web"))
    assert result.decision_stage != "approved"


def test_review_refuses_a_decision_it_does_not_recognise():
    with pytest.raises(admin.AdminError) as refused:
        admin.review(1, "maybe", "admin@example.com")
    assert refused.value.status == 400
