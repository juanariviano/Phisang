"""Decision-gate tests. Run from backend/: python -m pytest tests -q"""

import asyncio
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

import pytest

from app import policy
from app.models import PageResult, PageSignals, ThreatIntel


@pytest.fixture
def stub_gates(monkeypatch):
    calls = []

    async def lookup(url):
        return ThreatIntel(matched=False, source="URLhaus")

    def make_classify(label, confidence, password_inputs=0):
        async def classify(url):
            calls.append(url)
            return PageResult(label=label, confidence=confidence, phishing_score=0.99,
                              threshold=0.5, status="ok",
                              page_signals=PageSignals(password_inputs=password_inputs))
        monkeypatch.setattr(policy.page_stage, "classify", classify)

    monkeypatch.setattr(policy.urlhaus, "lookup", lookup)
    monkeypatch.setattr(policy, "remember", lambda result: None)
    monkeypatch.setattr(policy, "is_popular_host", lambda host: host.removeprefix("www.") == "monkeytype.com")
    return make_classify, calls


def test_unknown_clean_domain_is_fetched_not_cleared(stub_gates):
    make_classify, calls = stub_gates
    make_classify("phishing", 91, password_inputs=1)
    result = asyncio.run(policy.analyze("https://zkic.com/", "web"))
    assert calls == ["https://zkic.com/"]
    assert result.decision_stage == "page"
    assert result.classification == "phishing"


def test_model_alone_does_not_block_clean_url(stub_gates):
    make_classify, calls = stub_gates
    make_classify("phishing", 99)
    result = asyncio.run(policy.analyze("https://zkic.com/", "web"))
    assert calls
    assert result.classification == "benign"
    assert result.confidence == policy.UNCORROBORATED_BENIGN_CONFIDENCE
    # Not blocked, but the page's own score still shows through as its risk.
    assert result.risk_score == 0.99
    assert result.risk_level == "High Risk"
    assert any(signal.startswith("Warning:") for signal in result.signals)


def test_model_call_stands_on_doubtful_url(stub_gates):
    make_classify, calls = stub_gates
    make_classify("phishing", 97)
    result = asyncio.run(policy.analyze("https://crocs-com.ru/", "web"))
    assert calls
    assert result.classification == "phishing"


def test_popular_host_skips_fetch(stub_gates):
    make_classify, calls = stub_gates
    make_classify("phishing", 99, password_inputs=1)
    result = asyncio.run(policy.analyze("https://www.monkeytype.com/", "web"))
    assert calls == []
    assert result.classification == "benign"
    assert "Host is on the Tranco top-domain ranking" in result.signals


def test_well_known_host_still_skips_fetch(stub_gates):
    make_classify, calls = stub_gates
    make_classify("phishing", 91)
    result = asyncio.run(policy.analyze("https://github.com/", "web"))
    assert calls == []
    assert result.decision_stage == "heuristic"
    assert result.classification == "benign"
    assert result.risk_level == "SAFE"


def test_benign_page_does_not_clear_phishing_shaped_url(stub_gates):
    make_classify, calls = stub_gates
    make_classify("benign", 80)
    result = asyncio.run(policy.analyze("https://crocs-com.ru/login/verify", "web"))
    assert calls
    assert result.classification == "phishing"


def test_popular_match_is_exact_host_only(monkeypatch, tmp_path):
    from app import reputation
    listing = tmp_path / "tranco_top.txt"
    listing.write_text("github.io\nmonkeytype.com\n", encoding="utf-8")
    monkeypatch.setattr(reputation, "POPULAR_DOMAINS_PATH", listing)
    reputation._popular_domains.cache_clear()
    try:
        assert reputation.is_popular_host("monkeytype.com")
        assert reputation.is_popular_host("www.monkeytype.com")
        assert not reputation.is_popular_host("attacker.github.io")
        assert not reputation.is_popular_host("monkeytype.com.evil.ru")
    finally:
        reputation._popular_domains.cache_clear()


def _history_row(verdict, classification, score, stage):
    return {"SiteId": 1, "NormalizedUrl": "https://zkic.com/", "Host": "zkic.com",
            "FirstScannedAt": None, "LastScannedAt": None, "ScanCount": 1,
            "MaliciousCount": 0, "SafeCount": 0, "PotentiallyUnsafeCount": 0,
            "UnknownCount": 1, "EverMalicious": False, "LastVerdict": verdict,
            "EffectiveVerdict": verdict, "LastScore": score, "LastDecisionStage": stage,
            "LastScanRef": "scan_old", "LastClassification": classification}


def test_unknown_history_is_rescanned(stub_gates, monkeypatch):
    make_classify, calls = stub_gates
    make_classify("phishing", 91, password_inputs=1)
    monkeypatch.setattr(policy.history, "lookup",
                        lambda url: _history_row("unknown", "unavailable", None, "error"))
    monkeypatch.setattr(policy.history, "record", lambda *a, **k: None)
    result = asyncio.run(policy.analyze("https://zkic.com/", "web"))
    assert calls == ["https://zkic.com/"]
    assert result.decision_stage == "page"
    assert result.risk_level == "High Risk"


def test_history_replay_keeps_risk_level(stub_gates, monkeypatch):
    make_classify, calls = stub_gates
    make_classify("phishing", 91)
    monkeypatch.setattr(policy.history, "lookup",
                        lambda url: _history_row("safe", "benign", None, "heuristic"))
    monkeypatch.setattr(policy.history, "record", lambda *a, **k: None)
    result = asyncio.run(policy.analyze("https://zkic.com/", "web"))
    assert calls == []
    assert result.decision_stage == "history"
    assert result.risk_level == "SAFE"
