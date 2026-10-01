"""A plain-HTTP address adds risk at every stage, and never past 100."""

import asyncio
import sys
from pathlib import Path
from unittest.mock import AsyncMock, Mock

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from app import heuristics, policy
from app.models import PageResult, PageSignals, ThreatIntel
from app.risk import HTTP_RISK_PENALTY, with_http_penalty


@pytest.mark.parametrize("score, scheme, expected", [
    (0.0, "http", HTTP_RISK_PENALTY),
    (0.3, "http", 0.4),
    (0.55, "http", 0.65),
    (0.95, "http", 1.0),     # Capped: a score may never exceed 1.0 (100%).
    (1.0, "http", 1.0),
    (0.3, "https", 0.3),     # HTTPS is left exactly as the gates scored it.
    (1.0, "https", 1.0),
])
def test_penalty_is_added_and_capped(score, scheme, expected):
    assert with_http_penalty(score, scheme) == pytest.approx(expected)


@pytest.fixture
def stages(monkeypatch):
    lookup = AsyncMock(return_value=ThreatIntel(matched=False, source="URLhaus"))
    classify = AsyncMock(return_value=PageResult(
        label="benign", confidence=90, phishing_score=0.2, status="ok",
        page_signals=PageSignals()))
    monkeypatch.setattr(policy.urlhaus, "lookup", lookup)
    monkeypatch.setattr(policy.page_stage, "classify", classify)
    monkeypatch.setattr(policy, "remember", Mock())
    return lookup, classify


def test_page_stage_score_is_raised_for_http(stages):
    secure = asyncio.run(policy.analyze("https://zkic.com/", "web"))
    plain = asyncio.run(policy.analyze("http://zkic.com/", "web"))
    assert secure.risk_score == pytest.approx(0.2)
    assert plain.risk_score == pytest.approx(0.2 + HTTP_RISK_PENALTY)
    assert any("plain HTTP" in signal for signal in plain.signals)
    assert not any("plain HTTP" in signal for signal in secure.signals)


def test_heuristic_shortcut_score_is_raised_for_http(stages, monkeypatch):
    monkeypatch.setattr(policy, "is_popular_host", lambda host: True)
    plain = asyncio.run(policy.analyze("http://monkeytype.com/", "web"))
    assert plain.decision_stage == "heuristic"
    assert plain.risk_score == pytest.approx(HTTP_RISK_PENALTY)
    assert plain.risk_level == "SAFE"


def test_urlhaus_match_stays_at_the_maximum(stages):
    lookup, _ = stages
    lookup.return_value = ThreatIntel(matched=True, source="URLhaus", match_kind="url")
    listed = asyncio.run(policy.analyze("http://77.73.133.113/lego/start", "web"))
    assert listed.risk_score == 1.0
    assert listed.risk_level == "High Risk"
    assert any("already at its 100% maximum" in signal for signal in listed.signals)


def test_penalty_can_cross_a_risk_band(stages):
    _, classify = stages
    classify.return_value = PageResult(label="benign", confidence=60, phishing_score=0.55,
                                       status="ok", page_signals=PageSignals())
    assert asyncio.run(policy.analyze("https://zkic.com/", "web")).risk_level == "POTENTIALLY UNSAFE"
    plain = asyncio.run(policy.analyze("http://zkic.com/", "web"))
    assert plain.risk_score == pytest.approx(0.65)
    assert plain.risk_level == "MALICIOUS"


def test_lexical_gate_no_longer_scores_the_scheme():
    # Scored once on the final risk instead, so the same URL is not charged twice.
    assert heuristics.score("http://zkic.com/").risk_score == heuristics.score("https://zkic.com/").risk_score
