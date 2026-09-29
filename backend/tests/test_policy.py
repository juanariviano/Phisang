"""Decision routing tests; no network, browser or model weights required."""

import asyncio
import sys
from pathlib import Path
from unittest.mock import AsyncMock, Mock

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from app import policy
from app.models import PageResult, ThreatIntel
from app.page_stage import PageStageError
from app.urlhaus import UrlhausError


@pytest.fixture
def stages(monkeypatch):
    lookup = AsyncMock(return_value=ThreatIntel(matched=False, source="URLhaus"))
    classify = AsyncMock()
    monkeypatch.setattr(policy.urlhaus, "lookup", lookup)
    monkeypatch.setattr(policy.page_stage, "classify", classify)
    monkeypatch.setattr(policy, "remember", Mock())
    return lookup, classify


@pytest.mark.parametrize("label,score,confidence", [("phishing", 0.99, 99), ("benign", 0.03, 97)])
def test_plain_url_requires_page_verdict(stages, label, score, confidence):
    lookup, classify = stages
    classify.return_value = PageResult(
        label=label, confidence=confidence, phishing_score=score,
        model_name="phishing-html-classifier-v1", status="ok",
    )
    result = asyncio.run(policy.analyze("https://example.org/", "web"))
    assert result.heuristic.confidence == 100
    assert result.heuristic.label == "benign"
    lookup.assert_awaited_once_with("https://example.org/")
    classify.assert_awaited_once_with("https://example.org/")
    assert result.decision_stage == "page"
    assert result.classification == label
    assert result.confidence == confidence
    assert result.page.phishing_score == score
    assert result.page.status == "ok"
    assert result.error_code is None
    assert result.policy_version == "poc-flowchart-v2.1"


@pytest.mark.parametrize("reason", ["Page analysis is not available", "Destination could not be fetched: timeout"])
def test_page_failure_cannot_fall_back_to_benign(stages, reason):
    _, classify = stages
    classify.side_effect = PageStageError(reason)
    result = asyncio.run(policy.analyze("https://example.org/", "web"))
    classify.assert_awaited_once()
    assert result.heuristic.confidence == 100
    assert result.classification == "unavailable"
    assert result.confidence == 0
    assert result.decision_stage == "error"
    assert result.error_code == "page_unavailable"
    assert result.page.status == "unavailable"


def test_urlhaus_match_still_blocks_without_fetch(stages):
    lookup, classify = stages
    lookup.return_value = ThreatIntel(matched=True, source="URLhaus", match_kind="url")
    result = asyncio.run(policy.analyze("https://example.org/", "web"))
    assert result.classification == "malware"
    assert result.decision_stage == "urlhaus"
    classify.assert_not_awaited()


def test_urlhaus_failure_stays_unavailable(stages):
    lookup, classify = stages
    lookup.side_effect = UrlhausError("timeout")
    result = asyncio.run(policy.analyze("https://example.org/", "web"))
    assert result.classification == "unavailable"
    assert result.error_code == "threat_intel_unavailable"
    classify.assert_not_awaited()
