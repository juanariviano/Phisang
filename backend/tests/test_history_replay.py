import asyncio
import sys
from datetime import datetime
from pathlib import Path
from unittest.mock import AsyncMock, Mock

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from app import policy, history
from app.models import AnalyzeResponse, PageResult, ThreatIntel


def result(classification="phishing", score=0.91):
    return AnalyzeResponse(
        scan_id="original", normalized_url="https://example.org/",
        classification=classification, confidence=91, risk_score=score,
        risk_level="High Risk", decision_stage="page",
        page=PageResult(label="phishing", confidence=91, phishing_score=score,
                        threshold=0.6, model_name="laya_v3", status="ok"),
        threat_intel=ThreatIntel(matched=False, source="URLhaus"),
        policy_version="test", signals=["Original evidence"],
    )


def row(saved):
    return dict(EffectiveVerdict="malicious", LastVerdict="malicious",
        LastScannedAt=datetime(2026, 9, 29), FirstScannedAt=datetime(2026, 9, 29),
        ScanCount=1, MaliciousCount=1, SafeCount=0, PotentiallyUnsafeCount=0,
        UnknownCount=0, EverMalicious=True, LastScore=.91, LastDecisionStage="page",
        LastClassification="phishing", RawResponseJson=saved.model_dump_json())


@pytest.mark.parametrize("classification", ["phishing", "benign"])
def test_cached_result_preserves_actual_result(monkeypatch, classification):
    saved = result(classification)
    stored = row(saved)
    monkeypatch.setattr(policy.history, "lookup", Mock(return_value=stored))
    record = Mock()
    monkeypatch.setattr(policy.history, "record", record)
    fresh = AsyncMock()
    monkeypatch.setattr(policy, "_analyze_fresh", fresh)
    monkeypatch.setattr(policy, "remember", Mock())
    for _ in range(2):
        cached = asyncio.run(policy.analyze(saved.normalized_url, "web"))
        assert cached.classification == saved.classification
        assert cached.confidence == saved.confidence
        assert cached.risk_score == saved.risk_score
        assert cached.risk_level == saved.risk_level
        assert cached.page == saved.page
        assert cached.served_from_history
        assert cached.decision_stage == "history"
    fresh.assert_not_awaited()
    record.assert_not_called()


def test_history_reads_do_not_update_database(monkeypatch):
    cursor = Mock(side_effect=AssertionError("Cache hit must not write to SQL"))
    monkeypatch.setattr(history, "_cursor", cursor)
    history.record(result(), served_from_history=True)
    cursor.assert_not_called()


def test_rescan_bypasses_archive(monkeypatch):
    saved = result()
    monkeypatch.setattr(policy.history, "lookup", Mock(return_value=row(saved)))
    record = Mock()
    monkeypatch.setattr(policy.history, "record", record)
    fresh = AsyncMock(return_value=saved)
    monkeypatch.setattr(policy, "_analyze_fresh", fresh)
    rescanned = asyncio.run(policy.analyze(saved.normalized_url, "web", rescan=True))
    fresh.assert_awaited_once()
    assert not rescanned.served_from_history
    assert record.call_args.kwargs["is_rescan"]
    assert not record.call_args.kwargs["served_from_history"]


def test_legacy_malicious_record_does_not_fall_back_to_benign(monkeypatch):
    stored = row(result())
    stored.update(RawResponseJson=None, LastClassification="benign")
    monkeypatch.setattr(policy, "remember", Mock())
    cached = policy._from_history("cached", "https://example.org/", stored, policy._prior_from_row(stored))
    assert cached.classification == "phishing"
    assert cached.risk_score == .91
