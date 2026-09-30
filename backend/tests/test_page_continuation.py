import asyncio
import json
from unittest.mock import AsyncMock, Mock

import pytest
from fastapi.testclient import TestClient

from app import history, main, policy
from app.models import PageResult, PageShortcut, ThreatIntel
from app.page_stage import PageStageError
from test_history_replay import row


@pytest.fixture
def stages(monkeypatch):
    monkeypatch.setattr(policy, "is_popular_host", lambda host: True)
    monkeypatch.setattr(policy, "popular_domain_count", lambda: 10_000)
    lookup = AsyncMock(return_value=ThreatIntel(matched=False))
    classify = AsyncMock(return_value=PageResult(status="ok", label="benign", confidence=90, phishing_score=.1))
    monkeypatch.setattr(policy.urlhaus, "lookup", lookup)
    monkeypatch.setattr(policy.page_stage, "classify", classify)
    return lookup, classify


def test_tranco_notice_is_persisted_and_replayed_without_inspecting_page(stages, monkeypatch):
    _, classify = stages
    record = Mock()
    monkeypatch.setattr(history, "record", record)
    first = asyncio.run(policy.analyze("https://example.org/", "web"))
    assert first.page_shortcut == PageShortcut(source="tranco", top_count=10_000)
    assert first.page.status == "skipped"
    assert record.call_args.args[0].page_shortcut == first.page_shortcut
    monkeypatch.setattr(history, "lookup", lambda url: row(first))
    replay = asyncio.run(policy.analyze(first.normalized_url, "web"))
    assert replay.served_from_history
    assert replay.page_shortcut == first.page_shortcut
    assert replay.evidence_scan_id == first.scan_id
    assert record.call_count == 1
    classify.assert_not_awaited()


@pytest.mark.parametrize("streaming", [False, True])
def test_continue_bypasses_both_archive_and_tranco_and_creates_new_evidence(stages, monkeypatch, streaming):
    lookup, classify = stages
    first = asyncio.run(policy.analyze("https://example.org/", "web"))
    monkeypatch.setattr(history, "lookup", lambda url: row(first))
    record = Mock()
    monkeypatch.setattr(history, "record", record)
    headers = {"Accept": "text/event-stream"} if streaming else {}
    response = TestClient(main.app).post("/api/v1/analyze", headers=headers,
        json={"url": first.normalized_url, "inspect_page": True})
    assert response.status_code == 200
    body = (json.loads(response.text.split('event: done\ndata: ', 1)[1].split('\n\n', 1)[0])
            if streaming else response.json())
    assert body["page"]["status"] == "ok"
    assert body["decision_stage"] == "page"
    assert not body["served_from_history"]
    assert body["page_shortcut"] is None
    assert body["evidence_scan_id"] != first.scan_id
    assert body["explanation"] is None
    assert any("You requested page inspection" in signal for signal in body["signals"])
    classify.assert_awaited_once_with(first.normalized_url)
    assert lookup.await_count == 2
    record.assert_called_once()
    assert record.call_args.kwargs["is_rescan"]
    if streaming:
        assert '"stage": "page"' in response.text


def test_continue_also_bypasses_builtin_domain_shortcut(stages, monkeypatch):
    _, classify = stages
    monkeypatch.setattr(policy, "is_popular_host", lambda host: False)
    first = asyncio.run(policy.analyze("https://github.com/", "web"))
    assert first.page_shortcut.source == "well_known"
    assert first.page_shortcut.top_count is None
    final = asyncio.run(policy.analyze(first.normalized_url, "web", inspect_page=True))
    assert final.page.status == "ok"
    assert final.page_shortcut is None
    classify.assert_awaited_once()


def test_continue_preserves_threat_blocks_and_private_target_guard(stages):
    lookup, classify = stages
    lookup.return_value = ThreatIntel(matched=True, threat_type="malware")
    blocked = asyncio.run(policy.analyze("https://example.org/", "web", inspect_page=True))
    assert blocked.classification == "malware"
    assert blocked.page_shortcut is None
    with pytest.raises(policy.UrlError):
        asyncio.run(policy.analyze("http://127.0.0.1/", "web", inspect_page=True))
    classify.assert_not_awaited()
    lookup.assert_awaited_once()


def test_failed_continuation_is_not_reusable(stages):
    _, classify = stages
    classify.side_effect = PageStageError("Destination unavailable")
    failed = asyncio.run(policy.analyze("https://example.org/", "web", inspect_page=True))
    assert failed.classification == "unavailable"
    assert failed.page_shortcut is None
    assert not history.reusable(row(failed))


def test_older_shortcut_records_get_a_continue_option_without_inventing_list_size(stages, monkeypatch):
    saved = asyncio.run(policy.analyze("https://example.org/", "web"))
    saved.page_shortcut = None
    monkeypatch.setattr(history, "lookup", lambda url: row(saved))
    replay = asyncio.run(policy.analyze(saved.normalized_url, "web"))
    assert replay.page_shortcut == PageShortcut(source="tranco")
