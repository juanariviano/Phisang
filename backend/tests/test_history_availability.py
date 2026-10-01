import asyncio
from contextlib import contextmanager
from unittest.mock import AsyncMock, Mock

import pytest
from fastapi.testclient import TestClient

from app import history, main, policy
from app.config import settings
from test_history_replay import result, row


@pytest.mark.parametrize("failure", ["connection", "query"])
def test_failed_sql_lookup_is_distinct_from_a_url_not_in_the_database(monkeypatch, failure):
    monkeypatch.setattr(settings, "db_enabled", True)
    monkeypatch.setattr(settings, "db_host", "mock")
    @contextmanager
    def cursor():
        # Model _cursor's deliberate suppression of database errors.
        try:
            yield None if failure == "connection" else Mock(execute=Mock(side_effect=RuntimeError("SQL failed")))
        except RuntimeError:
            pass
    monkeypatch.setattr(history, "_cursor", cursor)
    with pytest.raises(history.HistoryUnavailable):
        history.lookup("https://example.org/")


def test_successful_sql_miss_remains_a_new_url(monkeypatch):
    monkeypatch.setattr(settings, "db_enabled", True)
    monkeypatch.setattr(settings, "db_host", "mock")
    cur = Mock(fetchone=Mock(return_value=None))
    @contextmanager
    def cursor():
        yield cur
    monkeypatch.setattr(history, "_cursor", cursor)
    assert history.lookup("https://example.org/") is None
    assert cur.execute.call_args.args[1] == (history.url_hash("https://example.org/"),)


@pytest.mark.parametrize("streaming", [False, True])
def test_outage_does_not_fetch_or_log_a_new_scan(monkeypatch, streaming):
    monkeypatch.setattr(history, "lookup", Mock(side_effect=history.HistoryUnavailable("Saved scans are temporarily unavailable.")))
    fresh, domain, record = AsyncMock(), AsyncMock(), Mock()
    monkeypatch.setattr(policy, "_analyze_fresh", fresh)
    monkeypatch.setattr(policy, "_registration_with_progress", domain)
    monkeypatch.setattr(history, "record", record)
    response = TestClient(main.app).post("/api/v1/analyze", json={"url": "https://example.org/"},
        headers={"Accept": "text/event-stream"} if streaming else {})
    if streaming:
        assert "event: error" in response.text
        assert "event: done" not in response.text
    else:
        assert response.status_code == 503
    assert "history_unavailable" in response.text
    fresh.assert_not_awaited()
    domain.assert_not_awaited()
    record.assert_not_called()


def test_existing_url_is_reused_after_database_recovers(monkeypatch):
    saved = result()
    monkeypatch.setattr(history, "lookup", Mock(side_effect=[history.HistoryUnavailable("offline"), row(saved)]))
    fresh, record = AsyncMock(), Mock()
    monkeypatch.setattr(policy, "_analyze_fresh", fresh)
    monkeypatch.setattr(history, "record", record)
    with pytest.raises(history.HistoryUnavailable):
        asyncio.run(policy.analyze(saved.normalized_url, "web"))
    replay = asyncio.run(policy.analyze(saved.normalized_url, "web"))
    assert replay.served_from_history
    assert replay.classification == saved.classification
    assert replay.evidence_scan_id == saved.scan_id
    fresh.assert_not_awaited()
    record.assert_not_called()


@pytest.mark.parametrize("options", [{"rescan": True}, {"inspect_page": True}])
def test_explicit_fresh_scan_still_works_during_an_archive_outage(monkeypatch, options):
    monkeypatch.setattr(history, "lookup", Mock(side_effect=history.HistoryUnavailable("offline")))
    fresh = AsyncMock(return_value=result())
    monkeypatch.setattr(policy, "_analyze_fresh", fresh)
    monkeypatch.setattr(history, "record", Mock())
    output = asyncio.run(policy.analyze("https://example.org/", "web", **options))
    assert not output.served_from_history
    fresh.assert_awaited_once()


def test_health_is_degraded_when_required_history_is_offline(monkeypatch):
    monkeypatch.setattr(settings, "db_enabled", True)
    monkeypatch.setattr(settings, "urlhaus_auth_key", "test")
    monkeypatch.setattr(main.page_stage, "ready", lambda: True)
    monkeypatch.setattr(main, "cache_ready", lambda: True)
    monkeypatch.setattr(history, "ready", lambda: False)
    response = main.health()
    assert response.status == "degraded"
    assert not response.history_ready
