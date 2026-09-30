import asyncio
from pathlib import Path
from unittest.mock import AsyncMock, Mock

import pytest

from app import page_stage, policy, scan_progress
from app.models import AnalyzeRequest, ThreatIntel
from app.page_fetch import FetchFailed
from test_history_replay import result, row


def test_cached_scans_do_not_report_skipped_checks(monkeypatch):
    saved = result()
    monkeypatch.setattr(policy.history, "lookup", Mock(return_value=row(saved)))
    events = []
    async def run():
        async def collect(event): events.append(event)
        with scan_progress.listen(collect):
            cached = await policy.analyze(saved.normalized_url, "web")
        assert cached.served_from_history
    asyncio.run(run())
    assert [e["stage"] for e in events] == ["history", "history", "result"]
    assert events[1]["status"] == "complete"


@pytest.mark.parametrize("failed", [False, True])
def test_page_progress_tracks_fetch_and_model_work(monkeypatch, failed):
    monkeypatch.setattr(policy.history, "lookup", Mock(return_value=None))
    monkeypatch.setattr(policy.urlhaus, "lookup", AsyncMock(return_value=ThreatIntel(matched=False)))
    monkeypatch.setattr(policy, "is_popular_host", lambda host: False)
    monkeypatch.setattr(policy, "is_well_known_host", lambda host: False)
    fetcher = Mock(fetch=AsyncMock(side_effect=FetchFailed("timeout") if failed else None,
        return_value={"status": 200, "final_url": "https://example.org/", "title": "Example",
                      "html": '<html><input type="password"></html>'}))
    monkeypatch.setattr(page_stage, "_fetcher", fetcher)
    monkeypatch.setattr(page_stage, "_classifier", Mock(model_dir=Path("model"), test_metrics={},
        predict=Mock(return_value={"phishing_score": .85})))
    events = []
    async def run():
        async def collect(event): events.append(event)
        with scan_progress.listen(collect):
            return await policy.analyze("https://example.org/", "web")
    output = asyncio.run(run())
    page_events = [e for e in events if e["stage"] == "page"]
    assert "Opening" in page_events[0]["detail"]
    assert page_events[-1]["status"] == ("unavailable" if failed else "complete")
    if failed:
        assert output.classification == "unavailable"
        assert len(page_events) == 2
    else:
        assert "Reading" in page_events[1]["detail"]
    assert events[-1]["stage"] == "result" and events[-1]["status"] == "complete"


def test_progress_listeners_are_isolated_between_simultaneous_scans():
    async def run():
        first, second = [], []
        async def request(name, output):
            async def collect(event): output.append(event)
            with scan_progress.listen(collect):
                await asyncio.sleep(0)
                await scan_progress.report(name, name)
        await asyncio.gather(request("first", first), request("second", second))
        assert [e["stage"] for e in first] == ["first"]
        assert [e["stage"] for e in second] == ["second"]
    asyncio.run(run())


def test_scan_stream_delivers_progress_before_done(monkeypatch):
    from app import main
    async def run():
        release = asyncio.Event()
        async def analyze(*args, **kwargs):
            await scan_progress.report("page", "Inspecting the website")
            await release.wait()
            return result()
        monkeypatch.setattr(main, "analyze", analyze)
        stream = main._scan_events(AnalyzeRequest(url="https://example.org"))
        assert "connected" in await anext(stream)
        assert "event: progress" in await asyncio.wait_for(anext(stream), 2)
        release.set()
        assert "event: done" in await asyncio.wait_for(anext(stream), 2)
        await stream.aclose()
    asyncio.run(run())


def test_disconnected_scan_stream_cancels_worker(monkeypatch):
    from app import main
    async def run():
        cancelled = asyncio.Event()
        async def analyze(*args, **kwargs):
            try:
                await scan_progress.report("page", "Inspecting the website")
                await asyncio.Event().wait()
            finally:
                cancelled.set()
        monkeypatch.setattr(main, "analyze", analyze)
        stream = main._scan_events(AnalyzeRequest(url="https://example.org"))
        await anext(stream)
        await asyncio.wait_for(anext(stream), 2)
        await stream.aclose()
        assert cancelled.is_set()
    asyncio.run(run())


def test_scan_error_event_and_json_compatibility(monkeypatch):
    from fastapi.testclient import TestClient
    from app import main
    from app.normalize import UrlError
    monkeypatch.setattr(main, "analyze", AsyncMock(side_effect=UrlError("invalid_url", "Invalid website address")))
    client = TestClient(main.app)
    response = client.post("/api/v1/analyze", json={"url": "bad"}, headers={"Accept": "text/event-stream"})
    assert response.headers["content-type"].startswith("text/event-stream")
    assert "event: error" in response.text and "event: done" not in response.text
    assert "Invalid website address" in response.text
    assert client.post("/api/v1/analyze", json={"url": "bad"}).status_code == 400
