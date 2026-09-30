import asyncio
import json
from unittest.mock import AsyncMock

import httpx
import pytest

from app import evidence, explanations
from app.config import settings
from app.models import Explanation
from test_scan_evidence import scan


@pytest.fixture(autouse=True)
def reset(monkeypatch):
    monkeypatch.setattr(settings, "explanation_api_key", "test")
    evidence._explanations.clear()
    explanations._inflight.clear()
    yield
    evidence._explanations.clear()


def provider_event(text, reason=None):
    return ("data: " + json.dumps({"choices": [{"delta": {"content": text},
        "finish_reason": reason}]}, ensure_ascii=False) + "\r\n\r\n").encode()


def test_provider_partial_text_arrives_before_completion(monkeypatch):
    async def run():
        release = asyncio.Event()
        first = asyncio.Event()
        snapshots = []
        class Body(httpx.AsyncByteStream):
            async def __aiter__(self):
                raw = provider_event('{"summary":"Check café')
                # Split even inside the multibyte character and SSE delimiters.
                for byte in raw:
                    yield bytes([byte])
                await release.wait()
                yield provider_event(' carefully.","reasons":["Warning"],"advice":["Verify it."]}', "stop")
                yield b"data: [DONE]\n\n"
        client = httpx.AsyncClient
        monkeypatch.setattr(explanations.httpx, "AsyncClient", lambda **kw: client(
            transport=httpx.MockTransport(lambda req: httpx.Response(200, stream=Body())), **kw))
        async def update(value):
            snapshots.append(value)
            first.set()
        task = asyncio.create_task(explanations._completion({}, None, update))
        await asyncio.wait_for(first.wait(), 2)
        assert snapshots[0]["summary"] == "Check café"
        assert not task.done()
        release.set()
        result = await task
        assert result.summary == "Check café carefully."
    asyncio.run(run())


def test_partial_json_decodes_escapes_without_exposing_syntax():
    # Standard JSON escaping, including strings split mid-value.
    text = json.dumps({"summary": 'Read "quoted" text', "reasons": ["First", "Second"]})[:-5]
    result = explanations._partial_answer(text)
    assert result["summary"] == 'Read "quoted" text'
    assert result["reasons"][0] == "First"
    assert result["reasons"][1].startswith("Sec")
    assert explanations._partial_answer("[") is None


def test_subscribers_share_generation_and_disconnect_does_not_cancel(monkeypatch):
    async def run():
        release = asyncio.Event()
        async def complete(facts, image, publish):
            await publish({"summary": "Starting", "reasons": [], "advice": []})
            await release.wait()
            return Explanation(summary="Finished", reasons=["Evidence"], advice=["Be careful"])
        completion = AsyncMock(side_effect=complete)
        monkeypatch.setattr(explanations, "_completion", completion)
        first = await explanations.stream(scan())
        second = await explanations.stream(scan())
        assert "connected" in await anext(first)
        assert "connected" in await anext(second)
        assert "snapshot" in await asyncio.wait_for(anext(first), 2)
        assert "Starting" in await asyncio.wait_for(anext(second), 2)
        await first.aclose()
        assert not evidence._explanations
        release.set()
        assert "event: done" in await asyncio.wait_for(anext(second), 2)
        await second.aclose()
        cached = await explanations.stream(scan())
        assert "Finished" in await anext(cached)
        await cached.aclose()
        completion.assert_awaited_once()
    asyncio.run(run())


@pytest.mark.parametrize("tail", [b"", provider_event("", "length"), b'data: {"error":{"message":"secret"}}\n\n'])
def test_incomplete_or_failed_provider_output_is_never_cached(monkeypatch, tail):
    async def run():
        full = json.dumps({"summary": "Incomplete", "reasons": ["A"], "advice": ["B"]})
        body = provider_event(full) + tail
        client = httpx.AsyncClient
        monkeypatch.setattr(explanations.httpx, "AsyncClient", lambda **kw: client(
            transport=httpx.MockTransport(lambda req: httpx.Response(200, content=body)), **kw))
        events = await explanations.stream(scan())
        output = "".join([event async for event in events])
        assert "event: error" in output
        assert "event: done" not in output
        assert "secret" not in output
        assert not evidence._explanations
    asyncio.run(run())


def test_sse_endpoint_content_type_and_cached_answer(monkeypatch):
    from fastapi.testclient import TestClient
    from app.main import app
    monkeypatch.setattr(evidence, "get_scan", lambda scan_id: scan())
    monkeypatch.setattr(explanations, "_request", AsyncMock(return_value=Explanation(
        summary="Cached answer", reasons=["Evidence"], advice=["Check first"])))
    response = TestClient(app).post("/api/v1/scans/test/explain", headers={"Accept": "text/event-stream"})
    assert response.status_code == 200
    assert response.headers["content-type"].startswith("text/event-stream")
    assert response.headers["x-accel-buffering"] == "no"
    assert "event: done" in response.text
    assert "Cached answer" in response.text
