import asyncio
import json
from unittest.mock import AsyncMock, Mock

import httpx
import pytest

from app import evidence, explanations, history, policy, registration
from app.config import settings
from app.models import AnalyzeResponse, DomainInfo, Explanation, PageResult, ThreatIntel
from test_history_replay import row


def scan(**changes):
    data = dict(scan_id="scan_evidence", evidence_scan_id="scan_evidence",
        normalized_url="https://example.org/", classification="benign", confidence=70,
        decision_stage="page", threat_intel=ThreatIntel(matched=False, source="URLhaus"),
        page=PageResult(status="ok", preview_available=True), policy_version="test")
    return AnalyzeResponse(**(data | changes))


@pytest.fixture(autouse=True)
def clean_caches():
    evidence._images.clear()
    evidence._explanations.clear()
    registration._cache.clear()
    yield
    evidence._images.clear()
    evidence._explanations.clear()


@pytest.mark.parametrize("error", ["page_unavailable", "threat_intel_unavailable"])
def test_failed_scan_is_logged_but_next_peel_retries(monkeypatch, error):
    failed = scan(classification="unavailable", error_code=error, decision_stage="error")
    successful = scan()
    archived = Mock(return_value=None)
    record = Mock()
    fresh = AsyncMock(side_effect=[failed, successful])
    monkeypatch.setattr(history, "lookup", archived)
    monkeypatch.setattr(history, "record", record)
    monkeypatch.setattr(policy, "_analyze_fresh", fresh)
    first = asyncio.run(policy.analyze("https://example.org/", "web"))
    archived.return_value = row(first)
    second = asyncio.run(policy.analyze("https://example.org/", "web"))
    assert record.call_count == 2
    assert fresh.await_count == 2
    assert second.classification == "benign"
    assert not second.served_from_history


def test_old_failed_and_corrupt_records_not_reused():
    assert not history.reusable({"LastClassification": "unavailable", "LastVerdict": "unknown"})
    assert not history.reusable({"RawResponseJson": "invalid"})
    assert not history.reusable(row(scan(page=PageResult(status="unavailable"))))


def test_replay_retains_evidence_and_registration():
    saved = scan(domain_info=DomainInfo(status="ok", domain="example.org"))
    stored = row(saved)
    replay = policy._from_history("replay", saved.normalized_url, stored, policy._prior_from_row(stored))
    assert replay.evidence_scan_id == saved.scan_id
    assert replay.domain_info == saved.domain_info


def test_domain_parsing_and_private_registration():
    assert registration.registered_domain("login.example.co.uk") == "example.co.uk"
    assert registration.registered_domain("someone.github.io") == "github.io"
    assert registration.registered_domain("8.8.8.8") is None
    info = registration.parse_record("example.org", {"events": [
        {"eventAction": "registration", "eventDate": "2000-01-02T00:00:00Z"},
        {"eventAction": "expiration", "eventDate": "garbage"}],
        "entities": [{"roles": ["registrar"], "vcardArray": ["vcard", [["fn", {}, "text", "Registrar"]]]}]})
    assert info.registrar == "Registrar"
    assert info.registered_at.startswith("2000-01-02")
    assert info.expires_at is None
    assert registration.parse_record("example.org", {}).status == "ok"


def test_rdap_failure_is_supplementary(monkeypatch):
    monkeypatch.setattr(settings, "rdap_enabled", True)
    lookup = AsyncMock(side_effect=ValueError("malformed response"))
    monkeypatch.setattr(registration, "_lookup", lookup)
    info = asyncio.run(registration.lookup("example.org"))
    assert info.status == "unavailable"
    assert info.domain == "example.org"


def test_rdap_rejects_private_redirects(monkeypatch):
    from app.url_guard import UrlRejected
    async def validate(url):
        if "127.0.0.1" in url:
            raise UrlRejected("private")
    monkeypatch.setattr(registration, "validate", validate)
    requests = []
    def handle(request):
        requests.append(str(request.url))
        return httpx.Response(302, headers={"location": "https://127.0.0.1/secret"})
    async def run():
        async with httpx.AsyncClient(transport=httpx.MockTransport(handle)) as client:
            with pytest.raises(UrlRejected):
                await registration._json(client, "https://registry.example/domain/example.org")
    asyncio.run(run())
    assert len(requests) == 1


def test_private_image_not_serialized_and_preview_bounded():
    item = scan()
    item.page._screenshot = b"\xff\xd8\xffimage"
    assert "screenshot" not in item.model_dump_json()
    evidence.remember_preview(item.scan_id, item.page._screenshot)
    assert evidence.get_preview(item.scan_id) == item.page._screenshot
    evidence.remember_preview("too_big", b"\xff\xd8\xff" + b"x" * evidence.MAX_PREVIEW_BYTES)
    evidence.remember_preview("html", b"<html>evil</html>")
    assert evidence.get_preview("too_big") is None
    assert evidence.get_preview("html") is None


def test_explain_is_cached_and_concurrent_calls_share_request(monkeypatch):
    monkeypatch.setattr(settings, "explanation_api_key", "test")
    complete = AsyncMock(return_value=Explanation(summary="Mixed findings.", reasons=["No listing."], advice=["Check the address."]))
    monkeypatch.setattr(explanations, "_completion", complete)
    async def run():
        first, second = await asyncio.gather(explanations.explain(scan()), explanations.explain(scan()))
        third = await explanations.explain(scan())
        assert first == second == third
    asyncio.run(run())
    complete.assert_awaited_once()


def test_provider_wire_format_includes_image_and_validates_output(monkeypatch):
    monkeypatch.setattr(settings, "explanation_api_key", "test-key")
    monkeypatch.setattr(settings, "explanation_base_url", "https://provider.example/v1/")
    calls = []
    def handle(request):
        calls.append(request)
        answer = json.dumps({"summary": "Check carefully.", "reasons": ["Model warning."], "advice": ["Use a known bookmark."]})
        body = "data: " + json.dumps({"choices": [{"delta": {"content": answer}, "finish_reason": "stop"}]}) + "\n\ndata: [DONE]\n\n"
        return httpx.Response(200, content=body, headers={"content-type": "text/event-stream"})
    client = httpx.AsyncClient
    monkeypatch.setattr(explanations.httpx, "AsyncClient", lambda **kwargs: client(transport=httpx.MockTransport(handle), **kwargs))
    answer = asyncio.run(explanations._completion(explanations.facts_for(scan()), b"\xff\xd8\xfftest"))
    assert str(calls[0].url) == "https://provider.example/v1/chat/completions"
    body = json.loads(calls[0].content)
    assert body["model"] == "gemini-3.5-flash-lite"
    assert body["stream"] is True
    assert body["messages"][1]["content"][1]["image_url"]["url"].startswith("data:image/jpeg;base64,")
    assert answer.included_screenshot


def test_provider_failure_not_cached_and_google_key_not_sent_elsewhere(monkeypatch):
    monkeypatch.setattr(settings, "gemini_api_key", "google-secret")
    monkeypatch.setattr(settings, "explanation_base_url", "https://another.example/v1")
    assert explanations.api_key() == ""
    monkeypatch.setattr(settings, "explanation_api_key", "test")
    complete = AsyncMock(side_effect=ValueError("malformed JSON"))
    monkeypatch.setattr(explanations, "_completion", complete)
    for _ in range(2):
        with pytest.raises(explanations.ExplanationError):
            asyncio.run(explanations.explain(scan()))
    assert complete.await_count == 2
    assert not evidence._explanations


@pytest.mark.parametrize("final_url,changed,host_changed", [
    ("https://accounts.example.net/sign-in", True, True),
    ("https://example.org/login", True, False),
    ("http://example.org/", True, False),
    ("https://EXAMPLE.org:443", False, False),
    ("https://example.org/", False, False),
    (None, None, None),
])
def test_destination_context_records_final_address_changes(final_url, changed, host_changed):
    item = scan(page=PageResult(status="ok", final_url=final_url, page_title="Account sign-in"))
    context = explanations.facts_for(item)["destination_context"]
    assert context["submitted_url"] == item.normalized_url
    assert context["final_url"] == final_url
    assert context["address_changed"] is changed
    assert context["host_changed"] is host_changed
    assert context["page_title"] == "Account sign-in"
    assert context["intermediate_redirects_recorded"] is False


@pytest.mark.parametrize("status", ["skipped", "unavailable"])
def test_uninspected_destination_does_not_claim_redirect_knowledge(status):
    context = explanations.destination_context(scan(page=PageResult(status=status)))
    assert not context["page_inspected"]
    assert context["address_changed"] is None
    assert context["host_changed"] is None
    assert context["final_url"] is None


def test_prompt_changes_invalidate_saved_explanations(monkeypatch):
    monkeypatch.setattr(settings, "explanation_api_key", "test")
    completion = AsyncMock(return_value=Explanation(summary="An account sign-in page.",
        reasons=["The page asks for a password."], advice=["Verify the address first."]))
    monkeypatch.setattr(explanations, "_completion", completion)
    async def run():
        await explanations.explain(scan())
        await explanations.explain(scan())
        assert completion.await_count == 1
        monkeypatch.setattr(explanations, "SYSTEM_PROMPT", explanations.SYSTEM_PROMPT + " Updated guidance.")
        await explanations.explain(scan())
        assert completion.await_count == 2
    asyncio.run(run())


def test_cursor_failure_does_not_yield_twice(monkeypatch):
    import pymssql
    conn = Mock()
    monkeypatch.setattr(settings, "db_enabled", True)
    monkeypatch.setattr(settings, "db_host", "mock")
    monkeypatch.setattr(pymssql, "connect", Mock(return_value=conn))
    with history._cursor():
        raise RuntimeError("Database operation failed")
    conn.rollback.assert_called_once()
    conn.close.assert_called_once()


def test_preview_and_explain_routes(monkeypatch):
    from fastapi.testclient import TestClient
    from app.main import app
    monkeypatch.setattr(evidence, "get_scan", lambda scan_id: scan() if scan_id == "scan_evidence" else None)
    evidence.remember_preview("scan_evidence", b"\xff\xd8\xffimage")
    client = TestClient(app)
    response = client.get("/api/v1/scans/scan_evidence/preview")
    assert response.status_code == 200
    assert response.headers["content-type"] == "image/jpeg"
    assert response.headers["x-content-type-options"] == "nosniff"
    assert client.get("/api/v1/scans/missing/preview").status_code == 404
    assert client.post("/api/v1/scans/missing/explain").status_code == 404
    assert client.post("/api/v1/scans/scan_evidence/explain").status_code == 503


@pytest.mark.parametrize("preview_fails", [False, True])
def test_fetch_captures_jpeg_and_preview_failure_keeps_html(monkeypatch, preview_fails):
    from app.page_fetch import Fetcher
    from playwright.async_api import Error
    image = b"\xff\xd8\xffimage"
    page = Mock(url="https://example.org/")
    page.goto = AsyncMock(return_value=Mock(status=200))
    page.content = AsyncMock(return_value="<html>Readable content</html>")
    page.title = AsyncMock(return_value="Example")
    page.screenshot = AsyncMock(side_effect=Error("capture failed") if preview_fails else None, return_value=image)
    context = Mock()
    context.new_page = AsyncMock(return_value=page)
    context.route = AsyncMock()
    context.close = AsyncMock()
    fetcher = Fetcher(settle=0)
    fetcher._browser = Mock(new_context=AsyncMock(return_value=context))
    monkeypatch.setattr(fetcher, "_resolve_redirects", AsyncMock(return_value=page.url))
    monkeypatch.setattr(fetcher, "_verify_peers", AsyncMock())
    result = asyncio.run(fetcher._fetch_once(page.url))
    assert result["html"] == "<html>Readable content</html>"
    assert result["screenshot"] == (None if preview_fails else image)
    assert page.screenshot.call_args.kwargs["type"] == "jpeg"
    assert not page.screenshot.call_args.kwargs["full_page"]
    context.close.assert_awaited_once()
