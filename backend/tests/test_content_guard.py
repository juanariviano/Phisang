import asyncio
from types import SimpleNamespace
from unittest.mock import AsyncMock, Mock

import pytest
from fastapi.testclient import TestClient

from app import history, main, page_fetch, page_stage, policy
from app.content_guard import UnsupportedContent, check_page_headers, check_page_url
from app.models import ThreatIntel


@pytest.mark.parametrize("url", [
    "https://example.org/SETUP.EXE?download=1#here",
    "https://example.org/report%2epdf", "https://example.org/%FFreport%2epdf", "https://example.org/archive.tar.gz",
    "https://example.org/picture.jpg/", "https://example.org/music.mp3",
    "https://example.org/file.pdf;session=abc", "https://example.org/data.json",
])
def test_file_paths_rejected(url):
    with pytest.raises(UnsupportedContent):
        check_page_url(url)


@pytest.mark.parametrize("url", [
    "https://example.com", "https://example.zip/", "https://example.org/index.html",
    "https://example.org/login.php", "https://example.org/login.aspx",
    "https://example.org/page.jsp", "https://example.org/report.pdf/view",
    "https://example.org/?next=file.exe", "https://example.org/home#file.pdf",
])
def test_webpages_and_hostname_suffixes_allowed(url):
    check_page_url(url)


@pytest.mark.parametrize("headers", [
    {"Content-Type": "application/pdf"}, {"content-type": "image/png"},
    {"content-type": "application/octet-stream"}, {},
    {"content-type": "text/html", "content-disposition": 'Attachment; filename="download.html"'},
])
def test_non_html_and_attachments_rejected(headers):
    with pytest.raises(UnsupportedContent):
        check_page_headers(headers)


@pytest.mark.parametrize("mime", ["text/html; charset=utf-8", "Application/XHTML+XML"])
def test_html_types_allowed(mime):
    check_page_headers({"Content-Type": mime})


@pytest.mark.parametrize("streaming", [False, True])
@pytest.mark.parametrize("client", ["web", "extension"])
def test_input_rejected_before_archive_or_any_scan(monkeypatch, streaming, client):
    lookup, record, fresh = Mock(), Mock(), AsyncMock()
    monkeypatch.setattr(policy.history, "lookup", lookup)
    monkeypatch.setattr(policy.history, "record", record)
    monkeypatch.setattr(policy, "_analyze_fresh", fresh)
    response = TestClient(main.app).post("/api/v1/analyze",
        json={"url": "example.org/download.pdf?token=abc", "client": client, "rescan": True},
        headers={"Accept": "text/event-stream"} if streaming else {})
    assert "unsupported_content" in response.text
    assert "webpages, not files" in response.text
    if streaming:
        assert "event: error" in response.text and "event: done" not in response.text
    else:
        assert response.status_code == 400
    lookup.assert_not_called()
    record.assert_not_called()
    fresh.assert_not_awaited()


def response(status=200, headers=None):
    return SimpleNamespace(status=status, headers=headers or {}, dispose=AsyncMock())


def test_redirect_to_file_is_rejected_before_requesting_file(monkeypatch):
    monkeypatch.setattr(page_fetch, "validate", AsyncMock())
    redirect = response(302, {"location": "/archive.zip?token=abc"})
    context = SimpleNamespace(request=SimpleNamespace(head=AsyncMock(return_value=redirect)))
    with pytest.raises(UnsupportedContent):
        asyncio.run(page_fetch.Fetcher()._resolve_redirects(context, "https://example.org/start"))
    context.request.head.assert_awaited_once()
    redirect.dispose.assert_awaited_once()


def test_extensionless_download_stops_at_headers_without_get_or_browser(monkeypatch):
    monkeypatch.setattr(page_fetch, "validate", AsyncMock())
    reply = response(headers={"content-type": "application/pdf"})
    context = SimpleNamespace(request=SimpleNamespace(head=AsyncMock(return_value=reply)))
    with pytest.raises(UnsupportedContent):
        asyncio.run(page_fetch.Fetcher()._resolve_redirects(context, "https://example.org/download"))
    reply.dispose.assert_awaited_once()


def test_html_redirect_chain_remains_supported(monkeypatch):
    monkeypatch.setattr(page_fetch, "validate", AsyncMock())
    context = SimpleNamespace(request=SimpleNamespace(head=AsyncMock(side_effect=[
        response(302, {"location": "/login.php"}), response(headers={"content-type": "text/html"}),
    ])))
    assert asyncio.run(page_fetch.Fetcher()._resolve_redirects(context, "https://example.org/")) == "https://example.org/login.php"


def test_file_destination_never_reaches_model_or_scan_archive(monkeypatch):
    monkeypatch.setattr(policy.history, "lookup", Mock(return_value=None))
    record, predict = Mock(), Mock()
    monkeypatch.setattr(policy.history, "record", record)
    monkeypatch.setattr(policy.urlhaus, "lookup", AsyncMock(return_value=ThreatIntel(matched=False)))
    monkeypatch.setattr(page_stage, "_fetcher", Mock(fetch=AsyncMock(side_effect=UnsupportedContent())))
    monkeypatch.setattr(page_stage, "_classifier", Mock(predict=predict))
    with pytest.raises(UnsupportedContent):
        asyncio.run(policy.analyze("https://example.org/download", "web", inspect_page=True))
    predict.assert_not_called()
    record.assert_not_called()


def test_old_scan_with_file_destination_is_not_reused():
    from test_history_replay import result, row
    saved = result()
    saved.page.final_url = "https://example.org/file.pdf"
    assert not history.reusable(row(saved))


@pytest.mark.parametrize("download", [False, True])
def test_actual_browser_response_is_checked_even_when_head_says_html(monkeypatch, download):
    # A server can answer HEAD differently, or JavaScript can navigate elsewhere.
    fetcher = page_fetch.Fetcher(settle=0)
    monkeypatch.setattr(fetcher, "_resolve_redirects", AsyncMock(return_value="https://example.org/"))
    frame = object()
    actual = SimpleNamespace(status=200, headers={"content-type": "application/pdf"},
        url="https://example.org/download", frame=frame,
        request=SimpleNamespace(is_navigation_request=lambda: True))
    page = SimpleNamespace(main_frame=frame, content=AsyncMock(), title=AsyncMock(), url=actual.url)
    handlers = {}
    page.on = lambda event, callback: handlers.update({event: callback})

    async def goto(*args, **kwargs):
        handlers["response"](actual)
        if download:
            from playwright.async_api import Error
            handlers["download"](None)
            raise Error("Download is starting")
        return actual

    page.goto = goto
    context = SimpleNamespace(route=AsyncMock(), new_page=AsyncMock(return_value=page), close=AsyncMock())
    fetcher._browser = SimpleNamespace(new_context=AsyncMock(return_value=context))
    with pytest.raises(UnsupportedContent):
        asyncio.run(fetcher._fetch_once("https://example.org/"))
    page.content.assert_not_awaited()
    context.close.assert_awaited_once()
