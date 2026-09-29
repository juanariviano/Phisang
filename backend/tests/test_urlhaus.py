"""URLhaus transport tests. Run from backend/: python -m pytest tests -q"""

import asyncio
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

import httpx
import pytest

from app import urlhaus

ENDPOINT = urlhaus.URLHAUS_HOST_ENDPOINT


@pytest.fixture(autouse=True)
def auth_key(monkeypatch):
    monkeypatch.setattr(urlhaus.settings, "urlhaus_auth_key", "test-key")


def _patch_post(monkeypatch, outcomes):
    calls = []

    async def post(self, url, **kwargs):
        calls.append(url)
        outcome = outcomes[len(calls) - 1]
        if isinstance(outcome, Exception):
            raise outcome
        return httpx.Response(200, json=outcome, request=httpx.Request("POST", url))

    monkeypatch.setattr(httpx.AsyncClient, "post", post)
    return calls


def test_one_timeout_is_retried(monkeypatch):
    calls = _patch_post(monkeypatch, [httpx.ReadTimeout(""), {"query_status": "no_results"}])
    payload = asyncio.run(urlhaus._post(ENDPOINT, {"host": "monkeytype.com"}))
    assert payload["query_status"] == "no_results"
    assert len(calls) == 2


def test_repeated_timeout_fails_with_a_readable_reason(monkeypatch):
    calls = _patch_post(monkeypatch, [httpx.ReadTimeout(""), httpx.ReadTimeout("")])
    with pytest.raises(urlhaus.UrlhausError, match="ReadTimeout"):
        asyncio.run(urlhaus._post(ENDPOINT, {"host": "monkeytype.com"}))
    assert len(calls) == urlhaus.TIMEOUT_ATTEMPTS
