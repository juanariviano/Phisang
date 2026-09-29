from __future__ import annotations

from typing import Any, Optional
from urllib.parse import urlsplit

import httpx

from . import history
from .cache import get_cached, set_cached
from .config import settings
from .models import ThreatIntel
from .normalize import hostname_of
from .reputation import is_ip_host

URLHAUS_URL_ENDPOINT = "https://urlhaus-api.abuse.ch/v1/url/"
URLHAUS_HOST_ENDPOINT = "https://urlhaus-api.abuse.ch/v1/host/"
CACHE_PREFIX = "v2"


class UrlhausError(RuntimeError):
    pass


def _headers() -> dict[str, str]:
    if not settings.urlhaus_auth_key:
        raise UrlhausError("URLHAUS_AUTH_KEY is not configured")
    return {"Auth-Key": settings.urlhaus_auth_key}


def _threat_type(payload: dict[str, Any]) -> Optional[str]:
    threat = payload.get("threat")
    if isinstance(threat, str) and threat:
        return threat
    tags = payload.get("tags")
    if isinstance(tags, list) and tags:
        return ",".join(str(t) for t in tags if t)
    return None


def _first_seen(payload: dict[str, Any]) -> Optional[str]:
    for key in ("date_added", "firstseen", "first_seen"):
        value = payload.get(key)
        if isinstance(value, str) and value:
            return " ".join(value.split())
    return None


def _to_intel(payload: dict[str, Any], match_kind: str) -> ThreatIntel:
    status = payload.get("query_status")
    if status != "ok":
        return ThreatIntel(matched=False, source="URLhaus", feed_status="ok")

    urlhaus_id = payload.get("id") or payload.get("urlhaus_reference")
    return ThreatIntel(
        matched=True,
        source="URLhaus",
        threat_type=_threat_type(payload),
        id=str(urlhaus_id) if urlhaus_id is not None else None,
        first_seen=_first_seen(payload),
        url_status=payload.get("url_status"),
        match_kind=match_kind,  # type: ignore[arg-type]
        feed_status="ok",
    )


def _same_listed_url(current: str, listed: str) -> bool:
    """True only if the current URL is the listed indicator or under the same path."""
    try:
        cur = urlsplit(current)
        lis = urlsplit(listed)
    except ValueError:
        return False
    if (cur.hostname or "").lower() != (lis.hostname or "").lower():
        return False
    cur_path = (cur.path or "/").rstrip("/") or "/"
    lis_path = (lis.path or "/").rstrip("/") or "/"
    if lis_path == "/":
        return cur_path == "/"
    if cur_path == lis_path:
        return True
    return cur_path.startswith(lis_path + "/")


def _intel_from_host(normalized_url: str, host: str, payload: dict[str, Any]) -> ThreatIntel:
    status = payload.get("query_status")
    if status in {"no_results", "invalid_host", "invalid_url"}:
        return ThreatIntel(matched=False, source="URLhaus", feed_status="ok")
    if status != "ok":
        raise UrlhausError(f"URLhaus host lookup status: {status}")

    # Dedicated malware IPs: any listing on the IP is enough to block.
    if is_ip_host(host):
        return _to_intel(payload, "host")

    listed = payload.get("urls") or []
    if not isinstance(listed, list):
        return ThreatIntel(matched=False, source="URLhaus", feed_status="ok")

    for item in listed:
        if not isinstance(item, dict):
            continue
        listed_url = item.get("url")
        if not listed_url or not _same_listed_url(normalized_url, str(listed_url)):
            continue
        urlhaus_id = item.get("id") or item.get("urlhaus_reference")
        return ThreatIntel(
            matched=True,
            source="URLhaus",
            threat_type=_threat_type(item) or _threat_type(payload),
            id=str(urlhaus_id) if urlhaus_id is not None else None,
            first_seen=_first_seen(item) or _first_seen(payload),
            url_status=item.get("url_status"),
            match_kind="host",
            feed_status="ok",
        )

    # Other URLhaus rows on this hostname are unrelated to the current path.
    return ThreatIntel(matched=False, source="URLhaus", feed_status="ok")


# The host endpoint occasionally takes 10+ seconds on a cold query and answers in
# about one on the next, so a timeout gets one more try before the scan degrades.
TIMEOUT_ATTEMPTS = 2


async def _post(endpoint: str, data: dict[str, str]) -> dict[str, Any]:
    try:
        async with httpx.AsyncClient(timeout=settings.urlhaus_timeout_seconds) as client:
            for attempt in range(1, TIMEOUT_ATTEMPTS + 1):
                try:
                    response = await client.post(endpoint, data=data, headers=_headers())
                    break
                except httpx.TimeoutException:
                    if attempt == TIMEOUT_ATTEMPTS:
                        raise
            response.raise_for_status()
            payload = response.json()
    except httpx.HTTPError as exc:
        # Timeouts carry an empty message, so the type is what says what happened.
        raise UrlhausError(f"URLhaus request failed: {type(exc).__name__} {exc}".rstrip()) from exc
    except ValueError as exc:
        raise UrlhausError("URLhaus returned non-JSON") from exc

    if not isinstance(payload, dict) or "query_status" not in payload:
        raise UrlhausError("URLhaus returned an unexpected payload")
    return payload


def _cache_read(key: str):
    """SQL archive first: a hit there spends no URLhaus token at all."""
    if history.enabled():
        hit = history.cache_get(key)
        if hit is not None:
            return hit
    return get_cached(key)


def _cache_write(key: str, payload: dict, matched: bool | None = None) -> None:
    if history.enabled():
        history.cache_set(key, payload, matched=matched)
    set_cached(key, payload)


async def lookup(normalized_url: str) -> ThreatIntel:
    url_key = f"{CACHE_PREFIX}:url:{normalized_url}"
    cached = _cache_read(url_key)
    if cached is not None:
        return ThreatIntel.model_validate(cached)

    url_payload = await _post(URLHAUS_URL_ENDPOINT, {"url": normalized_url})
    status = url_payload.get("query_status")

    if status == "ok":
        intel = _to_intel(url_payload, "url")
        _cache_write(url_key, intel.model_dump(), matched=True)
        return intel

    if status not in {"no_results", "invalid_url"}:
        raise UrlhausError(f"URLhaus URL lookup status: {status}")

    host = hostname_of(normalized_url)
    host_raw_key = f"{CACHE_PREFIX}:hostraw:{host}"
    host_payload = _cache_read(host_raw_key)
    if host_payload is None:
        host_payload = await _post(URLHAUS_HOST_ENDPOINT, {"host": host})
        _cache_write(host_raw_key, host_payload)

    intel = _intel_from_host(normalized_url, host, host_payload)
    _cache_write(url_key, intel.model_dump(), matched=intel.matched)
    return intel
