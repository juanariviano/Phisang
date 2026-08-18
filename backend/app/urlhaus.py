from __future__ import annotations

from typing import Any, Optional

import httpx

from .cache import get_cached, set_cached
from .config import settings
from .models import ThreatIntel
from .normalize import hostname_of

URLHAUS_URL_ENDPOINT = "https://urlhaus-api.abuse.ch/v1/url/"
URLHAUS_HOST_ENDPOINT = "https://urlhaus-api.abuse.ch/v1/host/"


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


async def _post(endpoint: str, data: dict[str, str]) -> dict[str, Any]:
    try:
        async with httpx.AsyncClient(timeout=settings.urlhaus_timeout_seconds) as client:
            response = await client.post(endpoint, data=data, headers=_headers())
            response.raise_for_status()
            payload = response.json()
    except httpx.HTTPError as exc:
        raise UrlhausError(f"URLhaus request failed: {exc}") from exc
    except ValueError as exc:
        raise UrlhausError("URLhaus returned non-JSON") from exc

    if not isinstance(payload, dict) or "query_status" not in payload:
        raise UrlhausError("URLhaus returned an unexpected payload")
    return payload


async def lookup(normalized_url: str) -> ThreatIntel:
    url_key = f"url:{normalized_url}"
    cached = get_cached(url_key)
    if cached is not None:
        return ThreatIntel.model_validate(cached)

    url_payload = await _post(URLHAUS_URL_ENDPOINT, {"url": normalized_url})
    status = url_payload.get("query_status")

    if status == "ok":
        intel = _to_intel(url_payload, "url")
        set_cached(url_key, intel.model_dump())
        return intel

    if status not in {"no_results", "invalid_url"}:
        raise UrlhausError(f"URLhaus URL lookup status: {status}")

    host = hostname_of(normalized_url)
    host_key = f"host:{host}"
    cached_host = get_cached(host_key)
    if cached_host is not None:
        intel = ThreatIntel.model_validate(cached_host)
        set_cached(url_key, intel.model_dump())
        return intel

    host_payload = await _post(URLHAUS_HOST_ENDPOINT, {"host": host})
    host_status = host_payload.get("query_status")
    if host_status == "ok":
        intel = _to_intel(host_payload, "host")
        set_cached(host_key, intel.model_dump())
        set_cached(url_key, intel.model_dump())
        return intel

    if host_status not in {"no_results", "invalid_host", "invalid_url"}:
        raise UrlhausError(f"URLhaus host lookup status: {host_status}")

    intel = ThreatIntel(matched=False, source="URLhaus", feed_status="ok")
    set_cached(url_key, intel.model_dump())
    set_cached(host_key, intel.model_dump())
    return intel
