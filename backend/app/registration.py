"""Bounded, best-effort domain registration facts from registry RDAP servers."""
import asyncio
import ipaddress
import time
from collections import OrderedDict
from datetime import datetime, timezone
from urllib.parse import quote, urljoin, urlsplit

import httpx
import tldextract

from .config import settings
from .models import DomainInfo
from .url_guard import validate

_extract = tldextract.TLDExtract(suffix_list_urls=(), cache_dir=None)
_bootstrap = (0.0, {})
_cache: OrderedDict[str, tuple[float, DomainInfo]] = OrderedDict()


def registered_domain(host: str) -> str | None:
    try:
        ipaddress.ip_address(host)
        return None
    except ValueError:
        pass
    return _extract(host).top_domain_under_public_suffix or None


async def _json(client, url):
    # Registry redirects are not trusted to lead to another public endpoint.
    for _ in range(4):
        if urlsplit(url).scheme != "https":
            raise ValueError("RDAP requires HTTPS")
        await validate(url)
        async with client.stream("GET", url, headers={"Accept": "application/rdap+json, application/json"}) as response:
            if response.is_redirect:
                url = urljoin(url, response.headers["location"])
                continue
            response.raise_for_status()
            chunks = bytearray()
            async for part in response.aiter_bytes():
                chunks.extend(part)
                if len(chunks) > 1_000_000:
                    raise ValueError("RDAP response too large")
            import json
            return json.loads(chunks)
    raise ValueError("Too many RDAP redirects")


def _date(value):
    if not isinstance(value, str):
        return None
    try:
        return datetime.fromisoformat(value.replace("Z", "+00:00")).isoformat()
    except ValueError:
        return None


def parse_record(domain: str, record: dict) -> DomainInfo:
    events = {e.get("eventAction"): _date(e.get("eventDate"))
              for e in record.get("events", []) if isinstance(e, dict)}
    registrar = None
    for entity in record.get("entities", []):
        if "registrar" not in entity.get("roles", []):
            continue
        card = entity.get("vcardArray", [])
        if len(card) == 2 and isinstance(card[1], list):
            for field in card[1]:
                if len(field) >= 4 and field[0] == "fn" and isinstance(field[3], str):
                    registrar = field[3][:250]
                    break
    return DomainInfo(status="ok", domain=domain, registrar=registrar,
        registered_at=events.get("registration"), expires_at=events.get("expiration"),
        nameservers=[n["ldhName"][:253] for n in record.get("nameservers", [])
                     if isinstance(n, dict) and isinstance(n.get("ldhName"), str)][:12],
        checked_at=datetime.now(timezone.utc).isoformat())


async def _lookup(domain):
    global _bootstrap
    async with httpx.AsyncClient(timeout=settings.rdap_timeout_seconds, follow_redirects=False) as client:
        if _bootstrap[0] < time.monotonic():
            data = await _json(client, "https://data.iana.org/rdap/dns.json")
            endpoints = {tld: urls[0] for tlds, urls in data["services"] for tld in tlds if urls}
            _bootstrap = (time.monotonic() + 86400, endpoints)
        endpoint = _bootstrap[1].get(domain.rsplit(".", 1)[-1])
        if not endpoint:
            return DomainInfo(domain=domain)
        record = await _json(client, endpoint.rstrip("/") + "/domain/" + quote(domain, safe=""))
        if record.get("objectClassName") != "domain":
            raise ValueError("Not a domain registration record")
        return parse_record(domain, record)


async def lookup(host: str) -> DomainInfo:
    domain = registered_domain(host)
    if not domain:
        return DomainInfo(status="not_applicable")
    if not settings.rdap_enabled:
        return DomainInfo(domain=domain)
    cached = _cache.get(domain)
    if cached and cached[0] > time.monotonic():
        _cache.move_to_end(domain)
        return cached[1].model_copy(deep=True)
    try:
        result = await asyncio.wait_for(_lookup(domain), settings.rdap_timeout_seconds)
    except Exception:
        # Registration service outages do not make the destination malicious.
        result = DomainInfo(domain=domain, checked_at=datetime.now(timezone.utc).isoformat())
    _cache[domain] = (time.monotonic() + (86400 if result.status == "ok" else 60), result)
    while len(_cache) > 256:
        _cache.popitem(last=False)
    return result.model_copy(deep=True)
