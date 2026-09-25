from __future__ import annotations

import logging
import re
from functools import lru_cache

from .config import DATA_DIR

logger = logging.getLogger("phisang")

# Top of the Tranco popularity ranking (https://tranco-list.eu), one domain per
# line; refresh with scripts/update_tranco.py.
POPULAR_DOMAINS_PATH = DATA_DIR / "tranco_top.txt"

IP_RE = re.compile(r"^(?:\d{1,3}\.){3}\d{1,3}$|^\[[0-9a-fA-F:]+\]$")

# Registrable roots where a few historical URLhaus rows must not poison the whole site.
WELL_KNOWN_ROOTS = {
    "google.com",
    "youtube.com",
    "youtu.be",
    "gstatic.com",
    "googleusercontent.com",
    "googlevideo.com",
    "wikipedia.org",
    "github.com",
    "microsoft.com",
    "live.com",
    "office.com",
    "apple.com",
    "icloud.com",
    "cloudflare.com",
    "amazon.com",
    "amazonaws.com",
    "facebook.com",
    "instagram.com",
    "whatsapp.com",
    "twitter.com",
    "x.com",
    "linkedin.com",
    "reddit.com",
    "bing.com",
    "duckduckgo.com",
    "yahoo.com",
    "mozilla.org",
    "stackoverflow.com",
    "netflix.com",
    "openai.com",
    "cloud.google.com",
}


def is_ip_host(host: str) -> bool:
    return bool(host) and bool(IP_RE.match(host))


def registered_domain(host: str) -> str:
    if not host:
        return ""
    hostname = host.lower().rstrip(".")
    if is_ip_host(hostname):
        return hostname
    labels = [part for part in hostname.split(".") if part]
    if len(labels) <= 2:
        return hostname
    return ".".join(labels[-2:])


def is_well_known_host(host: str) -> bool:
    root = registered_domain(host)
    return root in WELL_KNOWN_ROOTS or host.lower().rstrip(".") in WELL_KNOWN_ROOTS


@lru_cache(maxsize=1)
def _popular_domains() -> frozenset[str]:
    try:
        lines = POPULAR_DOMAINS_PATH.read_text(encoding="utf-8").splitlines()
    except FileNotFoundError:
        logger.warning("popular-domain list missing at %s; run scripts/update_tranco.py",
                       POPULAR_DOMAINS_PATH)
        return frozenset()
    return frozenset(line.strip().lower() for line in lines if line.strip())


def popular_domain_count() -> int:
    return len(_popular_domains())


def is_popular_host(host: str) -> bool:
    """True when the host itself is a ranked domain.

    Exact match only (plus a leading "www."): Tranco ranks shared-hosting roots
    such as github.io or blogspot.com, and matching parents would clear every
    attacker-owned subdomain under them.
    """
    hostname = host.lower().rstrip(".")
    if hostname.startswith("www."):
        hostname = hostname[4:]
    return bool(hostname) and hostname in _popular_domains()
