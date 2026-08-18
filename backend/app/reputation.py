from __future__ import annotations

import re

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
