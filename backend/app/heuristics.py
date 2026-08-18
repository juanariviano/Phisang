from __future__ import annotations

import math
import re
from urllib.parse import unquote, urlsplit

from .models import HeuristicResult
from .reputation import is_well_known_host

SUSPICIOUS_TOKENS = (
    "login",
    "verify",
    "secure",
    "update",
    "account",
    "password",
    "wallet",
    "signin",
    "sign-in",
    "confirm",
    "billing",
    "invoice",
    "unlock",
    "limited",
    "suspend",
    "paypal",
    "banking",
    "credential",
)

SUSPICIOUS_TLDS = {
    "xyz",
    "top",
    "tk",
    "ml",
    "ga",
    "cf",
    "gq",
    "click",
    "link",
    "zip",
    "review",
    "country",
    "support",
    "rest",
    "work",
    "cam",
    "cfd",
    "sbs",
    "icu",
    "cyou",
}

IP_RE = re.compile(
    r"^(?:\d{1,3}\.){3}\d{1,3}$|^\[[0-9a-fA-F:]+\]$"
)


def _entropy(text: str) -> float:
    if not text:
        return 0.0
    counts: dict[str, int] = {}
    for ch in text:
        counts[ch] = counts.get(ch, 0) + 1
    length = len(text)
    return -sum((n / length) * math.log2(n / length) for n in counts.values())


def score(normalized_url: str) -> HeuristicResult:
    parts = urlsplit(normalized_url)
    host = (parts.hostname or "").lower()
    path = unquote(parts.path or "")
    query = unquote(parts.query or "")
    haystack = f"{host} {path} {query}".lower()
    signals: list[str] = []
    risk = 0

    if IP_RE.match(host or ""):
        risk += 35
        signals.append("Host is a bare IP literal with no associated domain name")

    if "@" in normalized_url.split("://", 1)[-1].split("/", 1)[0]:
        risk += 25
        signals.append("URL contains a credential-like '@' in the host section")

    if host.startswith("xn--") or ".xn--" in host:
        risk += 20
        signals.append("Hostname uses punycode, which can hide lookalike characters")

    labels = [part for part in host.split(".") if part]
    if len(labels) >= 5:
        risk += 18
        signals.append("Hostname contains unusual nesting / many subdomain labels")
    elif len(labels) >= 4:
        risk += 10
        signals.append("Hostname has more subdomain labels than a typical site")

    hyphen_count = host.count("-")
    if hyphen_count >= 3:
        risk += 12
        signals.append("Hostname contains many hyphens, a common phishing pattern")

    token_hits = [token for token in SUSPICIOUS_TOKENS if token in haystack]
    well_known = is_well_known_host(host)
    if token_hits and not well_known:
        risk += min(40, 12 * len(token_hits))
        shown = ", ".join(token_hits[:4])
        signals.append(f"Login or verification terms appear in the URL ({shown})")

    url_len = len(normalized_url)
    if not well_known:
        if url_len > 120:
            risk += 15
            signals.append("URL is significantly longer than a typical website address")
        elif url_len > 75:
            risk += 8
            signals.append("URL is longer than usual")

    tld = labels[-1] if labels else ""
    if tld in SUSPICIOUS_TLDS:
        risk += 15
        signals.append(f"Top-level domain .{tld} is frequently abused in phishing kits")

    if parts.port and parts.port not in {80, 443}:
        risk += 10
        signals.append(f"URL uses a non-standard port ({parts.port})")

    percent_count = normalized_url.count("%")
    if percent_count >= 4 and not well_known:
        risk += 10
        signals.append("URL contains heavy percent-encoding that can hide the path")

    if parts.scheme == "http":
        risk += 5
        signals.append("Connection is not HTTPS — treated only as a weak signal")

    host_entropy = _entropy(host.replace(".", ""))
    if host_entropy >= 3.8 and len(host) >= 18:
        risk += 10
        signals.append("Hostname character distribution looks unusually random")

    if re.search(r"(paypal|apple|google|microsoft|amazon|facebook|instagram|whatsapp|bank)", host) and tld not in {
        "com",
        "net",
        "org",
        "gov",
        "edu",
        "co",
    }:
        risk += 18
        signals.append("Brand-like token appears on an unrelated registered domain")

    risk = max(0, min(100, risk))

    if risk >= 55:
        label: str = "phishing"
        confidence = min(100, 55 + risk // 2)
    elif risk >= 35:
        label = "suspicious"
        confidence = min(100, 45 + risk // 2)
    else:
        label = "benign"
        confidence = max(0, min(100, 100 - int(risk * 1.2)))
        if not signals:
            signals.append("No strong lexical phishing or malware patterns in the URL string")

    return HeuristicResult(
        label=label,  # type: ignore[arg-type]
        confidence=confidence,
        risk_score=risk,
        signals=signals,
    )
