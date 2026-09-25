"""SSRF guard for user-submitted URLs.

The API fetches whatever URL a caller supplies, so every address this module
approves must be a public internet host. Rejections carry a message that is
safe to return to the caller verbatim.
"""

import asyncio
import ipaddress
import socket
from urllib.parse import urlsplit

ALLOWED_SCHEMES = frozenset({"http", "https"})
ALLOWED_PORTS = frozenset({80, 443, 8080, 8443})
MAX_URL_LENGTH = 2048

# Python's ipaddress flags most non-routable space, but not all of it. Shared
# address space (100.64/10) carries Alibaba Cloud's metadata service at
# 100.100.100.200, and the rest are belt-and-braces entries for ranges whose
# classification has shifted between Python releases.
EXTRA_BLOCKED_NETWORKS = tuple(ipaddress.ip_network(cidr) for cidr in (
    "100.64.0.0/10",     # shared address space / CGNAT, Alibaba metadata
    "192.0.0.0/24",      # IETF protocol assignments, Oracle Cloud metadata
    "192.0.2.0/24",      # TEST-NET-1
    "198.18.0.0/15",     # benchmarking
    "198.51.100.0/24",   # TEST-NET-2
    "203.0.113.0/24",    # TEST-NET-3
    "240.0.0.0/4",       # reserved former class E
    "::/128",            # unspecified
    "2001:db8::/32",     # documentation
))


class UrlRejected(Exception):
    """A URL that must not be fetched. The message is safe to show callers."""


def classify_ip(raw) -> str:
    """Return "" when the address is a public internet host, else the reason."""
    try:
        address = ipaddress.ip_address(raw)
    except ValueError:
        return "unparseable IP address"

    # ::ffff:127.0.0.1 must be judged as 127.0.0.1, not as an opaque v6 address.
    mapped = getattr(address, "ipv4_mapped", None)
    if mapped is not None:
        address = mapped

    for flag, reason in (("is_unspecified", "unspecified address"),
                         ("is_loopback", "loopback address"),
                         ("is_link_local", "link-local address"),
                         ("is_multicast", "multicast address"),
                         ("is_private", "private address"),
                         ("is_reserved", "reserved address")):
        if getattr(address, flag):
            return reason

    for network in EXTRA_BLOCKED_NETWORKS:
        if address.version == network.version and address in network:
            return f"non-routable range {network}"
    return ""


def legacy_ipv4(host: str) -> str:
    """Read host the way inet_aton does, or "" if it is not an IPv4 literal.

    getaddrinfo and inet_aton disagree on legacy forms: "0177.0.0.1" resolves to
    the public 177.0.0.1 through the former but to loopback 127.0.0.1 through the
    latter. Whichever reading a downstream client picks must be safe, so both are
    checked.
    """
    try:
        return socket.inet_ntoa(socket.inet_aton(host))
    except OSError:
        return ""


def check_static(url: str) -> tuple:
    """Validate everything decidable without DNS. Returns (host, port)."""
    if not url or len(url) > MAX_URL_LENGTH:
        raise UrlRejected(f"URL must be 1-{MAX_URL_LENGTH} characters")

    parts = urlsplit(url.strip())
    if parts.scheme.lower() not in ALLOWED_SCHEMES:
        raise UrlRejected("only http and https URLs are supported")
    if parts.username or parts.password:
        raise UrlRejected("URLs with embedded credentials are not accepted")

    host = parts.hostname
    if not host:
        raise UrlRejected("URL has no host")

    try:
        port = parts.port
    except ValueError:
        raise UrlRejected("invalid port") from None
    port = port or (443 if parts.scheme.lower() == "https" else 80)
    if port not in ALLOWED_PORTS:
        raise UrlRejected(f"port {port} is not allowed")

    # A bare IP in the URL skips DNS entirely, so judge it now.
    try:
        ipaddress.ip_address(host)
    except ValueError:
        pass
    else:
        reason = classify_ip(host)
        if reason:
            raise UrlRejected(f"target resolves to a {reason}")

    legacy = legacy_ipv4(host)
    if legacy:
        reason = classify_ip(legacy)
        if reason:
            raise UrlRejected(f"target resolves to a {reason}")
    return host, port


async def resolve_public(host: str, port: int) -> list:
    """Resolve host and require every answer to be a public address."""
    loop = asyncio.get_running_loop()
    try:
        infos = await loop.getaddrinfo(host, port, type=socket.SOCK_STREAM)
    except socket.gaierror:
        raise UrlRejected("host could not be resolved") from None
    if not infos:
        raise UrlRejected("host could not be resolved")

    addresses = []
    for info in infos:
        ip = info[4][0]
        reason = classify_ip(ip)
        # One bad answer condemns the host: a rebinding attacker only needs the
        # browser to pick that record.
        if reason:
            raise UrlRejected(f"target resolves to a {reason}")
        addresses.append(ip)
    return addresses


async def validate(url: str) -> list:
    """Full pre-flight check. Raises UrlRejected, or returns resolved IPs."""
    host, port = check_static(url)
    return await resolve_public(host, port)
