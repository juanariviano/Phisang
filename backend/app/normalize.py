from __future__ import annotations

from urllib.parse import urlsplit, urlunsplit

import idna

MAX_URL_LENGTH = 4096
SUPPORTED_SCHEMES = {"http", "https"}


class UrlError(ValueError):
    def __init__(self, code: str, message: str) -> None:
        super().__init__(message)
        self.code = code
        self.message = message


def redact_url(url: str) -> str:
    """Strip credentials and query string for logs."""
    try:
        parts = urlsplit(url)
    except ValueError:
        return "<unparseable>"
    host = parts.hostname or ""
    port = parts.port
    netloc = host
    if port:
        netloc = f"{host}:{port}"
    path = parts.path or "/"
    return urlunsplit((parts.scheme, netloc, path, "", ""))


def normalize_url(raw: str) -> str:
    if raw is None:
        raise UrlError("invalid_url", "URL is empty")
    text = raw.strip()
    if not text:
        raise UrlError("invalid_url", "URL is empty")
    if len(text) > MAX_URL_LENGTH:
        raise UrlError("input_too_large", f"URL exceeds {MAX_URL_LENGTH} characters")

    parts = urlsplit(text)
    if not parts.scheme:
        parts = urlsplit(f"https://{text}")

    scheme = parts.scheme.lower()
    if scheme not in SUPPORTED_SCHEMES:
        raise UrlError("unsupported_scheme", f"Unsupported scheme: {scheme}")

    hostname = parts.hostname
    if not hostname:
        raise UrlError("invalid_url", "URL has no hostname")

    hostname = hostname.lower().rstrip(".")
    try:
        host = idna.encode(hostname).decode("ascii")
    except idna.IDNAError as exc:
        raise UrlError("invalid_url", "Invalid hostname") from exc

    try:
        port = parts.port
    except ValueError as exc:
        raise UrlError("invalid_url", "Invalid port") from exc
    netloc = host
    if port and not (
        (scheme == "http" and port == 80) or (scheme == "https" and port == 443)
    ):
        netloc = f"{host}:{port}"

    path = parts.path or "/"
    while "//" in path:
        path = path.replace("//", "/")
    if path != "/" and path.endswith("/"):
        path = path.rstrip("/")

    # Drop userinfo; keep query/fragment for exact URLhaus matching.
    return urlunsplit((scheme, netloc, path, parts.query, parts.fragment))


def hostname_of(url: str) -> str:
    host = urlsplit(url).hostname
    if not host:
        raise UrlError("invalid_url", "URL has no hostname")
    return host.lower()
