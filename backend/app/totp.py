"""Time-based one-time passwords (RFC 6238), as Google Authenticator speaks them.

Defaults match what the app assumes when it scans a QR: SHA-1, 6 digits, a new
code every 30 seconds. Nothing here needs a dependency; the algorithm is an HMAC
over a counter.

TOTP is a *second* factor. On its own a six-digit code is a million guesses
against a value that only changes every 30 seconds, so the caller is responsible
for a first factor and for rate limiting. app.admin does both.
"""

from __future__ import annotations

import base64
import hashlib
import hmac
import secrets
import struct
import time
from urllib.parse import quote

DIGITS = 6
PERIOD = 30
# One step either side, so a client clock off by a few seconds still works.
# Wider than this and a stolen code stays usable far too long.
DRIFT_STEPS = 1


def new_secret(length: int = 20) -> str:
    """A fresh base32 secret of the size RFC 4226 recommends (160 bits)."""
    return base64.b32encode(secrets.token_bytes(length)).decode("ascii").rstrip("=")


def _decode(secret: str) -> bytes:
    padded = secret.strip().replace(" ", "").upper()
    padded += "=" * (-len(padded) % 8)
    return base64.b32decode(padded, casefold=True)


def code_at(secret: str, counter: int) -> str:
    digest = hmac.new(_decode(secret), struct.pack(">Q", counter), hashlib.sha1).digest()
    offset = digest[-1] & 0x0F
    truncated = struct.unpack(">I", digest[offset:offset + 4])[0] & 0x7FFF_FFFF
    return str(truncated % (10 ** DIGITS)).zfill(DIGITS)


def verify(secret: str, code: str, *, now: float | None = None) -> int | None:
    """The counter the code belongs to, or None.

    The counter is returned so the caller can refuse a code it has already
    accepted: without that, a code stays replayable for its whole window.
    """
    code = (code or "").strip().replace(" ", "")
    if not secret or not code.isdigit() or len(code) != DIGITS:
        return None
    counter = int((time.time() if now is None else now) // PERIOD)
    for step in range(-DRIFT_STEPS, DRIFT_STEPS + 1):
        # compare_digest, so a wrong code cannot be found one character at a time.
        if hmac.compare_digest(code_at(secret, counter + step), code):
            return counter + step
    return None


def provisioning_uri(secret: str, account: str, issuer: str = "Phisang") -> str:
    """The otpauth:// URI a QR code carries, for enrolling the authenticator."""
    label = quote(f"{issuer}:{account}")
    return (f"otpauth://totp/{label}?secret={secret}&issuer={quote(issuer)}"
            f"&algorithm=SHA1&digits={DIGITS}&period={PERIOD}")
