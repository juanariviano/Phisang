"""Maps a 0-1 maliciousness score onto the four risk levels the clients show.

Each band includes its lower bound: 0.4 is already POTENTIALLY UNSAFE, 0.6 is
MALICIOUS and 0.8 is High Risk.
"""

from __future__ import annotations

from typing import Literal

RiskLevel = Literal["SAFE", "POTENTIALLY UNSAFE", "MALICIOUS", "High Risk"]

# (lower bound, level), highest band first.
RISK_BANDS: list[tuple[float, RiskLevel]] = [
    (0.8, "High Risk"),
    (0.6, "MALICIOUS"),
    (0.4, "POTENTIALLY UNSAFE"),
    (0.0, "SAFE"),
]

# The page model calls a page phishing from here on, so its label and its risk
# level never disagree.
MALICIOUS_FROM = 0.6

# A plain-HTTP address can be read and rewritten in transit, so it adds to
# whatever the gates found instead of replacing it. The sum is capped, so the
# penalty can never take a score past the top of the scale (100 as a percentage).
HTTP_RISK_PENALTY = 0.1


def risk_level(score: float) -> RiskLevel:
    if not 0.0 <= score <= 1.0:
        raise ValueError(f"risk score must be within [0, 1], got {score}")
    return next(level for bound, level in RISK_BANDS if score >= bound)


def with_http_penalty(score: float, scheme: str) -> float:
    """Raise a plain-HTTP address's risk score, never above 1.0."""
    if scheme != "http":
        return score
    return min(1.0, round(score + HTTP_RISK_PENALTY, 4))
