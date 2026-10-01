"""False-positive reports: a user telling us an unsafe verdict looks wrong.

Reports are kept for review only. Recording one never changes the scan's verdict,
the site's counters, or what a later scan decides — a client that could talk its
own result down would be a way to get a phishing page waved through.
"""

from __future__ import annotations

import logging
from typing import Optional

from . import history
from .models import AnalyzeResponse

logger = logging.getLogger("phisang")

MAX_REASON_CHARS = 1000


class ReportError(RuntimeError):
    """A report that could not be stored, with the status the API should answer."""

    def __init__(self, status: int, message: str) -> None:
        super().__init__(message)
        self.status = status


def enabled() -> bool:
    return history.enabled()


def save(result: AnalyzeResponse, *, client: str = "web", reason: Optional[str] = None) -> int:
    """Append one report for this scan and return its ID."""
    if not enabled():
        raise ReportError(503, "Reports are unavailable: the scan database is not configured.")
    digest = history.url_hash(result.normalized_url)
    scan_ref = result.evidence_scan_id or result.scan_id
    # history._cursor() turns a SQL failure into a warning rather than an
    # exception, so success is proven by the ID coming back, not by not raising.
    report_id = None
    with history._cursor() as cur:
        if cur is not None:
            cur.execute("SELECT SiteId FROM dbo.Sites WHERE UrlHash = %s", (digest,))
            site = cur.fetchone()
            cur.execute(
                """
                INSERT INTO dbo.FalsePositiveReports (
                    ScanRef, SiteId, UrlHash, NormalizedUrl, Client,
                    ReportedVerdict, ReportedClassification, ReportedRiskScore, Reason)
                OUTPUT inserted.ReportId
                VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s)
                """,
                (scan_ref[:32], None if site is None else site["SiteId"], digest,
                 result.normalized_url[:2048], client[:20], result.verdict,
                 result.classification, result.risk_score,
                 (reason or "").strip()[:MAX_REASON_CHARS] or None),
            )
            row = cur.fetchone()
            report_id = None if row is None else row["ReportId"]
    if report_id is None:
        raise ReportError(503, "The report could not be saved. Please try again later.")
    logger.info("false positive reported report_id=%s scan_ref=%s client=%s verdict=%s",
                report_id, scan_ref, client, result.verdict)
    return report_id
