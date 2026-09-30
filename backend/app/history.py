"""Scan history in SQL Server: the first stage of the pipeline and its archive.

A URL that has been scanned before is answered from here, so a repeat visit costs
no URLhaus token and no browser fetch. The table also carries the counters the API
needs to warn a caller that a site has been seen before, and how it went.

Verdict bands, applied to the page model's phishing score:

    score < 0.4          safe
    0.4 <= score <= 0.6  potentially_unsafe
    score > 0.6          malicious

A URLhaus match is malicious regardless of score, and a degraded result is
`unknown` so a failed scan never counts as a clean bill of health.

`Sites.EffectiveVerdict` is a computed column in the database, not a value written
from here: a site that was ever malicious reports `potentially_unsafe` even after a
later clean scan, and no caller can forget to apply that.
"""

from __future__ import annotations

import hashlib
import json
import logging
from contextlib import contextmanager
from datetime import datetime, timedelta, timezone
from typing import Any, Optional

from .config import settings
from .models import AnalyzeResponse

logger = logging.getLogger("phisang")

MALICIOUS = "malicious"
SAFE = "safe"
POTENTIALLY_UNSAFE = "potentially_unsafe"
UNKNOWN = "unknown"

UNSAFE_BAND_LOW = 0.4
UNSAFE_BAND_HIGH = 0.6

_pool: Any = None
_unavailable_logged = False


def _now() -> datetime:
    return datetime.now(timezone.utc).replace(tzinfo=None)


def url_hash(normalized_url: str) -> str:
    return hashlib.sha256(normalized_url.encode("utf-8", "ignore")).hexdigest()


def enabled() -> bool:
    return bool(settings.db_enabled and settings.db_host)


@contextmanager
def _cursor():
    """Yield a cursor, or None when history is off or the server is unreachable.

    Callers must treat None as "no history available" and carry on: a database
    outage degrades Phisang to its old stateless behaviour rather than breaking it.
    """
    global _pool, _unavailable_logged
    if not enabled():
        yield None
        return
    try:
        import pymssql
    except ImportError:
        if not _unavailable_logged:
            logger.warning("scan history disabled: pymssql is not installed")
            _unavailable_logged = True
        yield None
        return

    conn = None
    yielded = False
    try:
        conn = pymssql.connect(
            server=settings.db_host, port=str(settings.db_port),
            user=settings.db_user, password=settings.db_password,
            database=settings.db_name, timeout=settings.db_timeout_seconds,
            login_timeout=settings.db_timeout_seconds, autocommit=False,
        )
        cursor = conn.cursor(as_dict=True)
        yielded = True
        yield cursor
        conn.commit()
        _unavailable_logged = False
    except Exception as exc:
        if conn is not None:
            try:
                conn.rollback()
            except Exception:
                pass
        if not _unavailable_logged:
            logger.warning("scan history unavailable: %s", exc)
            _unavailable_logged = True
        if not yielded:
            yield None
    finally:
        if conn is not None:
            try:
                conn.close()
            except Exception:
                pass


def ready() -> bool:
    if not enabled():
        return False
    with _cursor() as cur:
        if cur is None:
            return False
        cur.execute("SELECT 1 AS ok")
        return cur.fetchone() is not None


def reusable(row: dict) -> bool:
    """Incomplete scans are audit events, never reusable safety decisions."""
    raw = row.get("RawResponseJson")
    if raw:
        try:
            result = AnalyzeResponse.model_validate_json(raw)
        except ValueError:
            return False
        return (result.classification != "unavailable" and not result.error_code
                and (result.page is None or result.page.status != "unavailable"))
    return (row.get("LastClassification") in {"benign", "phishing", "malware"}
            and row.get("LastVerdict") != "unknown"
            and row.get("LastDecisionStage") != "error")


def verdict_for(result: AnalyzeResponse) -> str:
    """Map a pipeline result onto the four verdict labels."""
    if result.classification == "malware":
        return MALICIOUS
    if result.classification == "unavailable":
        return UNKNOWN
    page = result.page
    score = page.phishing_score if page is not None else None
    if score is None:
        # No page score: fall back to the classification the pipeline settled on.
        return MALICIOUS if result.classification == "phishing" else SAFE
    if score > UNSAFE_BAND_HIGH:
        return MALICIOUS
    if score >= UNSAFE_BAND_LOW:
        return POTENTIALLY_UNSAFE
    return SAFE


def lookup(normalized_url: str) -> Optional[dict]:
    """Prior record for this URL, or None when it has never been scanned."""
    with _cursor() as cur:
        if cur is None:
            return None
        cur.execute(
            """
            SELECT sites.*, fresh.RawResponseJson
            FROM dbo.Sites AS sites
            OUTER APPLY (
                SELECT TOP 1 scans.RawResponseJson
                FROM dbo.Scans AS scans
                WHERE scans.SiteId = sites.SiteId AND scans.ServedFromHistory = 0
                ORDER BY scans.ScannedAt DESC, scans.ScanRef DESC
            ) AS fresh
            WHERE sites.UrlHash = %s
            """,
            (url_hash(normalized_url),),
        )
        return cur.fetchone()


def record(result: AnalyzeResponse, *, client: str = "web", host: str = "",
           duration_ms: Optional[int] = None, is_rescan: bool = False,
           served_from_history: bool = False) -> None:
    """Append the scan to the log and roll the site's counters forward."""
    # A cache read is not a new observation. Never overwrite the last actual
    # score, timestamp, classification or counters with a reduced cached response.
    if served_from_history or result.served_from_history:
        return
    verdict = verdict_for(result)
    page = result.page
    heuristic = result.heuristic
    intel = result.threat_intel
    signals = page.page_signals if page is not None else None

    with _cursor() as cur:
        if cur is None:
            return
        digest = url_hash(result.normalized_url)
        cur.execute("SELECT SiteId FROM dbo.Sites WHERE UrlHash = %s", (digest,))
        row = cur.fetchone()
        if row is None:
            cur.execute(
                """
                INSERT INTO dbo.Sites (UrlHash, NormalizedUrl, Host, FirstScannedAt, LastScannedAt)
                OUTPUT inserted.SiteId
                VALUES (%s, %s, %s, %s, %s)
                """,
                (digest, result.normalized_url[:2048], host[:255] or None, _now(), _now()),
            )
            site_id = cur.fetchone()["SiteId"]
        else:
            site_id = row["SiteId"]

        column = {MALICIOUS: "MaliciousCount", SAFE: "SafeCount",
                  POTENTIALLY_UNSAFE: "PotentiallyUnsafeCount"}.get(verdict, "UnknownCount")
        cur.execute(
            f"""
            UPDATE dbo.Sites
            SET LastScannedAt = %s, ScanCount = ScanCount + 1, {column} = {column} + 1,
                EverMalicious = CASE WHEN %s = 1 THEN 1 ELSE EverMalicious END,
                LastVerdict = %s, LastScore = %s, LastDecisionStage = %s, LastScanRef = %s,
                LastClassification = %s
            WHERE SiteId = %s
            """,
            (_now(), 1 if verdict == MALICIOUS else 0, verdict,
             page.phishing_score if page is not None else None,
             result.decision_stage, result.scan_id, result.classification, site_id),
        )

        cur.execute(
            """
            INSERT INTO dbo.Scans (
                ScanRef, SiteId, ScannedAt, Client, IsRescan, ServedFromHistory,
                Verdict, Classification, Confidence, DecisionStage, ErrorCode,
                PolicyVersion, DurationMs,
                ThreatIntelMatched, ThreatIntelSource, ThreatIntelType, ThreatIntelId, ThreatIntelStatus,
                HeuristicLabel, HeuristicConfidence, HeuristicRiskScore,
                PhishingScore, PageLabel, PageHttpStatus, PageFinalUrl, PageTitle,
                PageForms, PagePasswordInputs, PageInputs, PageIframes,
                PageModelName, PageModelAccuracy, SignalsJson, RawResponseJson)
            VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s,
                    %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s)
            """,
            (
                result.scan_id, site_id, _now(), client, 1 if is_rescan else 0,
                1 if served_from_history else 0,
                verdict, result.classification, result.confidence, result.decision_stage,
                result.error_code, result.policy_version, duration_ms,
                None if intel is None else (1 if intel.matched else 0),
                None if intel is None else intel.source,
                None if intel is None else intel.threat_type,
                None if intel is None else intel.id,
                None if intel is None else intel.feed_status,
                None if heuristic is None else heuristic.label,
                None if heuristic is None else heuristic.confidence,
                None if heuristic is None else heuristic.risk_score,
                None if page is None else page.phishing_score,
                None if page is None else page.label,
                None if page is None else page.http_status,
                None if page is None else (page.final_url or "")[:2048] or None,
                None if page is None else (page.page_title or "")[:400] or None,
                None if signals is None else signals.forms,
                None if signals is None else signals.password_inputs,
                None if signals is None else signals.inputs,
                None if signals is None else signals.iframes,
                None if page is None else page.model_name,
                None if page is None else page.model_accuracy,
                json.dumps(result.signals, ensure_ascii=False),
                result.model_dump_json(),
            ),
        )


# --- URLhaus response cache -------------------------------------------------
# Kept in SQL so a repeat lookup spends no rate-limit token. Hits and misses get
# different lifetimes: a listing stays true for a while, but "not listed" is only
# true until the next feed update, so it expires on the short TTL.

def cache_get(cache_key: str) -> Optional[dict]:
    with _cursor() as cur:
        if cur is None:
            return None
        cur.execute(
            """
            UPDATE dbo.UrlhausCache
            SET HitCount = HitCount + 1, LastHitAt = %s
            OUTPUT inserted.PayloadJson
            WHERE CacheKeyHash = %s AND ExpiresAt > %s
            """,
            (_now(), url_hash(cache_key), _now()),
        )
        row = cur.fetchone()
        return json.loads(row["PayloadJson"]) if row else None


def cache_set(cache_key: str, payload: dict, *, matched: Optional[bool] = None) -> None:
    kind = "hostraw" if ":hostraw:" in cache_key else "url"
    ttl = settings.db_urlhaus_match_ttl_seconds if matched else settings.cache_ttl_seconds
    expires = _now() + timedelta(seconds=ttl)
    with _cursor() as cur:
        if cur is None:
            return
        cur.execute(
            """
            UPDATE dbo.UrlhausCache
            SET CacheKey = %s, KeyKind = %s, Matched = %s, PayloadJson = %s,
                FetchedAt = %s, ExpiresAt = %s
            WHERE CacheKeyHash = %s
            """,
            (cache_key[:2100], kind, None if matched is None else (1 if matched else 0),
             json.dumps(payload, ensure_ascii=False), _now(), expires, url_hash(cache_key)),
        )
        if cur.rowcount == 0:
            cur.execute(
                """
                INSERT INTO dbo.UrlhausCache
                    (CacheKeyHash, CacheKey, KeyKind, Matched, PayloadJson, FetchedAt, ExpiresAt)
                VALUES (%s, %s, %s, %s, %s, %s, %s)
                """,
                (url_hash(cache_key), cache_key[:2100], kind,
                 None if matched is None else (1 if matched else 0),
                 json.dumps(payload, ensure_ascii=False), _now(), expires),
            )
