from __future__ import annotations

import asyncio
import logging
import time
from datetime import datetime, timezone
from urllib.parse import urlsplit

from . import evidence, heuristics, history, page_stage, registration, urlhaus
from .config import settings
from .inventory import new_scan_id, remember
from .models import AnalyzeResponse, PageResult, PriorScan, ThreatIntel
from .normalize import UrlError, hostname_of, normalize_url, redact_url
from .page_stage import PageStageError
from .reputation import is_popular_host, is_well_known_host
from .risk import MALICIOUS_FROM, risk_level
from .scan_progress import report, step
from .url_guard import UrlRejected, check_static
from .urlhaus import UrlhausError

logger = logging.getLogger("phisang")

POLICY_VERSION = "poc-flowchart-v2.4"

# Retain the existing policy's lower confidence for an uncorroborated model call.
UNCORROBORATED_BENIGN_CONFIDENCE = 50

LIMITATIONS = [
    "Some scans can be decided without fetching the destination page",
    "A markup-model phishing call blocks only when the URL or a password field backs it up",
    "URL checks use hand-written rules, not a trained model",
    "Automated checks can miss threats or flag legitimate pages",
    "Domain registration details are context, not proof of safety",
    "A benign / not-listed result is not a guarantee of safety",
]


def _format_when(value) -> str | None:
    return value.strftime("%Y-%m-%d %H:%M UTC") if value is not None else None


VERDICT_WORDS = {
    "malicious": "malicious",
    "safe": "safe",
    "potentially_unsafe": "potentially unsafe",
    "unknown": "inconclusive",
}


def _prior_from_row(row: dict) -> PriorScan:
    """Turn the stored counters into the warning shown before a rescan."""
    verdict = row["EffectiveVerdict"]
    when = _format_when(row["LastScannedAt"])
    parts = [f"This address was already scanned {row['ScanCount']}x, most recently on "
             f"{when}, and was rated {VERDICT_WORDS.get(verdict, verdict)}."]
    tally = []
    for count, word in ((row["MaliciousCount"], "malicious"),
                        (row["SafeCount"], "safe"),
                        (row["PotentiallyUnsafeCount"], "potentially unsafe"),
                        (row["UnknownCount"], "inconclusive")):
        if count:
            tally.append(f"{count}x {word}")
    if tally:
        parts.append("Across those scans: " + ", ".join(tally) + ".")
    # The sticky rule is the whole reason a clean site can still read as unsafe,
    # so say why rather than leaving the label unexplained.
    if row["EverMalicious"] and row["LastVerdict"] == "safe":
        parts.append("An earlier scan found it malicious, so it stays potentially unsafe "
                     "even though the latest scan was clean.")
    parts.append("Rescan to check it again.")
    return PriorScan(
        verdict=verdict,
        last_scanned_at=when,
        first_scanned_at=_format_when(row["FirstScannedAt"]),
        scan_count=row["ScanCount"],
        malicious_count=row["MaliciousCount"],
        safe_count=row["SafeCount"],
        potentially_unsafe_count=row["PotentiallyUnsafeCount"],
        unknown_count=row["UnknownCount"],
        ever_malicious=bool(row["EverMalicious"]),
        last_score=row["LastScore"],
        last_decision_stage=row["LastDecisionStage"],
        message=" ".join(parts),
    )


_HISTORY_LEVELS = {
    history.SAFE: "SAFE",
    history.POTENTIALLY_UNSAFE: "POTENTIALLY UNSAFE",
    history.MALICIOUS: "MALICIOUS",
}


def _from_history(scan_id: str, normalized: str, row: dict, prior: PriorScan) -> AnalyzeResponse:
    """Answer from the archive: no URLhaus token spent, no page fetched."""
    verdict = row["EffectiveVerdict"]
    saved = None
    if row.get("RawResponseJson"):
        try:
            saved = AnalyzeResponse.model_validate_json(row["RawResponseJson"])
        except ValueError:
            logger.warning("Invalid archived response; using stored verdict for %s", scan_id)
    if saved is not None:
        # Recover the last actual verdict even if older cache reads corrupted
        # the Sites summary. Preserve the database's historical warning rule.
        verdict = history.verdict_for(saved)
        if verdict == "safe" and row.get("EverMalicious"):
            verdict = "potentially_unsafe"
    classification = (saved.classification if saved else
                      "malware" if verdict == "malicious" and row.get("LastClassification") == "malware" else
                      "phishing" if verdict == "malicious" else
                      "benign" if verdict == "safe" else "unavailable")
    score = saved.risk_score if saved else row.get("LastScore")
    result = _base(
        scan_id=scan_id,
        normalized_url=normalized,
        classification=classification,
        confidence=saved.confidence if saved else 0,
        risk_score=score,
        level=_HISTORY_LEVELS.get(verdict),
        page_result=saved.page if saved else None,
        heuristic=saved.heuristic if saved else None,
        error_code=saved.error_code if saved else None,
        decision_stage="history",
        threat_intel=saved.threat_intel if saved else ThreatIntel(matched=False, source="PhisangDB", feed_status="skipped"),
        signals=(list(saved.signals) if saved else []) + [prior.message,
                 "Served from the scan archive; no URLhaus token spent and no page fetched",
                 "The verdict is based on the last scan's result and the site's history"],
        prior=prior,
        served_from_history=True,
        verdict=verdict,
    )
    result.domain_info = saved.domain_info if saved else None
    result.scanned_at = saved.scanned_at if saved else _format_when(row.get("LastScannedAt"))
    result.evidence_scan_id = (saved.evidence_scan_id or saved.scan_id) if saved else row.get("LastScanRef")
    return result


def _base(
    *,
    scan_id: str,
    normalized_url: str,
    classification: str,
    confidence: int,
    decision_stage: str,
    threat_intel: ThreatIntel,
    signals: list[str],
    risk_score: float | None = None,
    level: str | None = None,
    heuristic=None,
    page_result=None,
    error_code: str | None = None,
    prior=None,
    served_from_history: bool = False,
    verdict: str | None = None,
) -> AnalyzeResponse:
    result = AnalyzeResponse(
        scan_id=scan_id,
        normalized_url=normalized_url,
        classification=classification,  # type: ignore[arg-type]
        confidence=confidence,
        risk_score=None if risk_score is None else round(risk_score, 4),
        risk_level=level if risk_score is None else risk_level(risk_score),
        decision_stage=decision_stage,  # type: ignore[arg-type]
        threat_intel=threat_intel,
        heuristic=heuristic,
        page=page_result,
        prior=prior,
        served_from_history=served_from_history,
        verdict=verdict,  # type: ignore[arg-type]
        signals=signals,
        limitations=list(LIMITATIONS),
        policy_version=POLICY_VERSION,
        error_code=error_code,
    )
    remember(result)
    return result


def _unavailable(
    *,
    scan_id: str,
    normalized_url: str,
    error_code: str,
    threat_intel: ThreatIntel,
    signals: list[str],
    heuristic=None,
) -> AnalyzeResponse:
    return _base(
        scan_id=scan_id,
        normalized_url=normalized_url,
        classification="unavailable",
        confidence=0,
        decision_stage="error",
        threat_intel=threat_intel,
        signals=signals,
        heuristic=heuristic,
        page_result=PageResult(status="unavailable") if error_code == "page_unavailable" else None,
        error_code=error_code,
    )


async def analyze(raw_url: str, client: str, rescan: bool = False) -> AnalyzeResponse:
    started = time.monotonic()
    scan_id = new_scan_id()
    normalized = normalize_url(raw_url)

    # Judged before any gate runs: an address aimed at the local machine or a
    # private network is never something to call benign, and the heuristic gate
    # would otherwise clear some of them on lexical grounds alone. Kept to the
    # DNS-free checks so that dead hostnames still reach the URLhaus lookup.
    try:
        check_static(normalized)
    except UrlRejected as exc:
        raise UrlError("unsupported_target", str(exc)) from None

    logger.info("analyze start scan_id=%s client=%s rescan=%s url=%s",
                scan_id, client, rescan, redact_url(normalized))

    # Stage 0. A URL somebody already scanned is answered from the archive, which
    # is the only stage that costs neither a URLhaus token nor a page fetch. The
    # caller can request a rescan; incomplete previous scans retry automatically.
    async with step("history", "Checking saved scans", "Looking for an earlier result for this address."):
        prior_row = await asyncio.to_thread(history.lookup, normalized)
    prior = _prior_from_row(prior_row) if prior_row else None
    if prior_row is not None and not rescan and history.reusable(prior_row):
        # Returning an existing result is not another scan: no database write.
        await report("result", "Loading saved result", "This address already has a completed scan.")
        return _from_history(scan_id, normalized, prior_row, prior)

    result, domain_info = await asyncio.gather(
        _analyze_fresh(scan_id, normalized), _registration_with_progress(hostname_of(normalized)))
    # One place records every fresh scan, so no return path can quietly skip it.
    result.prior = prior
    result.domain_info = domain_info
    result.evidence_scan_id = scan_id
    result.scanned_at = datetime.now(timezone.utc).isoformat()
    result.verdict = history.verdict_for(result)  # type: ignore[assignment]
    async with step("result", "Preparing your result", "Putting the scan findings together."):
        await asyncio.to_thread(history.record, result, client=client, host=hostname_of(normalized),
                       duration_ms=int((time.monotonic() - started) * 1000),
                       is_rescan=prior_row is not None, served_from_history=False)
        if result.page:
            await asyncio.to_thread(evidence.persist_preview, scan_id, result.page._screenshot)
            result.page._screenshot = None
    return result


async def _registration_with_progress(host):
    await report("domain", "Looking up domain details", "Checking public registration information.")
    result = await registration.lookup(host)
    await report("domain", "Domain registration lookup", status="complete" if result.status == "ok" else "unavailable")
    return result


async def _analyze_fresh(scan_id: str, normalized: str) -> AnalyzeResponse:
    """URLhaus, then the lexical gate, then the page model."""
    try:
        async with step("threats", "Checking known threats", "Checking the address against the threat database."):
            intel = await urlhaus.lookup(normalized)
    except UrlhausError as exc:
        logger.warning("urlhaus failed scan_id=%s err=%s", scan_id, exc)
        return _unavailable(
            scan_id=scan_id,
            normalized_url=normalized,
            error_code="threat_intel_unavailable",
            threat_intel=ThreatIntel(matched=False, source="URLhaus", feed_status="unavailable"),
            signals=[
                "Threat-intelligence lookup failed or timed out",
                "Result is degraded — not a clean or benign verdict",
            ],
        )

    if intel.matched:
        match_kind = intel.match_kind or "url"
        identity = f"id {intel.id}" if intel.id else "listed indicator"
        signals = [
            f"{'Exact URL' if match_kind == 'url' else 'Hostname'} match against the URLhaus snapshot ({identity})",
        ]
        if intel.threat_type:
            signals.append(f"URLhaus threat type: {intel.threat_type}")
        return _base(
            scan_id=scan_id,
            normalized_url=normalized,
            classification="malware",
            confidence=97,
            risk_score=1.0,
            decision_stage="urlhaus",
            threat_intel=intel,
            signals=signals,
        )

    async with step("address", "Reviewing the address", "Looking for suspicious patterns in the website address."):
        heuristic = heuristics.score(normalized)

    # A clean URL string is only an absence of lexical red flags, not evidence the
    # page is safe: an unknown short domain such as zkic.com scores risk 0 and so
    # confidence 100. Only well-known or top-ranked hosts may skip the page fetch;
    # everything else has its markup read.
    host = urlsplit(normalized).hostname or ""
    reputation = ("well-known domain list" if is_well_known_host(host)
                  else "Tranco top-domain ranking" if is_popular_host(host) else None)
    if (heuristic.label == "benign"
            and heuristic.confidence > settings.heuristic_benign_threshold
            and reputation):
        return _base(
            scan_id=scan_id,
            normalized_url=normalized,
            classification="benign",
            confidence=heuristic.confidence,
            risk_score=heuristic.risk_score / 100,
            decision_stage="heuristic",
            threat_intel=intel,
            heuristic=heuristic,
            page_result=PageResult(status="skipped"),
            signals=heuristic.signals
            + [
                "Not listed in URLhaus",
                f"Host is on the {reputation}",
                "The URL rules found no strong warning signs on this known domain",
                "The destination page was not fetched during this scan",
            ],
        )

    # Inconclusive on the URL alone, so the page itself gets fetched and read.
    try:
        async with step("page", "Inspecting the website", "Opening the page on our server."):
            page_result = await page_stage.classify(normalized)
    except PageStageError as exc:
        logger.warning("page stage failed scan_id=%s err=%s", scan_id, exc)
        return _unavailable(
            scan_id=scan_id,
            normalized_url=normalized,
            error_code="page_unavailable",
            threat_intel=intel,
            heuristic=heuristic,
            signals=heuristic.signals
            + [str(exc), "Result is degraded — not a clean or benign verdict"],
        )

    signals = list(heuristic.signals)
    signals.append("URL checks were inconclusive, so the destination was fetched server-side")
    signals.append(f"Markup classifier read the fetched page as {page_result.label}")

    classification = page_result.label or "unavailable"
    confidence = page_result.confidence or 0
    risk_score = page_result.phishing_score
    # A benign-looking page must not clear a URL that is itself a strong phishing
    # shape (e.g. crocs-com.ru): kits often serve a clean landing page first.
    if classification == "benign" and heuristic.label == "phishing":
        classification = "phishing"
        confidence = heuristic.confidence
        # Blocked on the URL's word, so it must read as at least MALICIOUS.
        risk_score = max(risk_score or 0.0, heuristic.risk_score / 100, MALICIOUS_FROM)
        signals.append("The URL itself matches strong phishing patterns, which outweighs "
                       "the benign page reading")
    # The reverse needs corroboration: a phishing call stands only when the URL
    # is itself doubtful or the page asks for a password.
    elif classification == "phishing" and heuristic.label == "benign":
        password_inputs = (page_result.page_signals.password_inputs
                           if page_result.page_signals else 0)
        if not password_inputs:
            classification = "benign"
            confidence = UNCORROBORATED_BENIGN_CONFIDENCE
            signals.append(
                f"Warning: the markup classifier scored this page "
                f"{page_result.phishing_score:.2f} phishing, but the URL looks clean and the "
                "page asks for no password, so that call alone was not enough to block — "
                "stay careful before entering any details")
    return _base(
        scan_id=scan_id,
        normalized_url=normalized,
        classification=classification,
        confidence=confidence,
        risk_score=risk_score,
        decision_stage="page",
        threat_intel=intel,
        heuristic=heuristic,
        page_result=page_result,
        signals=signals,
    )


def map_url_error(exc: UrlError) -> tuple[int, str, str]:
    status = {
        "invalid_url": 400,
        "unsupported_scheme": 400,
        "unsupported_target": 400,
        "input_too_large": 413,
    }.get(exc.code, 400)
    return status, exc.code, exc.message
