from __future__ import annotations

import logging
import time
from urllib.parse import urlsplit

from . import heuristics, history, page_stage, urlhaus
from .config import settings
from .inventory import new_scan_id, remember
from .models import AnalyzeResponse, PageResult, PriorScan, ThreatIntel
from .normalize import UrlError, hostname_of, normalize_url, redact_url
from .page_stage import PageStageError
from .reputation import is_popular_host, is_well_known_host
from .risk import MALICIOUS_FROM, risk_level
from .url_guard import UrlRejected, check_static
from .urlhaus import UrlhausError

logger = logging.getLogger("phisang")

POLICY_VERSION = "poc-flowchart-v2.3"

# Reported for a page the markup model flagged with nothing else behind it. The
# v1 model scores ordinary sites (wikipedia.org 0.97, monkeytype.com 0.99) as
# high as real phishing, so its call alone is too weak to block on, and the
# benign verdict that replaces it should not look certain either.
UNCORROBORATED_BENIGN_CONFIDENCE = 50

LIMITATIONS = [
    "The destination is fetched server-side unless the host is a well-known or top-ranked domain",
    "A markup-model phishing call blocks only when the URL or a password field backs it up",
    "Heuristic scoring is a placeholder, not a trained model",
    "The markup classifier is a demo artifact and misreads ordinary login pages",
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


def _from_history(scan_id: str, normalized: str, row: dict, prior: PriorScan) -> AnalyzeResponse:
    """Answer from the archive: no URLhaus token spent, no page fetched."""
    verdict = row["EffectiveVerdict"]
    classification = row["LastClassification"] or (
        "phishing" if verdict == "malicious" else "benign")
    if verdict in {"potentially_unsafe", "unknown"}:
        classification = "unavailable" if verdict == "unknown" else classification
    return _base(
        scan_id=scan_id,
        normalized_url=normalized,
        classification=classification,
        confidence=int(round((row["LastScore"] or 0) * 100)) if row["LastScore"] is not None else 0,
        decision_stage="history",
        threat_intel=ThreatIntel(matched=False, source="PhisangDB", feed_status="skipped"),
        signals=[prior.message,
                 "Served from the scan archive; no URLhaus token spent and no page fetched",
                 "Send rescan=true to run the full pipeline again"],
        prior=prior,
        served_from_history=True,
        verdict=verdict,
    )


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
        risk_level=None if risk_score is None else risk_level(risk_score),
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
    # caller has to ask for a rescan to get past it.
    prior_row = history.lookup(normalized)
    prior = _prior_from_row(prior_row) if prior_row else None
    if prior_row is not None and not rescan:
        result = _from_history(scan_id, normalized, prior_row, prior)
        history.record(result, client=client, host=hostname_of(normalized),
                       duration_ms=int((time.monotonic() - started) * 1000),
                       is_rescan=False, served_from_history=True)
        return result

    result = await _analyze_fresh(scan_id, normalized)
    # One place records every fresh scan, so no return path can quietly skip it.
    result.prior = prior
    result.verdict = history.verdict_for(result)  # type: ignore[assignment]
    history.record(result, client=client, host=hostname_of(normalized),
                   duration_ms=int((time.monotonic() - started) * 1000),
                   is_rescan=prior_row is not None, served_from_history=False)
    return result


async def _analyze_fresh(scan_id: str, normalized: str) -> AnalyzeResponse:
    """URLhaus, then the lexical gate, then the page model."""
    try:
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
                f"Placeholder ML confidence {heuristic.confidence}% exceeded the {settings.heuristic_benign_threshold}% allow threshold",
                "The destination was not fetched — the URL checks were conclusive",
            ],
        )

    # Inconclusive on the URL alone, so the page itself gets fetched and read.
    try:
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
    if page_result.model_accuracy is not None:
        signals.append(f"That classifier scores {page_result.model_accuracy:.0%} accuracy on its "
                       "own test split — treat the verdict as advisory")

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
