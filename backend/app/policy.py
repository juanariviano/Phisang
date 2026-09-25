from __future__ import annotations

import logging

from . import heuristics, page_stage, urlhaus
from .config import settings
from .inventory import new_scan_id, remember
from .models import AnalyzeResponse, PageResult, ThreatIntel
from .normalize import UrlError, normalize_url, redact_url
from .page_stage import PageStageError
from .url_guard import UrlRejected, check_static
from .urlhaus import UrlhausError

logger = logging.getLogger("phisang")

POLICY_VERSION = "poc-flowchart-v2.0"

LIMITATIONS = [
    "The destination is fetched server-side only when the URL checks are inconclusive",
    "Heuristic scoring is a placeholder, not a trained model",
    "The markup classifier is a demo artifact and misreads ordinary login pages",
    "A benign / not-listed result is not a guarantee of safety",
]


def _base(
    *,
    scan_id: str,
    normalized_url: str,
    classification: str,
    confidence: int,
    decision_stage: str,
    threat_intel: ThreatIntel,
    signals: list[str],
    heuristic=None,
    page_result=None,
    error_code: str | None = None,
) -> AnalyzeResponse:
    result = AnalyzeResponse(
        scan_id=scan_id,
        normalized_url=normalized_url,
        classification=classification,  # type: ignore[arg-type]
        confidence=confidence,
        decision_stage=decision_stage,  # type: ignore[arg-type]
        threat_intel=threat_intel,
        heuristic=heuristic,
        page=page_result,
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


async def analyze(raw_url: str, client: str) -> AnalyzeResponse:
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

    logger.info("analyze start scan_id=%s client=%s url=%s", scan_id, client, redact_url(normalized))

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
            decision_stage="urlhaus",
            threat_intel=intel,
            signals=signals,
        )

    heuristic = heuristics.score(normalized)

    if heuristic.label == "benign" and heuristic.confidence > settings.heuristic_benign_threshold:
        return _base(
            scan_id=scan_id,
            normalized_url=normalized,
            classification="benign",
            confidence=heuristic.confidence,
            decision_stage="heuristic",
            threat_intel=intel,
            heuristic=heuristic,
            page_result=PageResult(status="skipped"),
            signals=heuristic.signals
            + [
                "Not listed in URLhaus",
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
    return _base(
        scan_id=scan_id,
        normalized_url=normalized,
        classification=page_result.label or "unavailable",
        confidence=page_result.confidence or 0,
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
