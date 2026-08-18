from __future__ import annotations

import logging

from . import heuristics, llm, urlhaus
from .config import settings
from .inventory import new_scan_id, remember
from .llm import LlmError
from .models import AnalyzeResponse, LlmResult, ThreatIntel
from .normalize import UrlError, normalize_url, redact_url
from .urlhaus import UrlhausError

logger = logging.getLogger("linkguard")

POLICY_VERSION = "poc-flowchart-v1"

LIMITATIONS = [
    "The destination was not visited or analyzed",
    "Heuristic scoring is a placeholder, not a trained model",
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
    llm_result=None,
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
        llm=llm_result,
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
        llm_result=LlmResult(status="unavailable") if error_code == "llm_unavailable" else None,
        error_code=error_code,
    )


async def analyze(raw_url: str, client: str) -> AnalyzeResponse:
    scan_id = new_scan_id()
    normalized = normalize_url(raw_url)
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
            llm_result=LlmResult(status="skipped"),
            signals=heuristic.signals
            + [
                "Not listed in URLhaus",
                f"Placeholder ML confidence {heuristic.confidence}% exceeded the {settings.heuristic_benign_threshold}% allow threshold",
            ],
        )

    try:
        llm_result = await llm.classify(normalized, heuristic)
    except LlmError as exc:
        logger.warning("llm failed scan_id=%s err=%s", scan_id, exc)
        reason = (
            "Heuristic flagged the URL as inconclusive or suspicious, but Gemini was unavailable"
            if heuristic.label != "benign"
            else "Heuristic confidence was too low to allow locally, and Gemini was unavailable"
        )
        return _unavailable(
            scan_id=scan_id,
            normalized_url=normalized,
            error_code="llm_unavailable",
            threat_intel=intel,
            heuristic=heuristic,
            signals=heuristic.signals + [reason, "Result is degraded — not a clean or benign verdict"],
        )

    signals = list(heuristic.signals)
    signals.append(f"Gemini classified the URL as {llm_result.label} from the URL string only")
    return _base(
        scan_id=scan_id,
        normalized_url=normalized,
        classification=llm_result.label or "unavailable",
        confidence=llm_result.confidence or 0,
        decision_stage="llm",
        threat_intel=intel,
        heuristic=heuristic,
        llm_result=llm_result,
        signals=signals,
    )


def map_url_error(exc: UrlError) -> tuple[int, str, str]:
    status = {
        "invalid_url": 400,
        "unsupported_scheme": 400,
        "input_too_large": 413,
    }.get(exc.code, 400)
    return status, exc.code, exc.message
