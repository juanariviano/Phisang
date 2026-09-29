"""The page-analysis gate: fetch the destination, classify its markup.

Owns the browser and the model for the process lifetime, since starting Chromium
and loading the model are both too slow to do per request.
"""

from __future__ import annotations

import asyncio
import logging

from .config import settings
from .models import PageResult, PageSignals
from .page_fetch import FetchFailed, Fetcher, clean_html, page_signals
from .page_model import Classifier, LayaClassifier, ModelUnavailable, load_classifier
from .risk import MALICIOUS_FROM, risk_level
from .url_guard import UrlRejected

logger = logging.getLogger("phisang")

_fetcher: Fetcher | None = None
_classifier: Classifier | LayaClassifier | None = None


class PageStageError(Exception):
    """The gate could not produce a verdict. The message is caller-safe."""


async def startup() -> None:
    global _fetcher, _classifier
    if not settings.page_stage_enabled:
        logger.info("page stage disabled by configuration")
        return
    try:
        _classifier = load_classifier(settings.page_model_dir)
    except ModelUnavailable as exc:
        logger.warning("page stage model unavailable: %s", exc)
        return
    proxy = {"server": settings.page_fetch_proxy} if settings.page_fetch_proxy else None
    fetcher = Fetcher(
        max_concurrency=settings.page_fetch_concurrency,
        nav_timeout=settings.page_fetch_timeout_seconds,
        total_timeout=settings.page_fetch_budget_seconds,
        proxy=proxy,
    )
    try:
        await fetcher.start()
    except Exception as exc:
        logger.warning("page stage browser unavailable: %s", exc)
        _classifier = None
        return
    _fetcher = fetcher
    logger.info("page stage ready model=%s proxy=%s",
                _classifier.model_dir.name, settings.page_fetch_proxy or "none")


async def shutdown() -> None:
    global _fetcher, _classifier
    if _fetcher is not None:
        await _fetcher.stop()
        _fetcher = None
    _classifier = None


def ready() -> bool:
    return _fetcher is not None and _classifier is not None


def model_name() -> str | None:
    return _classifier.model_dir.name if _classifier else None


def model_accuracy() -> float | None:
    return _classifier.test_metrics.get("accuracy") if _classifier else None


async def classify(url: str) -> PageResult:
    if not ready():
        raise PageStageError("Page analysis is not available")

    try:
        page = await _fetcher.fetch(url)
    except UrlRejected as exc:
        raise PageStageError(f"Destination refused: {exc}") from None
    except FetchFailed as exc:
        raise PageStageError(f"Destination could not be fetched: {exc}") from None

    # An error page carries none of the destination's real markup, so reading it
    # would put a verdict on the host's 404 template. A taken-down phishing site
    # must come back degraded, never benign.
    if not 200 <= page["status"] < 300:
        raise PageStageError(
            f"Destination answered HTTP {page['status']}, so its markup was not read")

    try:
        verdict = await asyncio.to_thread(_classifier.predict, page["html"])
    except ValueError as exc:
        raise PageStageError(f"Page held nothing to classify: {exc}") from None

    # The label follows the risk bands rather than the artifact's own operating
    # threshold, so a page shown as MALICIOUS or High Risk is also called phishing.
    score = verdict["phishing_score"]
    is_phishing = score >= MALICIOUS_FROM
    signals = page_signals(clean_html(page["html"]))
    return PageResult(
        label="phishing" if is_phishing else "benign",
        confidence=round((score if is_phishing else 1 - score) * 100),
        phishing_score=score,
        threshold=MALICIOUS_FROM,
        risk_level=risk_level(score),
        reasoning=_reasoning(score, signals),
        final_url=page["final_url"],
        http_status=page["status"],
        page_title=page["title"],
        page_signals=PageSignals(**signals),
        model_name=model_name(),
        model_accuracy=model_accuracy(),
        status="ok",
    )


def _reasoning(score: float, signals: dict) -> str:
    parts = [f"The fetched page scored {score:.2f} on the markup classifier."]
    if signals["password_inputs"]:
        parts.append(f"It asks for a password in {signals['password_inputs']} field(s)"
                     f" across {signals['forms']} form(s).")
    elif signals["forms"]:
        parts.append(f"It carries {signals['forms']} form(s) but no password field.")
    else:
        parts.append("It carries no form at all.")
    if signals["iframes"]:
        parts.append(f"{signals['iframes']} iframe(s) are embedded.")
    return " ".join(parts)
