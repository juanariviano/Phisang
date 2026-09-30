from __future__ import annotations

import asyncio
import logging
import json
from contextlib import suppress
from contextlib import asynccontextmanager

from fastapi import FastAPI, Query, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse, Response, StreamingResponse
from fastapi.staticfiles import StaticFiles

from . import evidence, explanations, history, inventory, page_stage, scan_progress
from .cache import cache_ready, init_cache
from .config import WEB_DIR, settings
from .models import AnalyzeRequest, ErrorBody, HealthResponse, MetaResponse
from .normalize import UrlError
from .policy import LIMITATIONS, POLICY_VERSION, analyze, map_url_error

logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(name)s %(message)s")
logger = logging.getLogger("phisang")


@asynccontextmanager
async def lifespan(_app: FastAPI):
    init_cache()
    await page_stage.startup()
    logger.info("Phisang API ready policy=%s cache=%s page_stage=%s",
                POLICY_VERSION, cache_ready(), page_stage.ready())
    try:
        yield
    finally:
        await page_stage.shutdown()


app = FastAPI(title="Phisang POC", version=POLICY_VERSION, lifespan=lifespan)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=False,
    allow_methods=["*"],
    allow_headers=["*"],
)


@app.get("/api/v1/health", response_model=HealthResponse)
def health() -> HealthResponse:
    urlhaus_ok = bool(settings.urlhaus_auth_key)
    page_ok = page_stage.ready()
    ready = cache_ready()
    status = "ok" if urlhaus_ok and ready and page_ok else "degraded"
    return HealthResponse(
        status=status,
        policy_version=POLICY_VERSION,
        urlhaus_configured=urlhaus_ok,
        page_stage_ready=page_ok,
        cache_ready=ready,
        history_ready=history.ready(),
    )


@app.get("/api/v1/meta", response_model=MetaResponse)
def meta() -> MetaResponse:
    return MetaResponse(
        policy_version=POLICY_VERSION,
        page_model=page_stage.model_name(),
        page_model_accuracy=page_stage.model_accuracy(),
        heuristic_benign_threshold=settings.heuristic_benign_threshold,
        cache_ttl_seconds=settings.cache_ttl_seconds,
        limitations=list(LIMITATIONS),
    )


@app.post("/api/v1/analyze")
async def analyze_url(body: AnalyzeRequest, request: Request):
    if "text/event-stream" in request.headers.get("accept", ""):
        return StreamingResponse(_scan_events(body), media_type="text/event-stream", headers={
            "Cache-Control": "no-cache, no-transform", "X-Accel-Buffering": "no"})
    try:
        return await _analyze_with_explanation(body)
    except UrlError as exc:
        status, code, message = map_url_error(exc)
        return JSONResponse(
            status_code=status,
            content=ErrorBody(error_code=code, message=message).model_dump(),
        )


async def _analyze_with_explanation(body):
    result = await analyze(body.url, body.client, rescan=body.rescan)
    return await asyncio.to_thread(_with_saved_explanation, result)


def _with_saved_explanation(result):
    # Reading a result never initiates an LLM call. A rescan has a new evidence ID.
    answer = evidence.get_explanation(result.evidence_scan_id or result.scan_id)
    return result.model_copy(update={"explanation": answer})


async def _scan_events(body):
    queue = asyncio.Queue(maxsize=32)

    async def progress(value):
        await queue.put(("progress", value))

    async def run():
        with scan_progress.listen(progress):
            try:
                result = await _analyze_with_explanation(body)
                await queue.put(("done", result.model_dump(mode="json")))
            except UrlError as exc:
                _, code, message = map_url_error(exc)
                await queue.put(("error", {"error_code": code, "message": message}))
            except Exception:
                logger.exception("Streaming scan failed")
                await queue.put(("error", {"message": "The scan could not finish. Please try again."}))

    task = asyncio.create_task(run())
    try:
        yield ": connected\n\n"
        while True:
            try:
                event, value = await asyncio.wait_for(queue.get(), 10)
            except asyncio.TimeoutError:
                yield ": keepalive\n\n"
                continue
            yield f"event: {event}\ndata: {json.dumps(value, ensure_ascii=False)}\n\n"
            if event in {"done", "error"}:
                break
    finally:
        # A closed tab must not leave an unobserved scan task behind.
        if not task.done():
            task.cancel()
        with suppress(asyncio.CancelledError):
            await task


@app.get("/api/v1/scans")
def list_scans(limit: int = Query(default=25, ge=1, le=100)):
    return {"scans": [item.model_dump() for item in inventory.list_scans(limit)]}


@app.get("/api/v1/scans/{scan_id}")
def get_scan(scan_id: str):
    item = evidence.get_scan(scan_id)
    if item is None:
        return JSONResponse(
            status_code=404,
            content=ErrorBody(error_code="not_found", message="Scan not found").model_dump(),
        )
    return _with_saved_explanation(item)


@app.get("/api/v1/scans/{scan_id}/preview")
def get_preview(scan_id: str):
    item = evidence.get_scan(scan_id)
    image = evidence.get_preview(item.evidence_scan_id or item.scan_id) if item else None
    if not image:
        return JSONResponse(status_code=404, content={"message": "Preview unavailable"})
    return Response(content=image, media_type="image/jpeg", headers={
        "Cache-Control": "private, max-age=3600", "X-Content-Type-Options": "nosniff"})


@app.post("/api/v1/scans/{scan_id}/explain")
async def explain_scan(scan_id: str, request: Request):
    item = await asyncio.to_thread(evidence.get_scan, scan_id)
    if item is None:
        return JSONResponse(status_code=404, content={"message": "Scan not found. Please scan the address again."})
    try:
        if "text/event-stream" in request.headers.get("accept", ""):
            events = await explanations.stream(item)
            return StreamingResponse(events, media_type="text/event-stream", headers={
                "Cache-Control": "no-cache, no-transform", "X-Accel-Buffering": "no"})
        return await explanations.explain(item)
    except explanations.ExplanationError as exc:
        return JSONResponse(status_code=exc.status, content={"message": str(exc)})


if WEB_DIR.exists():
    app.mount("/", StaticFiles(directory=str(WEB_DIR), html=True), name="web")
else:
    logger.warning("Web scanner directory missing: %s", WEB_DIR)
