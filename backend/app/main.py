from __future__ import annotations

import logging
from contextlib import asynccontextmanager

from fastapi import FastAPI, Query
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse
from fastapi.staticfiles import StaticFiles

from . import history, inventory, page_stage
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
async def analyze_url(body: AnalyzeRequest):
    try:
        return await analyze(body.url, body.client, rescan=body.rescan)
    except UrlError as exc:
        status, code, message = map_url_error(exc)
        return JSONResponse(
            status_code=status,
            content=ErrorBody(error_code=code, message=message).model_dump(),
        )


@app.get("/api/v1/scans")
def list_scans(limit: int = Query(default=25, ge=1, le=100)):
    return {"scans": [item.model_dump() for item in inventory.list_scans(limit)]}


@app.get("/api/v1/scans/{scan_id}")
def get_scan(scan_id: str):
    item = inventory.get_scan(scan_id)
    if item is None:
        return JSONResponse(
            status_code=404,
            content=ErrorBody(error_code="not_found", message="Scan not found").model_dump(),
        )
    return item


if WEB_DIR.exists():
    app.mount("/", StaticFiles(directory=str(WEB_DIR), html=True), name="web")
else:
    logger.warning("Web scanner directory missing: %s", WEB_DIR)
