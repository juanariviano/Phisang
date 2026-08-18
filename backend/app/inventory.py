from __future__ import annotations

import uuid
from collections import deque
from typing import Optional

from .models import AnalyzeResponse

MAX_SCANS = 100
_scans: deque[AnalyzeResponse] = deque(maxlen=MAX_SCANS)


def new_scan_id() -> str:
    return f"scan_{uuid.uuid4().hex[:8]}"


def remember(result: AnalyzeResponse) -> None:
    _scans.appendleft(result)


def list_scans(limit: int = 25) -> list[AnalyzeResponse]:
    return list(_scans)[: max(1, min(limit, MAX_SCANS))]


def get_scan(scan_id: str) -> Optional[AnalyzeResponse]:
    for item in _scans:
        if item.scan_id == scan_id:
            return item
    return None
