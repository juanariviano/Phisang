"""Scan-owned evidence; bounded memory fallback when SQL is unavailable."""
from collections import OrderedDict

from . import history, inventory
from .models import AnalyzeResponse, Explanation

MAX_PREVIEW_BYTES = 600_000
_images: OrderedDict[str, bytes] = OrderedDict()
_explanations: OrderedDict[tuple[str, str], Explanation] = OrderedDict()


def _put(cache, key, value):
    cache[key] = value
    cache.move_to_end(key)
    while len(cache) > 100:
        cache.popitem(last=False)


def remember_preview(scan_id: str, image: bytes | None):
    if image and image.startswith(b"\xff\xd8\xff") and len(image) <= MAX_PREVIEW_BYTES:
        _put(_images, scan_id, image)


def get_scan(scan_id: str) -> AnalyzeResponse | None:
    item = inventory.get_scan(scan_id)
    if item is not None:
        return item
    with history._cursor() as cur:
        if cur is None:
            return None
        cur.execute("SELECT RawResponseJson FROM dbo.Scans WHERE ScanRef = %s", (scan_id,))
        row = cur.fetchone()
        if row and row.get("RawResponseJson"):
            try:
                return AnalyzeResponse.model_validate_json(row["RawResponseJson"])
            except ValueError:
                return None


def persist_preview(scan_id: str, image: bytes | None):
    remember_preview(scan_id, image)
    image = _images.get(scan_id)
    if image is None:
        return
    # Separate from recording the verdict: an unapplied migration must not lose
    # the scan's audit log.
    with history._cursor() as cur:
        if cur is not None:
            cur.execute("UPDATE dbo.Scans SET ScreenshotJpeg = %s WHERE ScanRef = %s", (image, scan_id))


def get_preview(scan_id: str) -> bytes | None:
    image = _images.get(scan_id)
    if image is not None:
        return image
    with history._cursor() as cur:
        if cur is None:
            return None
        cur.execute("SELECT ScreenshotJpeg FROM dbo.Scans WHERE ScanRef = %s", (scan_id,))
        row = cur.fetchone()
        if row and row.get("ScreenshotJpeg"):
            image = bytes(row["ScreenshotJpeg"])
            remember_preview(scan_id, image)
            return _images.get(scan_id)


def get_explanation(scan_id: str, key: str) -> Explanation | None:
    cached = _explanations.get((scan_id, key))
    if cached:
        return cached
    with history._cursor() as cur:
        if cur is None:
            return None
        cur.execute("SELECT ExplanationJson FROM dbo.Scans WHERE ScanRef = %s AND ExplanationKey = %s", (scan_id, key))
        row = cur.fetchone()
        if row and row.get("ExplanationJson"):
            try:
                cached = Explanation.model_validate_json(row["ExplanationJson"])
                _put(_explanations, (scan_id, key), cached)
                return cached
            except ValueError:
                return None


def save_explanation(scan_id: str, key: str, result: Explanation):
    _put(_explanations, (scan_id, key), result)
    with history._cursor() as cur:
        if cur is not None:
            cur.execute("UPDATE dbo.Scans SET ExplanationJson = %s, ExplanationKey = %s WHERE ScanRef = %s",
                        (result.model_dump_json(), key, scan_id))
