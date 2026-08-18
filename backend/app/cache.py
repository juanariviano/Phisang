from __future__ import annotations

import json
import sqlite3
import time
from typing import Any, Optional

from .config import DATA_DIR, settings

DB_PATH = DATA_DIR / "urlhaus_cache.db"


def _connect() -> sqlite3.Connection:
    conn = sqlite3.connect(DB_PATH, timeout=5)
    conn.execute(
        """
        CREATE TABLE IF NOT EXISTS urlhaus_cache (
            cache_key TEXT PRIMARY KEY,
            payload TEXT NOT NULL,
            created_at REAL NOT NULL
        )
        """
    )
    return conn


def init_cache() -> None:
    with _connect() as conn:
        conn.execute("SELECT 1 FROM urlhaus_cache LIMIT 1")


def get_cached(cache_key: str) -> Optional[dict[str, Any]]:
    now = time.time()
    with _connect() as conn:
        row = conn.execute(
            "SELECT payload, created_at FROM urlhaus_cache WHERE cache_key = ?",
            (cache_key,),
        ).fetchone()
        if not row:
            return None
        payload, created_at = row
        if now - created_at > settings.cache_ttl_seconds:
            conn.execute("DELETE FROM urlhaus_cache WHERE cache_key = ?", (cache_key,))
            return None
        return json.loads(payload)


def set_cached(cache_key: str, payload: dict[str, Any]) -> None:
    with _connect() as conn:
        conn.execute(
            """
            INSERT OR REPLACE INTO urlhaus_cache (cache_key, payload, created_at)
            VALUES (?, ?, ?)
            """,
            (cache_key, json.dumps(payload), time.time()),
        )


def cache_ready() -> bool:
    try:
        init_cache()
        return True
    except sqlite3.Error:
        return False
