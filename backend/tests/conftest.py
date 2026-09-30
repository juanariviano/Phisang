"""Unit tests must never read/write the configured live SQL database."""
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from app.config import settings


@pytest.fixture(autouse=True)
def isolate_external_services(monkeypatch):
    from app import policy
    # Tests must not change behavior when a developer refreshes the local ranking.
    monkeypatch.setattr(policy, "is_popular_host", lambda host: False)
    monkeypatch.setattr(settings, "db_enabled", False)
    monkeypatch.setattr(settings, "rdap_enabled", False)
    monkeypatch.setattr(settings, "explanation_api_key", "")
    monkeypatch.setattr(settings, "gemini_api_key", "")
