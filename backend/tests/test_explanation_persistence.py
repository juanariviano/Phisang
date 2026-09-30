"""Shared explanations survive restarts and are replaced only by a fresh scan."""
import asyncio
import json
from contextlib import contextmanager
from unittest.mock import AsyncMock, Mock

import pytest
from fastapi.testclient import TestClient

from app import evidence, explanations, history, main, policy
from app.config import settings
from app.models import Explanation
from test_history_replay import row
from test_scan_evidence import scan


@pytest.fixture
def sql_rows(monkeypatch):
    """Exercise SQL serialization/lookup without touching the configured database."""
    records = {"scan_evidence": {}, "fresh_scan": {}}

    class Cursor:
        def execute(self, query, params):
            if query.startswith("UPDATE dbo.Scans SET ExplanationJson"):
                answer, key, scan_id = params
                records[scan_id] = {"ExplanationJson": answer, "ExplanationKey": key}
            elif query.startswith("SELECT ExplanationJson FROM dbo.Scans"):
                # Reuse is keyed by the saved scan, not mutable replay metadata.
                assert len(params) == 1
                self.selected = records.get(params[0])
            else:
                raise AssertionError(query)

        def fetchone(self):
            return self.selected

    @contextmanager
    def cursor():
        yield Cursor()

    monkeypatch.setattr(history, "_cursor", cursor)
    evidence._explanations.clear()
    yield records
    evidence._explanations.clear()


@pytest.mark.parametrize("streaming", [False, True])
def test_repeat_scan_returns_sql_answer_without_provider_and_rescan_starts_fresh(monkeypatch, sql_rows, streaming):
    saved = scan(verdict="malicious", risk_score=.91, risk_level="MALICIOUS", page=None)
    answer = Explanation(summary="Saved explanation.", reasons=["A risk was found."], advice=["Check first."])
    evidence.save_explanation(saved.scan_id, "old-fingerprint", answer)
    assert json.loads(sql_rows[saved.scan_id]["ExplanationJson"])["summary"] == answer.summary
    evidence._explanations.clear()  # Simulate a restart or a different API worker.

    monkeypatch.setattr(history, "lookup", Mock(return_value=row(saved)))
    record = Mock()
    monkeypatch.setattr(history, "record", record)
    fresh = AsyncMock(return_value=scan(scan_id="fresh_scan", evidence_scan_id="fresh_scan", page=None))
    monkeypatch.setattr(policy, "_analyze_fresh", fresh)
    monkeypatch.setattr(policy, "new_scan_id", lambda: "fresh_scan")
    completion = AsyncMock(return_value=answer.model_copy(update={"summary": "New scan explanation."}))
    monkeypatch.setattr(explanations, "_completion", completion)
    client = TestClient(main.app)
    headers = {"Accept": "text/event-stream"} if streaming else {}

    def analyze(rescan=False, client_name="web"):
        response = client.post("/api/v1/analyze", headers=headers,
            json={"url": saved.normalized_url, "client": client_name, "rescan": rescan})
        assert response.status_code == 200
        if streaming:
            done = response.text.split("event: done\ndata: ", 1)[1].split("\n\n", 1)[0]
            return json.loads(done)
        return response.json()

    for client_name in ("web", "extension"):
        replay = analyze(client_name=client_name)
        assert replay["served_from_history"]
        assert replay["explanation"] == answer.model_dump()
    fresh.assert_not_awaited()
    record.assert_not_called()
    completion.assert_not_awaited()

    # Saved Explain still works with no provider credentials (including SSE).
    monkeypatch.setattr(evidence, "get_scan", lambda scan_id: saved)
    response = client.post(f"/api/v1/scans/{saved.scan_id}/explain", headers=headers)
    assert response.status_code == 200
    assert answer.summary in response.text
    assert client.get(f"/api/v1/scans/{saved.scan_id}").json()["explanation"] == answer.model_dump()
    completion.assert_not_awaited()

    rescanned = analyze(rescan=True)
    assert not rescanned["served_from_history"]
    assert rescanned["explanation"] is None
    fresh.assert_awaited_once()
    record.assert_called_once()
    completion.assert_not_awaited()  # Still on demand after a rescan.
    monkeypatch.setattr(settings, "explanation_api_key", "test")
    new_answer = asyncio.run(explanations.explain(scan(
        scan_id=rescanned["scan_id"], evidence_scan_id=rescanned["evidence_scan_id"], page=None)))
    assert new_answer.summary == "New scan explanation."
    completion.assert_awaited_once()
    evidence._explanations.clear()
    assert evidence.get_explanation("fresh_scan") == new_answer
    assert evidence.get_explanation(saved.scan_id) == answer


def test_corrupt_saved_answer_is_not_reused(sql_rows):
    sql_rows["scan_evidence"] = {"ExplanationJson": '{"summary":"partial"}'}
    assert evidence.get_explanation("scan_evidence") is None
