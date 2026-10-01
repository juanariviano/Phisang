"""False-positive reports are stored for review and never change a verdict."""

import sys
from contextlib import contextmanager
from pathlib import Path

import pytest
from fastapi.testclient import TestClient

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from app import evidence, history, main, reports
from app.config import settings
from test_scan_evidence import scan


@pytest.fixture
def sql_rows(monkeypatch):
    """Record the INSERT without touching the configured database."""
    rows = []

    class Cursor:
        def execute(self, query, params):
            if query.startswith("SELECT SiteId FROM dbo.Sites"):
                self.selected = {"SiteId": 42}
            elif "INSERT INTO dbo.FalsePositiveReports" in query:
                rows.append(params)
                self.selected = {"ReportId": len(rows)}
            elif query.startswith("SELECT ExplanationJson FROM dbo.Scans"):
                self.selected = None  # Reading a scan back is unrelated to reports.
            else:
                raise AssertionError(query)

        def fetchone(self):
            return self.selected

    @contextmanager
    def cursor():
        yield Cursor()

    monkeypatch.setattr(settings, "db_enabled", True)
    monkeypatch.setattr(settings, "db_host", "test-sql")
    monkeypatch.setattr(history, "_cursor", cursor)
    return rows


@pytest.fixture
def flagged(monkeypatch):
    item = scan(scan_id="request", evidence_scan_id="scan_evidence", classification="phishing",
                verdict="malicious", risk_score=.91, risk_level="High Risk")
    monkeypatch.setattr(evidence, "get_scan", lambda scan_id: item if scan_id == item.scan_id else None)
    return item


def test_report_is_stored_against_the_evidence_scan(sql_rows, flagged):
    response = TestClient(main.app).post("/api/v1/scans/request/report",
                                        json={"client": "extension", "reason": " It is our own site. "})
    assert response.status_code == 200
    body = response.json()
    assert body == {"status": "recorded", "report_id": 1, "scan_id": "scan_evidence"}
    scan_ref, site_id, digest, url, client, verdict, classification, score, reason = sql_rows[0]
    assert scan_ref == "scan_evidence"          # Not the transient request ID.
    assert site_id == 42
    assert digest == history.url_hash(flagged.normalized_url)
    assert url == flagged.normalized_url
    assert client == "extension"
    # The verdict as it stood when the report was filed.
    assert (verdict, classification, score) == ("malicious", "phishing", .91)
    assert reason == "It is our own site."


def test_report_leaves_the_scan_and_its_history_untouched(sql_rows, flagged, monkeypatch):
    # A client that could talk its own verdict down would be a way through.
    recorded = []
    monkeypatch.setattr(history, "record", lambda *a, **k: recorded.append(a))
    client = TestClient(main.app)
    assert client.post("/api/v1/scans/request/report", json={"client": "web"}).status_code == 200
    assert client.get("/api/v1/scans/request").json()["classification"] == "phishing"
    assert flagged.classification == "phishing"
    assert flagged.verdict == "malicious"
    assert recorded == []


def test_unknown_scan_cannot_be_reported(sql_rows, flagged):
    response = TestClient(main.app).post("/api/v1/scans/missing/report", json={"client": "web"})
    assert response.status_code == 404
    assert sql_rows == []


def test_empty_reason_and_missing_body_are_accepted(sql_rows, flagged):
    client = TestClient(main.app)
    assert client.post("/api/v1/scans/request/report").status_code == 200
    assert client.post("/api/v1/scans/request/report", json={"reason": "   "}).status_code == 200
    assert [params[-1] for params in sql_rows] == [None, None]
    assert [params[4] for params in sql_rows] == ["web", "web"]


def test_overlong_reason_is_rejected(sql_rows, flagged):
    response = TestClient(main.app).post("/api/v1/scans/request/report",
                                         json={"reason": "x" * (reports.MAX_REASON_CHARS + 1)})
    assert response.status_code == 422
    assert sql_rows == []


def test_report_says_so_when_it_could_not_be_saved(flagged, monkeypatch):
    @contextmanager
    def offline():
        yield None

    monkeypatch.setattr(settings, "db_enabled", True)
    monkeypatch.setattr(settings, "db_host", "test-sql")
    monkeypatch.setattr(history, "_cursor", offline)
    response = TestClient(main.app).post("/api/v1/scans/request/report", json={"client": "web"})
    assert response.status_code == 503
    assert "could not be saved" in response.json()["message"]


def test_reports_need_the_database(flagged):
    # conftest leaves SQL disabled, so this is the unconfigured case.
    response = TestClient(main.app).post("/api/v1/scans/request/report", json={"client": "web"})
    assert response.status_code == 503
    assert "not configured" in response.json()["message"]
