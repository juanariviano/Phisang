from typing import Any, Literal, Optional

from pydantic import BaseModel, Field, PrivateAttr

from .risk import RiskLevel

Classification = Literal["malware", "phishing", "benign", "unavailable"]
DecisionStage = Literal["history", "urlhaus", "heuristic", "page", "error", "approved"]
ClientName = Literal["web", "extension"]
HeuristicLabel = Literal["benign", "suspicious", "phishing"]
PageLabel = Literal["phishing", "benign"]


class AnalyzeRequest(BaseModel):
    url: str = Field(..., min_length=1, max_length=4096)
    client: ClientName = "web"
    # A known URL is answered from history unless the caller insists on a fresh look.
    rescan: bool = False
    # Bypass history and reputation shortcuts, while retaining threat checks.
    inspect_page: bool = False


Verdict = Literal["malicious", "safe", "potentially_unsafe", "unknown"]


class PriorScan(BaseModel):
    """What the archive already knows about this URL, shown before a rescan."""

    seen_before: bool = True
    verdict: Verdict
    last_scanned_at: Optional[str] = None
    first_scanned_at: Optional[str] = None
    scan_count: int = 0
    malicious_count: int = 0
    safe_count: int = 0
    potentially_unsafe_count: int = 0
    unknown_count: int = 0
    # True once a scan has ever called it malicious, which keeps the verdict at
    # potentially_unsafe even after a later clean result.
    ever_malicious: bool = False
    last_score: Optional[float] = None
    last_decision_stage: Optional[str] = None
    message: str


class ThreatIntel(BaseModel):
    matched: bool
    source: Optional[str] = None
    threat_type: Optional[str] = None
    id: Optional[str] = None
    first_seen: Optional[str] = None
    url_status: Optional[str] = None
    match_kind: Optional[Literal["url", "host"]] = None
    feed_status: Literal["ok", "unavailable", "skipped"] = "ok"


class HeuristicResult(BaseModel):
    label: HeuristicLabel
    confidence: int
    risk_score: int
    signals: list[str] = Field(default_factory=list)


class PageSignals(BaseModel):
    forms: int = 0
    password_inputs: int = 0
    inputs: int = 0
    links: int = 0
    iframes: int = 0


class PageResult(BaseModel):
    """Verdict from fetching the destination and classifying its markup."""

    label: Optional[PageLabel] = None
    confidence: Optional[int] = None
    phishing_score: Optional[float] = None
    threshold: Optional[float] = None
    risk_level: Optional[RiskLevel] = None
    reasoning: Optional[str] = None
    final_url: Optional[str] = None
    http_status: Optional[int] = None
    # Attacker-controlled text: safe in JSON, but never render it as markup.
    page_title: Optional[str] = None
    page_signals: Optional[PageSignals] = None
    model_name: Optional[str] = None
    model_accuracy: Optional[float] = None
    status: Literal["ok", "skipped", "unavailable"] = "skipped"
    preview_available: bool = False
    _screenshot: bytes | None = PrivateAttr(default=None)


class DomainInfo(BaseModel):
    status: Literal["ok", "unavailable", "not_applicable"] = "unavailable"
    domain: Optional[str] = None
    source: str = "RDAP"
    registrar: Optional[str] = None
    registered_at: Optional[str] = None
    expires_at: Optional[str] = None
    nameservers: list[str] = Field(default_factory=list)
    checked_at: Optional[str] = None


class Explanation(BaseModel):
    summary: str = Field(min_length=1, max_length=1600)
    reasons: list[str] = Field(min_length=1, max_length=6)
    advice: list[str] = Field(min_length=1, max_length=5)
    model: str = ""
    generated_at: str = ""
    included_screenshot: bool = False


class PageShortcut(BaseModel):
    source: Literal["tranco", "well_known"]
    top_count: Optional[int] = None


class AnalyzeResponse(BaseModel):
    scan_id: str
    normalized_url: str
    classification: Classification
    confidence: int
    # 0 (clean) to 1 (malicious), banded into risk_level by app.risk.
    risk_score: Optional[float] = None
    risk_level: Optional[RiskLevel] = None
    decision_stage: DecisionStage
    threat_intel: ThreatIntel
    heuristic: Optional[HeuristicResult] = None
    page: Optional[PageResult] = None
    prior: Optional[PriorScan] = None
    served_from_history: bool = False
    verdict: Optional[Verdict] = None
    signals: list[str] = Field(default_factory=list)
    limitations: list[str] = Field(default_factory=list)
    policy_version: str
    error_code: Optional[str] = None
    domain_info: Optional[DomainInfo] = None
    # A replay has a new request ID but keeps the original evidence identity.
    evidence_scan_id: Optional[str] = None
    scanned_at: Optional[str] = None
    explanation: Optional[Explanation] = None
    page_shortcut: Optional[PageShortcut] = None


class FalsePositiveReportRequest(BaseModel):
    client: ClientName = "web"
    # Free text from the reporter. Stored and reviewed by hand, never rendered as
    # markup and never fed back into a verdict.
    reason: Optional[str] = Field(default=None, max_length=1000)


class FalsePositiveReportResponse(BaseModel):
    status: Literal["recorded"] = "recorded"
    report_id: int
    scan_id: str


class AdminSignInRequest(BaseModel):
    email: str = Field(..., min_length=3, max_length=320)
    password: str = Field(..., min_length=1, max_length=256)
    # Six digits from the authenticator app, valid for one 30-second window.
    code: str = Field(..., min_length=6, max_length=8)


class AdminReviewRequest(BaseModel):
    decision: Literal["approved", "rejected"]
    note: Optional[str] = Field(default=None, max_length=1000)


class AdminBatchReviewRequest(AdminReviewRequest):
    # Bounded so one call cannot clear an unbounded number of addresses.
    report_ids: list[int] = Field(..., min_length=1, max_length=200)


class HealthResponse(BaseModel):
    status: Literal["ok", "degraded"]
    policy_version: str
    urlhaus_configured: bool
    page_stage_ready: bool
    cache_ready: bool
    history_ready: bool = False


class MetaResponse(BaseModel):
    policy_version: str
    page_model: Optional[str] = None
    page_model_accuracy: Optional[float] = None
    heuristic_benign_threshold: int
    cache_ttl_seconds: int
    limitations: list[str]


class ErrorBody(BaseModel):
    error_code: str
    message: str
    details: Optional[dict[str, Any]] = None
