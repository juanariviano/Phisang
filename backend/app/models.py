from typing import Any, Literal, Optional

from pydantic import BaseModel, Field

Classification = Literal["malware", "phishing", "benign", "unavailable"]
DecisionStage = Literal["history", "urlhaus", "heuristic", "page", "error"]
ClientName = Literal["web", "extension"]
HeuristicLabel = Literal["benign", "suspicious", "phishing"]
PageLabel = Literal["phishing", "benign"]


class AnalyzeRequest(BaseModel):
    url: str = Field(..., min_length=1, max_length=4096)
    client: ClientName = "web"
    # A known URL is answered from history unless the caller insists on a fresh look.
    rescan: bool = False


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
    reasoning: Optional[str] = None
    final_url: Optional[str] = None
    http_status: Optional[int] = None
    # Attacker-controlled text: safe in JSON, but never render it as markup.
    page_title: Optional[str] = None
    page_signals: Optional[PageSignals] = None
    model_name: Optional[str] = None
    model_accuracy: Optional[float] = None
    status: Literal["ok", "skipped", "unavailable"] = "skipped"


class AnalyzeResponse(BaseModel):
    scan_id: str
    normalized_url: str
    classification: Classification
    confidence: int
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
