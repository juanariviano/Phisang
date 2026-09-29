from typing import Any, Literal, Optional

from pydantic import BaseModel, Field

from .risk import RiskLevel

Classification = Literal["malware", "phishing", "benign", "unavailable"]
DecisionStage = Literal["urlhaus", "heuristic", "page", "error"]
ClientName = Literal["web", "extension"]
HeuristicLabel = Literal["benign", "suspicious", "phishing"]
PageLabel = Literal["phishing", "benign"]


class AnalyzeRequest(BaseModel):
    url: str = Field(..., min_length=1, max_length=4096)
    client: ClientName = "web"


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
