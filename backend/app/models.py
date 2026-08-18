from typing import Any, Literal, Optional

from pydantic import BaseModel, Field

Classification = Literal["malware", "phishing", "benign", "unavailable"]
DecisionStage = Literal["urlhaus", "heuristic", "llm", "error"]
ClientName = Literal["web", "extension"]
HeuristicLabel = Literal["benign", "suspicious", "phishing"]
LlmLabel = Literal["phishing", "malware", "benign"]


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


class LlmResult(BaseModel):
    label: Optional[LlmLabel] = None
    confidence: Optional[int] = None
    reasoning: Optional[str] = None
    status: Literal["ok", "skipped", "unavailable"] = "skipped"


class AnalyzeResponse(BaseModel):
    scan_id: str
    normalized_url: str
    classification: Classification
    confidence: int
    decision_stage: DecisionStage
    threat_intel: ThreatIntel
    heuristic: Optional[HeuristicResult] = None
    llm: Optional[LlmResult] = None
    signals: list[str] = Field(default_factory=list)
    limitations: list[str] = Field(default_factory=list)
    policy_version: str
    error_code: Optional[str] = None


class HealthResponse(BaseModel):
    status: Literal["ok", "degraded"]
    policy_version: str
    urlhaus_configured: bool
    gemini_configured: bool
    cache_ready: bool


class MetaResponse(BaseModel):
    policy_version: str
    gemini_model: str
    heuristic_benign_threshold: int
    cache_ttl_seconds: int
    limitations: list[str]


class ErrorBody(BaseModel):
    error_code: str
    message: str
    details: Optional[dict[str, Any]] = None
