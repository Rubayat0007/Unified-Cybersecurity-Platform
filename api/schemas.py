from datetime import datetime
from typing import Any

from pydantic import BaseModel, ConfigDict

from core.models.enums import (
    RecommendedAction,
    Severity,
    SignalSource,
    SignalStatus,
    SignalType,
)


class EvidenceResponse(BaseModel):
    model_config = ConfigDict(extra="forbid")

    source: SignalSource
    category: str
    description: str
    evidence_type: str | None = None
    value: Any = None
    timestamp: datetime
    metadata: dict[str, Any] = {}


class SecuritySignalResponse(BaseModel):
    model_config = ConfigDict(extra="forbid")

    source: SignalSource
    signal_type: SignalType
    status: SignalStatus
    raw_score: float | None = None
    raw_score_semantics: str | None = None
    normalized_score: float | None = None
    confidence: float | None = None
    severity: Severity | None = None
    timestamp: datetime
    evidence: list[Any] = []
    metadata: dict[str, Any] = {}


class SecurityAssessmentResponse(BaseModel):
    model_config = ConfigDict(extra="forbid")

    overall_severity: Severity
    primary_threat: str | None = None
    threats: list[str] = []
    signals: list[SecuritySignalResponse] = []
    evidence: list[EvidenceResponse] = []
    component_status: dict[str, SignalStatus] = {}
    recommended_action: RecommendedAction
    timestamp: datetime
    metadata: dict[str, Any] = {}


class OperationalDecisionResponse(BaseModel):
    model_config = ConfigDict(extra="forbid")

    severity: Severity
    action: RecommendedAction
    reason: str
    requires_human_review: bool
    primary_threat: str | None = None


class UnifiedAssessmentResponse(BaseModel):
    model_config = ConfigDict(extra="forbid")

    assessment: SecurityAssessmentResponse
    decision: OperationalDecisionResponse