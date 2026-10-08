from datetime import datetime
from typing import Any

from pydantic import BaseModel, ConfigDict, Field

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
    metadata: dict[str, Any] = Field(default_factory=dict)


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
    evidence: list[Any] = Field(default_factory=list)
    metadata: dict[str, Any] = Field(default_factory=dict)


class SecurityAssessmentResponse(BaseModel):
    model_config = ConfigDict(extra="forbid")

    overall_severity: Severity
    primary_threat: str | None = None
    threats: list[str] = Field(default_factory=list)
    signals: list[SecuritySignalResponse] = Field(default_factory=list)
    evidence: list[EvidenceResponse] = Field(default_factory=list)
    component_status: dict[str, SignalStatus] = Field(default_factory=dict)
    recommended_action: RecommendedAction
    timestamp: datetime
    metadata: dict[str, Any] = Field(default_factory=dict)


class OperationalDecisionResponse(BaseModel):
    model_config = ConfigDict(extra="forbid")

    severity: Severity
    action: RecommendedAction
    reason: str
    requires_human_review: bool
    primary_threat: str | None = None


class AssessmentAuditResponse(BaseModel):
    model_config = ConfigDict(extra="forbid")

    event_id: str
    processed_at: datetime
    source_statuses: dict[str, SignalStatus] = Field(
        default_factory=dict
    )
    overall_severity: Severity
    recommended_action: RecommendedAction
    primary_threat: str | None = None
    human_review_required: bool


class UnifiedAssessmentResponse(BaseModel):
    model_config = ConfigDict(extra="forbid")

    assessment: SecurityAssessmentResponse
    decision: OperationalDecisionResponse
    audit: AssessmentAuditResponse