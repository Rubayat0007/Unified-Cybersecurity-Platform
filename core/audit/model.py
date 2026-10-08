from dataclasses import dataclass
from datetime import datetime

from core.models.enums import RecommendedAction, Severity, SignalStatus


@dataclass(frozen=True)
class AssessmentAudit:
    event_id: str
    processed_at: datetime
    source_statuses: dict[str, SignalStatus]
    overall_severity: Severity
    recommended_action: RecommendedAction
    primary_threat: str | None
    human_review_required: bool