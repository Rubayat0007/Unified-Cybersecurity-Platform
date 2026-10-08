from dataclasses import dataclass, field
from datetime import datetime, timezone

from core.models.enums import RecommendedAction, Severity, SignalStatus
from core.models.signal import SecuritySignal
from core.evidence.model import Evidence


@dataclass(frozen=True)
class SecurityAssessment:
    overall_severity: Severity

    primary_threat: str | None = None
    threats: tuple[str, ...] = ()

    signals: tuple[SecuritySignal, ...] = ()
    evidence: tuple[Evidence, ...] = ()

    component_status: dict[str, SignalStatus] = field(default_factory=dict)

    recommended_action: RecommendedAction = RecommendedAction.MONITOR

    timestamp: datetime = field(
        default_factory=lambda: datetime.now(timezone.utc)
    )

    metadata: dict[str, object] = field(default_factory=dict)