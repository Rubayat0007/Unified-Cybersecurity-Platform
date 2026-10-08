from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any

from core.models.enums import (
    Severity,
    SignalSource,
    SignalStatus,
    SignalType,
)


@dataclass(frozen=True)
class SecuritySignal:
    source: SignalSource
    signal_type: SignalType
    status: SignalStatus

    raw_score: float | None = None
    raw_score_semantics: str | None = None

    normalized_score: float | None = None
    confidence: float | None = None

    severity: Severity | None = None

    timestamp: datetime = field(
        default_factory=lambda: datetime.now(timezone.utc)
    )

    evidence: tuple[Any, ...] = ()
    metadata: dict[str, Any] = field(default_factory=dict)

    def __post_init__(self) -> None:
        if self.normalized_score is not None and not 0.0 <= self.normalized_score <= 100.0:
            raise ValueError("normalized_score must be between 0 and 100")

        if self.confidence is not None and not 0.0 <= self.confidence <= 1.0:
            raise ValueError("confidence must be between 0 and 1")