from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any

from core.models.enums import SignalSource


@dataclass(frozen=True)
class Evidence:
    source: SignalSource
    category: str
    description: str

    evidence_type: str | None = None
    value: Any = None

    timestamp: datetime = field(
        default_factory=lambda: datetime.now(timezone.utc)
    )

    metadata: dict[str, Any] = field(default_factory=dict)