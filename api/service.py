
from collections.abc import Sequence
from typing import Any, Mapping

from core.models.signal import SecuritySignal
from core.orchestration.engine import UnifiedAssessment, assess


def run_assessment(
    ai_nids_result: Mapping[str, Any] | None = None,
    phishvision_result: Mapping[str, Any] | None = None,
    event_id: str | None = None,
    phishvision_signals: Sequence[SecuritySignal] | None = None,
    phishvision_error: Exception | None = None,
) -> UnifiedAssessment:
    """Public service boundary for unified security assessment."""
    return assess(
        ai_nids_result=ai_nids_result,
        phishvision_result=phishvision_result,
        event_id=event_id,
        phishvision_signals=phishvision_signals,
        phishvision_error=phishvision_error,
    )
