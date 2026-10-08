from typing import Any, Mapping

from core.orchestration.engine import UnifiedAssessment, assess


def run_assessment(
    ai_nids_result: Mapping[str, Any] | None = None,
    phishvision_result: Mapping[str, Any] | None = None,
) -> UnifiedAssessment:
    """Public service boundary for unified security assessment."""
    return assess(
        ai_nids_result=ai_nids_result,
        phishvision_result=phishvision_result,
    )