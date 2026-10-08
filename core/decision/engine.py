from dataclasses import dataclass

from core.decision.assessment import SecurityAssessment
from core.models.enums import RecommendedAction, Severity


@dataclass(frozen=True)
class OperationalDecision:
    severity: Severity
    action: RecommendedAction
    reason: str
    requires_human_review: bool
    primary_threat: str | None = None


def decide(assessment: SecurityAssessment) -> OperationalDecision:
    """Translate a security assessment into an operational decision.

    This layer deliberately preserves the correlation policy's recommended
    action. It adds operational context without silently changing risk
    semantics.
    """
    severity = assessment.overall_severity
    action = assessment.recommended_action

    if severity == Severity.UNKNOWN:
        reason = (
            "No usable security signal is available; investigation is "
            "required rather than assuming the event is benign."
        )
        requires_human_review = True

    elif assessment.primary_threat is not None:
        corroboration = assessment.metadata.get(
            "cross_source_corroboration",
            False,
        )

        if corroboration:
            reason = (
                f"Multiple security sources corroborate a "
                f"{severity.value} assessment for "
                f"{assessment.primary_threat}."
            )
        else:
            reason = (
                f"A security source produced a {severity.value} assessment "
                f"for {assessment.primary_threat}."
            )

        requires_human_review = action in {
            RecommendedAction.INVESTIGATE,
            RecommendedAction.BLOCK,
        }

    else:
        reason = (
            f"The overall assessment is {severity.value} with no specific "
            "primary threat identified."
        )
        requires_human_review = action in {
            RecommendedAction.INVESTIGATE,
            RecommendedAction.BLOCK,
        }

    return OperationalDecision(
        severity=severity,
        action=action,
        reason=reason,
        requires_human_review=requires_human_review,
        primary_threat=assessment.primary_threat,
    )