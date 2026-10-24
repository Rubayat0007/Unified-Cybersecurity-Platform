from dataclasses import dataclass

from core.decision.assessment import SecurityAssessment
from core.models.enums import RecommendedAction, Severity
from core.reliability import has_informative_benign, resolve_floor


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

    # A benign verdict needs measured support. Without a reliability profile at
    # or above the floor, the platform cannot claim the event is safe - missing
    # or weak evidence is not safety.
    if action is RecommendedAction.ALLOW and not has_informative_benign(
        assessment.signals, resolve_floor()
    ):
        severity = Severity.UNKNOWN
        action = RecommendedAction.INVESTIGATE
        requires_human_review = True
        reason = (
            f"{reason} No available signal carries a reliability profile at or "
            "above the floor, so a benign verdict cannot justify ALLOW."
        )

    return OperationalDecision(
        severity=severity,
        action=action,
        reason=reason,
        requires_human_review=requires_human_review,
        primary_threat=assessment.primary_threat,
    )