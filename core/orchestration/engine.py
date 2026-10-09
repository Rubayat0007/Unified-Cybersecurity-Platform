
from uuid import uuid4
from dataclasses import dataclass
from collections.abc import Sequence
from typing import Any, Mapping

from adapters.ai_nids.adapter import adapt_result as adapt_ai_nids
from adapters.phishvision.adapter import adapt_result as adapt_phishvision
from core.audit.model import AssessmentAudit
from core.correlation.engine import correlate
from core.decision.assessment import SecurityAssessment
from core.decision.engine import OperationalDecision, decide
from core.models.enums import (
    Severity,
    SignalSource,
    SignalStatus,
    SignalType,
)
from core.models.signal import SecuritySignal


@dataclass(frozen=True)
class UnifiedAssessment:
    assessment: SecurityAssessment
    decision: OperationalDecision
    audit: AssessmentAudit


def _unavailable_signal(
    source: SignalSource,
    signal_type: SignalType,
) -> SecuritySignal:
    return SecuritySignal(
        source=source,
        signal_type=signal_type,
        status=SignalStatus.UNAVAILABLE,
        severity=Severity.UNKNOWN,
        metadata={"reason": "source result not provided"},
    )


def _error_signal(
    source: SignalSource,
    signal_type: SignalType,
    exc: Exception,
) -> SecuritySignal:
    return SecuritySignal(
        source=source,
        signal_type=signal_type,
        status=SignalStatus.ERROR,
        severity=Severity.UNKNOWN,
        metadata={
            "error_type": type(exc).__name__,
            "reason": "source adapter rejected the result",
        },
    )


def _provider_failure_signals(
    exc: Exception,
) -> tuple[SecuritySignal, ...]:
    signal_types = (
        SignalType.TEXT_THREAT,
        SignalType.URL_THREAT,
        SignalType.VISUAL_THREAT,
    )

    return tuple(
        SecuritySignal(
            source=SignalSource.PHISHVISION,
            signal_type=signal_type,
            status=SignalStatus.ERROR,
            severity=Severity.UNKNOWN,
            metadata={
                "error_type": type(exc).__name__,
                "reason": "provider execution failed",
            },
        )
        for signal_type in signal_types
    )


def assess(
    ai_nids_result: Mapping[str, Any] | None = None,
    phishvision_result: Mapping[str, Any] | None = None,
    event_id: str | None = None,
    phishvision_signals: Sequence[SecuritySignal] | None = None,
    phishvision_error: Exception | None = None,
) -> UnifiedAssessment:
    """
    Orchestrate source results or normalized provider signals,
    correlation, operational decision, and audit creation.

    The legacy phishvision_result argument remains supported.
    Runtime provider signals and provider errors use separate arguments.
    """
    phishvision_modes = (
        phishvision_result is not None,
        phishvision_signals is not None,
        phishvision_error is not None,
    )

    if sum(phishvision_modes) > 1:
        raise ValueError(
            "Provide only one PhishVision input mode"
        )

    signals: list[SecuritySignal] = []

    if ai_nids_result is None:
        signals.append(
            _unavailable_signal(
                SignalSource.AI_NIDS,
                SignalType.NETWORK_INTRUSION,
            )
        )
    else:
        try:
            signals.append(adapt_ai_nids(ai_nids_result))
        except (KeyError, TypeError, ValueError) as exc:
            signals.append(
                _error_signal(
                    SignalSource.AI_NIDS,
                    SignalType.NETWORK_INTRUSION,
                    exc,
                )
            )

    if phishvision_signals is not None:
        normalized_signals = tuple(phishvision_signals)

        if any(
            not isinstance(signal, SecuritySignal)
            for signal in normalized_signals
        ):
            raise TypeError(
                "phishvision_signals must contain SecuritySignal objects"
            )

        if any(
            signal.source is not SignalSource.PHISHVISION
            for signal in normalized_signals
        ):
            raise ValueError(
                "phishvision_signals must contain only PhishVision signals"
            )

        signals.extend(normalized_signals)

    elif phishvision_error is not None:
        signals.extend(
            _provider_failure_signals(phishvision_error)
        )

    elif phishvision_result is None:
        signals.extend(
            (
                _unavailable_signal(
                    SignalSource.PHISHVISION,
                    SignalType.TEXT_THREAT,
                ),
                _unavailable_signal(
                    SignalSource.PHISHVISION,
                    SignalType.URL_THREAT,
                ),
                _unavailable_signal(
                    SignalSource.PHISHVISION,
                    SignalType.VISUAL_THREAT,
                ),
            )
        )

    else:
        try:
            signals.extend(
                adapt_phishvision(phishvision_result)
            )
        except (KeyError, TypeError, ValueError) as exc:
            signals.append(
                _error_signal(
                    SignalSource.PHISHVISION,
                    SignalType.PHISHING,
                    exc,
                )
            )

    assessment = correlate(tuple(signals))
    decision = decide(assessment)

    resolved_event_id = event_id or str(uuid4())

    audit = AssessmentAudit(
        event_id=resolved_event_id,
        processed_at=assessment.timestamp,
        source_statuses=dict(assessment.component_status),
        overall_severity=assessment.overall_severity,
        recommended_action=decision.action,
        primary_threat=assessment.primary_threat,
        human_review_required=decision.requires_human_review,
    )

    return UnifiedAssessment(
        assessment=assessment,
        decision=decision,
        audit=audit,
    )
