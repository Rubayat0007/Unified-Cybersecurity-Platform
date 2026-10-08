from dataclasses import dataclass
from typing import Any, Mapping

from adapters.ai_nids.adapter import adapt_result as adapt_ai_nids
from adapters.phishvision.adapter import adapt_result as adapt_phishvision
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


def assess(
    ai_nids_result: Mapping[str, Any] | None = None,
    phishvision_result: Mapping[str, Any] | None = None,
) -> UnifiedAssessment:
    """Orchestrate source adapters, correlation, and operational decision."""

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

    if phishvision_result is None:
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
            signals.extend(adapt_phishvision(phishvision_result))
        except (KeyError, TypeError, ValueError) as exc:
            signals.append(
                _error_signal(
                    SignalSource.PHISHVISION,
                    SignalType.PHISHING,
                    exc,
                )
            )

    assessment = correlate(tuple(signals))

    return UnifiedAssessment(
        assessment=assessment,
        decision=decide(assessment),
    )