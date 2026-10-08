from collections.abc import Iterable

from core.decision.assessment import SecurityAssessment
from core.models.enums import SignalStatus
from core.models.signal import SecuritySignal
from core.policies.default_policy import (
    determine_overall_severity,
    determine_primary_threat,
    determine_recommended_action,
    determine_threats,
    has_cross_source_corroboration,
)


_STATUS_PRIORITY = {
    SignalStatus.AVAILABLE: 5,
    SignalStatus.ERROR: 4,
    SignalStatus.TIMEOUT: 3,
    SignalStatus.UNAVAILABLE: 2,
    SignalStatus.NOT_APPLICABLE: 1,
}


def _component_status(
    signals: tuple[SecuritySignal, ...],
) -> dict[str, SignalStatus]:
    result: dict[str, SignalStatus] = {}

    for signal in signals:
        key = signal.source.value
        current = result.get(key)

        if (
            current is None
            or _STATUS_PRIORITY[signal.status]
            > _STATUS_PRIORITY[current]
        ):
            result[key] = signal.status

    return result


def correlate(
    signals: Iterable[SecuritySignal],
) -> SecurityAssessment:
    signal_tuple = tuple(signals)

    overall_severity = determine_overall_severity(signal_tuple)
    threats = determine_threats(signal_tuple)
    primary_threat = determine_primary_threat(signal_tuple)

    evidence = tuple(
        evidence_item
        for signal in signal_tuple
        for evidence_item in signal.evidence
    )

    component_status = _component_status(signal_tuple)

    corroboration = has_cross_source_corroboration(signal_tuple)

    return SecurityAssessment(
        overall_severity=overall_severity,
        primary_threat=primary_threat,
        threats=threats,
        signals=signal_tuple,
        evidence=evidence,
        component_status=component_status,
        recommended_action=determine_recommended_action(
            overall_severity
        ),
        metadata={
            "policy_version": "default-v0.1",
            "available_signal_count": sum(
                signal.status is SignalStatus.AVAILABLE
                for signal in signal_tuple
            ),
            "cross_source_corroboration": corroboration,
        },
    )
