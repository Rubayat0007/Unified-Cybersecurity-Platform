from collections.abc import Iterable

from core.models.enums import (
    RecommendedAction,
    Severity,
    SignalStatus,
)
from core.models.signal import SecuritySignal


_SEVERITY_RANK = {
    Severity.UNKNOWN: 0,
    Severity.MINIMAL: 1,
    Severity.LOW: 2,
    Severity.SUSPICIOUS: 3,
    Severity.MEDIUM: 4,
    Severity.HIGH: 5,
    Severity.CRITICAL: 6,
}

_THREAT_SEVERITIES = {
    Severity.SUSPICIOUS,
    Severity.MEDIUM,
    Severity.HIGH,
    Severity.CRITICAL,
}


def available_signals(
    signals: Iterable[SecuritySignal],
) -> tuple[SecuritySignal, ...]:
    return tuple(
        signal
        for signal in signals
        if signal.status is SignalStatus.AVAILABLE
    )


def determine_overall_severity(
    signals: Iterable[SecuritySignal],
) -> Severity:
    available = available_signals(signals)

    severities = [
        signal.severity
        for signal in available
        if signal.severity is not None
    ]

    if not severities:
        return Severity.UNKNOWN

    return max(
        severities,
        key=lambda severity: _SEVERITY_RANK[severity],
    )


def determine_threats(
    signals: Iterable[SecuritySignal],
) -> tuple[str, ...]:
    threats = {
        signal.signal_type.value
        for signal in available_signals(signals)
        if signal.severity in _THREAT_SEVERITIES
    }

    return tuple(sorted(threats))


def determine_primary_threat(
    signals: Iterable[SecuritySignal],
) -> str | None:
    candidates = [
        signal
        for signal in available_signals(signals)
        if signal.severity in _THREAT_SEVERITIES
    ]

    if not candidates:
        return None

    selected = min(
        candidates,
        key=lambda signal: (
            -_SEVERITY_RANK[signal.severity],
            signal.signal_type.value,
            signal.source.value,
        ),
    )

    return selected.signal_type.value


def determine_recommended_action(
    severity: Severity,
) -> RecommendedAction:
    if severity is Severity.CRITICAL:
        return RecommendedAction.INVESTIGATE

    if severity is Severity.HIGH:
        return RecommendedAction.INVESTIGATE

    if severity in {
        Severity.SUSPICIOUS,
        Severity.MEDIUM,
    }:
        return RecommendedAction.WARN

    if severity is Severity.LOW:
        return RecommendedAction.MONITOR

    if severity is Severity.MINIMAL:
        return RecommendedAction.ALLOW

    return RecommendedAction.INVESTIGATE


def has_cross_source_corroboration(
    signals: Iterable[SecuritySignal],
) -> bool:
    sources = {
        signal.source.value
        for signal in available_signals(signals)
        if signal.severity in _THREAT_SEVERITIES
    }

    return len(sources) >= 2
