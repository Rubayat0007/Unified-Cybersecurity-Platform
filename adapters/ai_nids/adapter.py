from collections.abc import Mapping
from typing import Any

from core.models.enums import (
    Severity,
    SignalSource,
    SignalStatus,
    SignalType,
)
from core.models.signal import SecuritySignal


_AI_NIDS_SEVERITY_MAP = {
    "LOW": Severity.LOW,
    "MEDIUM": Severity.MEDIUM,
    "HIGH": Severity.HIGH,
    "SUSPICIOUS": Severity.SUSPICIOUS,
}


def _require_mapping(value: Any, name: str) -> Mapping[str, Any]:
    if not isinstance(value, Mapping):
        raise TypeError(f"{name} must be a mapping")
    return value


def _finite_number(value: Any, name: str) -> float:
    try:
        result = float(value)
    except (TypeError, ValueError) as exc:
        raise ValueError(f"{name} must be numeric") from exc

    if result != result or result in (float("inf"), float("-inf")):
        raise ValueError(f"{name} must be finite")

    return result


def _map_severity(value: Any) -> Severity | None:
    if value is None:
        return None

    if not isinstance(value, str):
        raise TypeError("AI-NIDS severity must be a string")

    try:
        return _AI_NIDS_SEVERITY_MAP[value.upper()]
    except KeyError as exc:
        raise ValueError(
            f"Unsupported AI-NIDS severity: {value!r}"
        ) from exc


def adapt_result(result: Mapping[str, Any]) -> SecuritySignal:
    """
    Convert an aggregate AI-NIDS detection result into a unified
    SecuritySignal.

    This adapter does not execute AI-NIDS inference. It only translates
    an already-produced detector result into the unified domain model.
    """
    result = _require_mapping(result, "result")

    required = {
        "prediction",
        "confidence",
        "attack_probability",
        "severity",
    }

    missing = required.difference(result)
    if missing:
        raise ValueError(
            f"AI-NIDS result missing required fields: "
            f"{sorted(missing)}"
        )

    prediction = int(result["prediction"])

    if prediction not in {0, 1}:
        raise ValueError("AI-NIDS prediction must be 0 or 1")

    confidence = _finite_number(
        result["confidence"],
        "confidence",
    )

    attack_probability = _finite_number(
        result["attack_probability"],
        "attack_probability",
    )

    if not 0.0 <= confidence <= 1.0:
        raise ValueError("confidence must be between 0 and 1")

    if not 0.0 <= attack_probability <= 1.0:
        raise ValueError(
            "attack_probability must be between 0 and 1"
        )

    severity = _map_severity(result["severity"])

    flows = result.get("flows", [])

    metadata = {
        "prediction": prediction,
        "packet_count": result.get("packet_count"),
        "duration": result.get("duration"),
        "flow_count": len(flows) if isinstance(flows, list) else None,
    }

    return SecuritySignal(
        source=SignalSource.AI_NIDS,
        signal_type=SignalType.NETWORK_INTRUSION,
        status=SignalStatus.AVAILABLE,
        raw_score=attack_probability,
        raw_score_semantics="attack_probability",
        normalized_score=attack_probability * 100.0,
        confidence=confidence,
        severity=severity,
        metadata=metadata,
    )