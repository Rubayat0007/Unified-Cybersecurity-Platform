"""Run contract scenarios against the platform's existing rules policy.

These scenarios test policy behavior, not detector quality or real-world accuracy.
"""
from __future__ import annotations

from collections.abc import Mapping, Sequence
from typing import Any

from core.correlation.engine import correlate
from core.decision.engine import decide
from core.models.enums import (
    RecommendedAction,
    Severity,
    SignalSource,
    SignalStatus,
    SignalType,
)
from core.models.signal import SecuritySignal

_EXPECTED_FIELDS = {
    "overall_severity",
    "action",
    "primary_threat",
    "requires_human_review",
    "cross_source_corroboration",
    "available_signal_count",
    "threats",
}


def _enum(enum_type: type, value: Any, field_name: str) -> Any:
    try:
        return enum_type(value)
    except (TypeError, ValueError) as exc:
        choices = ", ".join(item.value for item in enum_type)
        raise ValueError(
            f"Unsupported {field_name} {value!r}; expected one of: {choices}"
        ) from exc


def _build_signal(raw: Mapping[str, Any], scenario_id: str) -> SecuritySignal:
    if not isinstance(raw, Mapping):
        raise ValueError(f"Scenario {scenario_id}: each signal must be an object")

    required = {"source", "signal_type", "status"}
    missing = required.difference(raw)
    if missing:
        raise ValueError(
            f"Scenario {scenario_id}: signal missing fields {sorted(missing)}"
        )

    severity_raw = raw.get("severity")
    severity = (
        None
        if severity_raw is None
        else _enum(Severity, severity_raw, "severity")
    )
    return SecuritySignal(
        source=_enum(SignalSource, raw["source"], "source"),
        signal_type=_enum(SignalType, raw["signal_type"], "signal_type"),
        status=_enum(SignalStatus, raw["status"], "status"),
        severity=severity,
        metadata=dict(raw.get("metadata", {})),
    )


def run_scenario(scenario: Mapping[str, Any]) -> dict[str, Any]:
    """Evaluate one scenario and compare actual policy outputs to expectations.

    Invalid scenario definitions are returned as failed rows so a report can
    show the bad case rather than silently dropping it.
    """
    scenario_id = scenario.get("id") if isinstance(scenario, Mapping) else None
    name = scenario.get("name") if isinstance(scenario, Mapping) else None
    expected = scenario.get("expected") if isinstance(scenario, Mapping) else None

    try:
        if not isinstance(scenario, Mapping):
            raise ValueError("Each scenario must be an object")
        if not isinstance(scenario_id, str) or not scenario_id.strip():
            raise ValueError("Scenario id must be a non-empty string")
        if not isinstance(name, str) or not name.strip():
            raise ValueError(f"Scenario {scenario_id}: name must be a non-empty string")

        signals_raw = scenario.get("signals")
        if not isinstance(signals_raw, list):
            raise ValueError(f"Scenario {scenario_id}: signals must be a list")
        if not isinstance(expected, Mapping) or not expected:
            raise ValueError(f"Scenario {scenario_id}: expected must be a non-empty object")

        unexpected = set(expected).difference(_EXPECTED_FIELDS)
        if unexpected:
            raise ValueError(
                f"Scenario {scenario_id}: unsupported expected fields {sorted(unexpected)}"
            )

        signals = tuple(_build_signal(signal, scenario_id) for signal in signals_raw)
        assessment = correlate(signals)
        operational_decision = decide(assessment)
        actual = {
            "overall_severity": assessment.overall_severity.value,
            "action": operational_decision.action.value,
            "primary_threat": operational_decision.primary_threat,
            "requires_human_review": operational_decision.requires_human_review,
            "cross_source_corroboration": bool(
                assessment.metadata.get("cross_source_corroboration", False)
            ),
            "available_signal_count": int(
                assessment.metadata.get("available_signal_count", 0)
            ),
            "threats": list(assessment.threats),
        }
        mismatches = {
            field: {"expected": expected[field], "actual": actual[field]}
            for field in expected
            if expected[field] != actual[field]
        }
        return {
            "id": scenario_id,
            "name": name,
            "passed": not mismatches,
            "expected": dict(expected),
            "actual": actual,
            "mismatches": mismatches,
            "error": None,
        }
    except Exception as exc:  # Keep malformed cases visible in the report.
        return {
            "id": scenario_id if isinstance(scenario_id, str) else "<invalid-scenario>",
            "name": name if isinstance(name, str) else "Invalid scenario definition",
            "passed": False,
            "expected": dict(expected) if isinstance(expected, Mapping) else {},
            "actual": None,
            "mismatches": {},
            "error": f"{type(exc).__name__}: {exc}",
        }


def evaluate_scenarios(scenarios: Sequence[Mapping[str, Any]]) -> dict[str, Any]:
    """Return per-scenario results and a contract pass rate."""
    if not scenarios:
        raise ValueError("At least one policy scenario is required")

    results = [run_scenario(scenario) for scenario in scenarios]
    passed = sum(bool(result["passed"]) for result in results)
    total = len(results)
    return {
        "schema_version": 1,
        "evaluation_type": "rules_policy_contract_scenarios",
        "scenario_count": total,
        "passed_count": passed,
        "failed_count": total - passed,
        "pass_rate": passed / total,
        "interpretation": (
            "Pass rate measures agreement with declared policy-contract outcomes; "
            "it is not real-world detection accuracy or evidence of fusion efficacy."
        ),
        "results": results,
    }
