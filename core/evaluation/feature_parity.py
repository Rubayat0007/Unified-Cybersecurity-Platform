"""Compare candidate and reference flow-feature exports without running detectors."""

from __future__ import annotations

import math
from collections.abc import Mapping
from typing import Any


FEATURE_NAMES = (
    "flow_duration",
    "total_fwd_packets",
    "total_bwd_packets",
    "fwd_packet_length",
    "bwd_packet_length",
    "flow_bytes",
    "flow_packets",
    "flow_rate",
    "packet_rate",
    "avg_packet_size",
    "syn_count",
    "ack_count",
    "rst_count",
    "fin_count",
    "active_time",
    "idle_time",
    "header_length",
    "down_up_ratio",
    "fwd_iat_mean",
    "bwd_iat_mean",
)

_ID_SAMPLE_LIMIT = 100


def _finite_number(value: Any, field_name: str) -> float:
    """Convert a feature value to a finite float, rejecting booleans."""
    if isinstance(value, bool):
        raise ValueError(f"{field_name} must be numeric, not boolean")

    try:
        number = float(value)
    except (TypeError, ValueError, OverflowError) as exc:
        raise ValueError(f"{field_name} must be numeric") from exc

    if not math.isfinite(number):
        raise ValueError(f"{field_name} must be finite")

    return number


def _normalise_records(
    records: Any,
    source_name: str,
    id_column: str,
    errors: list[str],
) -> tuple[dict[str, dict[str, float]], int]:
    """Validate records and normalize their model features."""
    try:
        rows = list(records)
    except TypeError:
        errors.append(f"{source_name} records must be iterable")
        return {}, 0

    if not rows:
        errors.append(f"{source_name} records must not be empty")
        return {}, 0

    normalized: dict[str, dict[str, float]] = {}
    seen_ids: set[str] = set()

    for row_number, row in enumerate(rows, start=1):
        prefix = f"{source_name} row {row_number}"

        if not isinstance(row, Mapping):
            errors.append(f"{prefix} must be a mapping")
            continue

        flow_id_value = row.get(id_column)
        if not isinstance(flow_id_value, str) or not flow_id_value.strip():
            errors.append(
                f"{prefix}.{id_column} must be a non-empty string"
            )
            continue

        flow_id = flow_id_value.strip()

        if flow_id in seen_ids:
            errors.append(
                f"{source_name} contains duplicate {id_column}: {flow_id!r}"
            )
            continue

        seen_ids.add(flow_id)
        feature_values: dict[str, float] = {}
        row_valid = True

        for feature_name in FEATURE_NAMES:
            if feature_name not in row:
                errors.append(
                    f"{prefix} flow_id {flow_id!r} is missing "
                    f"feature {feature_name!r}"
                )
                row_valid = False
                continue

            try:
                feature_values[feature_name] = _finite_number(
                    row[feature_name],
                    feature_name,
                )
            except ValueError as exc:
                errors.append(
                    f"{prefix} flow_id {flow_id!r}: {exc}"
                )
                row_valid = False

        if row_valid:
            normalized[flow_id] = feature_values

    return normalized, len(rows)


def _coerce_tolerance(
    value: Any,
    name: str,
    errors: list[str],
) -> float | None:
    if isinstance(value, bool):
        errors.append(f"{name} must be a finite, non-negative number")
        return None

    try:
        number = float(value)
    except (TypeError, ValueError, OverflowError):
        errors.append(f"{name} must be a finite, non-negative number")
        return None

    if not math.isfinite(number) or number < 0:
        errors.append(f"{name} must be a finite, non-negative number")
        return None

    return number


def _invalid_report(
    errors: list[str],
    reference_count: int = 0,
    candidate_count: int = 0,
    absolute_tolerance: float | None = None,
    relative_tolerance: float | None = None,
) -> dict[str, Any]:
    return {
        "valid": False,
        "equivalent": False,
        "errors": errors,
        "tolerances": {
            "absolute": absolute_tolerance,
            "relative": relative_tolerance,
        },
        "summary": {
            "reference_flow_count": reference_count,
            "candidate_flow_count": candidate_count,
            "matched_flow_count": 0,
            "missing_candidate_flow_count": 0,
            "missing_reference_flow_count": 0,
            "features_compared": len(FEATURE_NAMES),
            "feature_values_compared": 0,
            "feature_mismatch_count": 0,
        },
        "feature_summary": {},
        "mismatches": [],
        "mismatch_examples_truncated": False,
    }


def compare_feature_records(
    reference_records: Any,
    candidate_records: Any,
    *,
    id_column: str = "flow_id",
    abs_tol: float = 1e-6,
    rel_tol: float = 1e-6,
    max_mismatches: int = 100,
) -> dict[str, Any]:
    """Compare all 20 features for records matched by a stable flow ID.

    A structurally valid comparison is not necessarily equivalent. Equivalence
    requires identical flow-ID sets and every feature difference to satisfy:

        abs(reference - candidate)
        <= max(abs_tol, rel_tol * max(abs(reference), abs(candidate)))

    Input provenance and the scientific validity of the flow matching are
    outside this function's scope.
    """
    errors: list[str] = []

    absolute_tolerance = _coerce_tolerance(
        abs_tol, "abs_tol", errors
    )
    relative_tolerance = _coerce_tolerance(
        rel_tol, "rel_tol", errors
    )

    if not isinstance(id_column, str) or not id_column.strip():
        errors.append("id_column must be a non-empty string")

    if (
        isinstance(max_mismatches, bool)
        or not isinstance(max_mismatches, int)
        or max_mismatches < 0
    ):
        errors.append("max_mismatches must be a non-negative integer")

    if errors:
        return _invalid_report(
            errors,
            absolute_tolerance=absolute_tolerance,
            relative_tolerance=relative_tolerance,
        )

    assert absolute_tolerance is not None
    assert relative_tolerance is not None

    reference, reference_count = _normalise_records(
        reference_records,
        "reference",
        id_column,
        errors,
    )
    candidate, candidate_count = _normalise_records(
        candidate_records,
        "candidate",
        id_column,
        errors,
    )

    if errors:
        return _invalid_report(
            errors,
            reference_count,
            candidate_count,
            absolute_tolerance,
            relative_tolerance,
        )

    reference_ids = set(reference)
    candidate_ids = set(candidate)
    matched_ids = sorted(reference_ids & candidate_ids)
    missing_candidate = sorted(reference_ids - candidate_ids)
    missing_reference = sorted(candidate_ids - reference_ids)

    feature_summary: dict[str, Any] = {}
    mismatches: list[dict[str, Any]] = []
    feature_mismatch_count = 0

    for feature_name in FEATURE_NAMES:
        mismatch_count = 0
        maximum_absolute_error = 0.0

        for flow_id in matched_ids:
            reference_value = reference[flow_id][feature_name]
            candidate_value = candidate[flow_id][feature_name]
            absolute_error = abs(reference_value - candidate_value)

            allowed_error = max(
                absolute_tolerance,
                relative_tolerance
                * max(abs(reference_value), abs(candidate_value)),
            )

            maximum_absolute_error = max(
                maximum_absolute_error,
                absolute_error,
            )

            if absolute_error > allowed_error:
                mismatch_count += 1
                feature_mismatch_count += 1

                if len(mismatches) < max_mismatches:
                    mismatches.append({
                        "flow_id": flow_id,
                        "feature": feature_name,
                        "reference_value": reference_value,
                        "candidate_value": candidate_value,
                        "absolute_error": absolute_error,
                        "allowed_error": allowed_error,
                    })

        feature_summary[feature_name] = {
            "compared_values": len(matched_ids),
            "mismatch_count": mismatch_count,
            "max_absolute_error": (
                maximum_absolute_error if matched_ids else None
            ),
        }

    summary = {
        "reference_flow_count": reference_count,
        "candidate_flow_count": candidate_count,
        "matched_flow_count": len(matched_ids),
        "missing_candidate_flow_count": len(missing_candidate),
        "missing_candidate_flow_ids_sample": (
            missing_candidate[:_ID_SAMPLE_LIMIT]
        ),
        "missing_candidate_flow_ids_truncated": (
            len(missing_candidate) > _ID_SAMPLE_LIMIT
        ),
        "missing_reference_flow_count": len(missing_reference),
        "missing_reference_flow_ids_sample": (
            missing_reference[:_ID_SAMPLE_LIMIT]
        ),
        "missing_reference_flow_ids_truncated": (
            len(missing_reference) > _ID_SAMPLE_LIMIT
        ),
        "features_compared": len(FEATURE_NAMES),
        "feature_values_compared": len(matched_ids) * len(FEATURE_NAMES),
        "feature_mismatch_count": feature_mismatch_count,
    }

    equivalent = (
        bool(matched_ids)
        and not missing_candidate
        and not missing_reference
        and feature_mismatch_count == 0
    )

    return {
        "valid": True,
        "equivalent": equivalent,
        "errors": [],
        "tolerances": {
            "absolute": absolute_tolerance,
            "relative": relative_tolerance,
        },
        "summary": summary,
        "feature_summary": feature_summary,
        "mismatches": mismatches,
        "mismatch_examples_truncated": (
            feature_mismatch_count > len(mismatches)
        ),
    }
