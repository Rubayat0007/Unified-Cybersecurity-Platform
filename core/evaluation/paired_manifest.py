"""Validation helpers for paired, labeled detector-event evaluation manifests.

Only the Python standard library is used. Validation does not load detector
models or assert that event pairing is scientifically valid; the pairing
reference and adjudication evidence still require human review.
"""

from __future__ import annotations

from collections import Counter, defaultdict
from datetime import datetime, timedelta
import re
from typing import Any


_SPLITS = {"train", "validation", "test"}
_INCIDENT_TYPES = {
    "benign",
    "network_intrusion",
    "phishing",
    "multi_stage",
    "other",
}
_PAIRING_METHODS = {
    "shared_incident_id",
    "shared_transaction_id",
    "analyst_adjudication",
    "verified_time_window",
}
_SHA256_RE = re.compile(r"^[0-9a-fA-F]{64}$")
# Require RFC3339-shaped timestamps and a literal UTC marker. datetime.fromisoformat()
# alone is more permissive (e.g. it accepts a space separator and offset seconds).
_UTC_DATETIME_RE = re.compile(
    r"[0-9]{4}-[0-9]{2}-[0-9]{2}T"
    r"(?:[01][0-9]|2[0-3]):[0-5][0-9]:[0-5][0-9]"
    r"(?:\.[0-9]+)?(?:Z|\+00:00)"
)
_SOURCE_NAMES = ("ai_nids", "phishvision")

_TOP_LEVEL_FIELDS = {
    "schema_version", "manifest_id", "purpose", "fusion_target", "events"
}
_FUSION_TARGET_FIELDS = {"name", "positive_class_meaning", "label_definition"}
_EVENT_FIELDS = {
    "event_id", "group_id", "split", "event_time_utc", "pairing_basis",
    "event_label", "sources",
}
_PAIRING_FIELDS = {"method", "reference"}
_EVENT_LABEL_FIELDS = {"security_incident", "incident_type", "adjudication_source"}
_SOURCE_RECORD_FIELDS = {
    "record_id", "input_sha256", "model_sha256", "true_label",
    "predicted_label", "score", "score_semantics", "decision_threshold",
    "prediction_timestamp_utc",
}


def _is_nonempty_string(value: Any) -> bool:
    return isinstance(value, str) and bool(value.strip())


def _reject_unknown_fields(
    value: dict[str, Any],
    allowed_fields: set[str],
    prefix: str,
    errors: list[str],
) -> None:
    """Mirror JSON Schema ``additionalProperties: false`` checks."""
    extras = [key for key in value if key not in allowed_fields]
    if extras:
        errors.append(
            f"{prefix} has unsupported fields: {sorted(str(key) for key in extras)}"
        )


def _is_binary_integer(value: Any) -> bool:
    return type(value) is int and value in (0, 1)


def _is_unit_interval_number(value: Any) -> bool:
    return (
        isinstance(value, (int, float))
        and not isinstance(value, bool)
        and 0.0 <= float(value) <= 1.0
    )


def _is_timezone_aware_utc_iso_datetime(value: Any) -> bool:
    """Accept RFC3339-shaped timestamps with a zero UTC offset (Z or +00:00)."""
    if not isinstance(value, str) or _UTC_DATETIME_RE.fullmatch(value) is None:
        return False
    normalized = value[:-1] + "+00:00" if value.endswith("Z") else value
    try:
        parsed = datetime.fromisoformat(normalized)
    except ValueError:
        return False
    return parsed.tzinfo is not None and parsed.utcoffset() == timedelta(0)


def validate_paired_manifest(payload: Any) -> dict[str, Any]:
    """Return ``valid``, ``errors`` and split/class-count summary for payload.

    In addition to type/range checks, this validator rejects unknown fields so
    its accepted manifest shape matches the checked-in JSON Schema. Fields
    named ``*_utc`` must carry a zero UTC offset. Structural validation cannot
    prove the truth of pairing claims or adjudicated labels.
    """
    errors: list[str] = []
    if not isinstance(payload, dict):
        return {
            "valid": False,
            "errors": ["manifest must be a JSON object"],
            "summary": {},
        }

    _reject_unknown_fields(payload, _TOP_LEVEL_FIELDS, "manifest", errors)

    for field in (
        "schema_version", "manifest_id", "purpose", "fusion_target", "events"
    ):
        if field not in payload:
            errors.append(f"missing top-level field: {field}")

    if type(payload.get("schema_version")) is not int or payload.get("schema_version") != 1:
        errors.append("schema_version must equal integer 1")
    if not _is_nonempty_string(payload.get("manifest_id")):
        errors.append("manifest_id must be a non-empty string")
    if payload.get("purpose") != "paired_fusion_evaluation":
        errors.append("purpose must be 'paired_fusion_evaluation'")

    target = payload.get("fusion_target")
    if not isinstance(target, dict):
        errors.append("fusion_target must be an object")
    else:
        _reject_unknown_fields(target, _FUSION_TARGET_FIELDS, "fusion_target", errors)
        for field in ("name", "positive_class_meaning", "label_definition"):
            if not _is_nonempty_string(target.get(field)):
                errors.append(f"fusion_target.{field} must be a non-empty string")

    events = payload.get("events")
    if not isinstance(events, list) or not events:
        errors.append("events must be a non-empty array")
        events = []

    event_ids: set[str] = set()
    records_by_source: dict[str, set[str]] = {name: set() for name in _SOURCE_NAMES}
    group_splits: dict[str, set[str]] = defaultdict(set)
    split_counts: Counter[str] = Counter()
    positive_counts: Counter[str] = Counter()
    source_record_counts: Counter[str] = Counter()

    for index, event in enumerate(events):
        prefix = f"events[{index}]"
        if not isinstance(event, dict):
            errors.append(f"{prefix} must be an object")
            continue

        _reject_unknown_fields(event, _EVENT_FIELDS, prefix, errors)
        for field in (
            "event_id", "group_id", "split", "event_time_utc", "pairing_basis",
            "event_label", "sources",
        ):
            if field not in event:
                errors.append(f"{prefix} missing field: {field}")

        event_id = event.get("event_id")
        if not _is_nonempty_string(event_id):
            errors.append(f"{prefix}.event_id must be a non-empty string")
        elif event_id in event_ids:
            errors.append(f"duplicate event_id: {event_id}")
        else:
            event_ids.add(event_id)

        group_id = event.get("group_id")
        if not _is_nonempty_string(group_id):
            errors.append(f"{prefix}.group_id must be a non-empty string")

        split = event.get("split")
        if not isinstance(split, str) or split not in _SPLITS:
            errors.append(f"{prefix}.split must be one of {sorted(_SPLITS)}")
        else:
            split_counts[split] += 1
            if _is_nonempty_string(group_id):
                group_splits[group_id].add(split)

        if not _is_timezone_aware_utc_iso_datetime(event.get("event_time_utc")):
            errors.append(
                f"{prefix}.event_time_utc must be an ISO-8601 UTC datetime "
                "with zero offset (Z or +00:00)"
            )

        pairing = event.get("pairing_basis")
        if not isinstance(pairing, dict):
            errors.append(f"{prefix}.pairing_basis must be an object")
        else:
            _reject_unknown_fields(pairing, _PAIRING_FIELDS, f"{prefix}.pairing_basis", errors)
            method = pairing.get("method")
            if not isinstance(method, str) or method not in _PAIRING_METHODS:
                errors.append(
                    f"{prefix}.pairing_basis.method must be one of {sorted(_PAIRING_METHODS)}"
                )
            if not _is_nonempty_string(pairing.get("reference")):
                errors.append(f"{prefix}.pairing_basis.reference must be a non-empty string")

        label = event.get("event_label")
        if not isinstance(label, dict):
            errors.append(f"{prefix}.event_label must be an object")
        else:
            _reject_unknown_fields(label, _EVENT_LABEL_FIELDS, f"{prefix}.event_label", errors)
            if type(label.get("security_incident")) is not bool:
                errors.append(f"{prefix}.event_label.security_incident must be boolean")
            elif isinstance(split, str) and split in _SPLITS:
                positive_counts[f"{split}:{int(label['security_incident'])}"] += 1
            incident_type = label.get("incident_type")
            if not isinstance(incident_type, str) or incident_type not in _INCIDENT_TYPES:
                errors.append(
                    f"{prefix}.event_label.incident_type must be one of {sorted(_INCIDENT_TYPES)}"
                )
            if not _is_nonempty_string(label.get("adjudication_source")):
                errors.append(f"{prefix}.event_label.adjudication_source must be a non-empty string")

        sources = event.get("sources")
        if not isinstance(sources, dict):
            errors.append(f"{prefix}.sources must be an object")
            continue

        missing_sources = set(_SOURCE_NAMES) - set(sources)
        extra_sources = set(sources) - set(_SOURCE_NAMES)
        if missing_sources:
            errors.append(f"{prefix}.sources missing: {sorted(missing_sources)}")
        if extra_sources:
            errors.append(f"{prefix}.sources has unsupported keys: {sorted(str(key) for key in extra_sources)}")

        for source_name in _SOURCE_NAMES:
            record = sources.get(source_name)
            record_prefix = f"{prefix}.sources.{source_name}"
            if not isinstance(record, dict):
                errors.append(f"{record_prefix} must be an object")
                continue

            _reject_unknown_fields(record, _SOURCE_RECORD_FIELDS, record_prefix, errors)
            for field in (
                "record_id", "input_sha256", "model_sha256", "true_label",
                "predicted_label", "score", "score_semantics",
            ):
                if field not in record:
                    errors.append(f"{record_prefix} missing field: {field}")

            record_id = record.get("record_id")
            if not _is_nonempty_string(record_id):
                errors.append(f"{record_prefix}.record_id must be a non-empty string")
            elif record_id in records_by_source[source_name]:
                errors.append(f"duplicate {source_name} record_id: {record_id}")
            else:
                records_by_source[source_name].add(record_id)
                source_record_counts[source_name] += 1

            for hash_field in ("input_sha256", "model_sha256"):
                hash_value = record.get(hash_field)
                if not isinstance(hash_value, str) or not _SHA256_RE.fullmatch(hash_value):
                    errors.append(
                        f"{record_prefix}.{hash_field} must be a 64-character SHA-256 hex string"
                    )

            for label_field in ("true_label", "predicted_label"):
                if not _is_binary_integer(record.get(label_field)):
                    errors.append(f"{record_prefix}.{label_field} must be integer 0 or 1")

            if not _is_unit_interval_number(record.get("score")):
                errors.append(f"{record_prefix}.score must be a number in [0, 1]")
            if not _is_nonempty_string(record.get("score_semantics")):
                errors.append(f"{record_prefix}.score_semantics must be a non-empty string")

            if "decision_threshold" in record and not _is_unit_interval_number(record["decision_threshold"]):
                errors.append(f"{record_prefix}.decision_threshold must be a number in [0, 1]")

            if "prediction_timestamp_utc" in record and not _is_timezone_aware_utc_iso_datetime(record["prediction_timestamp_utc"]):
                errors.append(
                    f"{record_prefix}.prediction_timestamp_utc must be an ISO-8601 UTC datetime "
                    "with zero offset (Z or +00:00)"
                )

    for group_id, splits in sorted(group_splits.items()):
        if len(splits) > 1:
            errors.append(f"group_id {group_id!r} appears across splits: {sorted(splits)}")

    summary = {
        "event_count": len(events),
        "split_counts": dict(sorted(split_counts.items())),
        "event_label_counts": dict(sorted(positive_counts.items())),
        "source_record_counts": dict(sorted(source_record_counts.items())),
        "distinct_group_count": len(group_splits),
    }
    return {"valid": not errors, "errors": errors, "summary": summary}
