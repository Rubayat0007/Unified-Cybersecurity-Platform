"""Compare reference and candidate AI-NIDS flow-feature CSV exports."""

from __future__ import annotations

import argparse
import csv
import json
from pathlib import Path
import sys

PROJECT_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(PROJECT_ROOT))

from core.evaluation.feature_parity import (
    FEATURE_NAMES,
    compare_feature_records,
)


def load_feature_csv(path: Path, id_column: str) -> tuple[list[dict], list[str]]:
    """Load a CSV with a stable flow ID and all canonical model features."""
    with path.open("r", encoding="utf-8-sig", newline="") as handle:
        reader = csv.reader(handle, strict=True)

        try:
            headers = next(reader)
        except StopIteration as exc:
            raise ValueError("CSV is empty or has no header") from exc

        if not headers or any(not name.strip() for name in headers):
            raise ValueError("CSV headers must be non-empty")

        if len(headers) != len(set(headers)):
            raise ValueError("CSV contains duplicate column names")

        required = {id_column, *FEATURE_NAMES}
        missing = sorted(required - set(headers))
        if missing:
            raise ValueError(
                f"CSV is missing required columns: {missing}"
            )

        records = []
        for line_number, values in enumerate(reader, start=2):
            if not values:
                continue

            if len(values) != len(headers):
                raise ValueError(
                    f"CSV row {line_number} has {len(values)} fields; "
                    f"expected {len(headers)}"
                )

            records.append(dict(zip(headers, values)))

    return records, headers


def main() -> int:
    parser = argparse.ArgumentParser(
        description=(
            "Compare two flow-feature CSV exports. This tool does not run "
            "detectors or establish the provenance of reference records."
        )
    )
    parser.add_argument("reference", type=Path)
    parser.add_argument("candidate", type=Path)
    parser.add_argument("--id-column", default="flow_id")
    parser.add_argument("--abs-tol", type=float, default=1e-6)
    parser.add_argument("--rel-tol", type=float, default=1e-6)
    parser.add_argument("--max-mismatches", type=int, default=100)
    parser.add_argument("--json-output", type=Path)
    args = parser.parse_args()

    try:
        reference_records, reference_headers = load_feature_csv(
            args.reference, args.id_column
        )
        candidate_records, candidate_headers = load_feature_csv(
            args.candidate, args.id_column
        )
    except (OSError, UnicodeError, csv.Error, ValueError) as exc:
        print(f"Cannot read feature CSV: {exc}", file=sys.stderr)
        return 2

    result = compare_feature_records(
        reference_records,
        candidate_records,
        id_column=args.id_column,
        abs_tol=args.abs_tol,
        rel_tol=args.rel_tol,
        max_mismatches=args.max_mismatches,
    )

    required_columns = {args.id_column, *FEATURE_NAMES}
    report = {
        "reference_file": args.reference.name,
        "candidate_file": args.candidate.name,
        "ignored_extra_columns": {
            "reference": sorted(set(reference_headers) - required_columns),
            "candidate": sorted(set(candidate_headers) - required_columns),
        },
        **result,
        "interpretation": (
            "Equivalence only describes the supplied records, flow IDs, "
            "and tolerances. It does not verify reference provenance, prove "
            "that IDs link the same real flows, or establish equivalence "
            "with the CICIDS2017 training pipeline."
        ),
    }

    output_text = json.dumps(report, indent=2, sort_keys=True)

    if args.json_output:
        try:
            args.json_output.parent.mkdir(parents=True, exist_ok=True)
            args.json_output.write_text(
                output_text + "\n", encoding="utf-8"
            )
        except OSError as exc:
            print(f"Cannot write report: {exc}", file=sys.stderr)
            return 2

    print(json.dumps(result["summary"], indent=2, sort_keys=True))

    if not result["valid"]:
        print("Feature comparison: INVALID")
        for error in result["errors"]:
            print(f"- {error}")
        if args.json_output:
            print(f"Report: {args.json_output}")
        return 1

    if not result["equivalent"]:
        print("Feature comparison: FAIL")
        print("Flow-ID coverage or feature values differ.")
        for mismatch in result["mismatches"]:
            print(
                f"- flow_id={mismatch['flow_id']}, "
                f"feature={mismatch['feature']}, "
                f"reference={mismatch['reference_value']}, "
                f"candidate={mismatch['candidate_value']}, "
                f"absolute_error={mismatch['absolute_error']}"
            )
        if result["mismatch_examples_truncated"]:
            print("Additional feature mismatches were omitted.")
        if args.json_output:
            print(f"Report: {args.json_output}")
        return 1

    print("Feature comparison: PASS")
    print(
        "Reminder: numerical equivalence on these records does not "
        "establish reference provenance or training-pipeline parity."
    )
    if args.json_output:
        print(f"Report: {args.json_output}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
