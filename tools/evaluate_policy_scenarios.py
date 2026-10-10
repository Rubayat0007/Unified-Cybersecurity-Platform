"""Evaluate labeled scenarios against the unified platform's current policy."""
from __future__ import annotations

import argparse
import csv
import hashlib
import json
import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

PROJECT_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(PROJECT_ROOT))

from core.evaluation.policy_scenarios import evaluate_scenarios  # noqa: E402

DEFAULT_INPUT = PROJECT_ROOT / "fixtures" / "evaluation" / "policy_scenarios.json"


def _sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _scenarios_from_document(document: Any) -> list[Any]:
    """Validate the scenario document's version and scenario-list shape."""
    if (
        not isinstance(document, dict)
        or type(document.get("schema_version")) is not int
        or document.get("schema_version") != 1
    ):
        raise ValueError("Scenario file must be an object with integer schema_version: 1")
    scenarios = document.get("scenarios")
    if not isinstance(scenarios, list):
        raise ValueError("Scenario file must contain a 'scenarios' list")
    return scenarios


def _write_reports(report: dict[str, Any], output_dir: Path) -> None:
    output_dir.mkdir(parents=True, exist_ok=True)
    json_path = output_dir / "policy_scenario_summary.json"
    csv_path = output_dir / "policy_scenario_results.csv"
    if json_path.exists() or csv_path.exists():
        raise FileExistsError(
            f"Report output already exists in {output_dir}; choose another directory."
        )

    json_path.write_text(
        json.dumps(report, indent=2, sort_keys=True) + "\n", encoding="utf-8"
    )
    with csv_path.open("w", encoding="utf-8", newline="") as handle:
        writer = csv.DictWriter(
            handle,
            fieldnames=["id", "name", "passed", "expected_json", "actual_json", "error"],
        )
        writer.writeheader()
        for result in report["results"]:
            writer.writerow(
                {
                    "id": result["id"],
                    "name": result["name"],
                    "passed": result["passed"],
                    "expected_json": json.dumps(result["expected"], sort_keys=True),
                    "actual_json": json.dumps(result["actual"], sort_keys=True)
                    if result["actual"] is not None else "",
                    "error": result["error"] or "",
                }
            )


def main() -> int:
    parser = argparse.ArgumentParser(
        description=(
            "Evaluate synthetic scenarios against the current correlation and "
            "operational decision rules. This does not evaluate detector accuracy."
        )
    )
    parser.add_argument(
        "--input", type=Path, default=DEFAULT_INPUT,
        help=f"Scenario JSON path (default: {DEFAULT_INPUT})",
    )
    parser.add_argument(
        "--output-dir", type=Path,
        help="Optional new report directory; existing report files are never overwritten.",
    )
    args = parser.parse_args()

    try:
        input_path = args.input.resolve()
        with input_path.open("r", encoding="utf-8-sig") as handle:
            document = json.load(handle)
        scenarios = _scenarios_from_document(document)

        report = evaluate_scenarios(scenarios)
        report.update(
            {
                "generated_at_utc": datetime.now(timezone.utc).isoformat(),
                "input_file_name": input_path.name,
                "input_file_sha256": _sha256(input_path),
            }
        )
        print(
            f"Policy scenario evaluation: {report['passed_count']}/"
            f"{report['scenario_count']} passed; {report['failed_count']} failed"
        )
        for result in report["results"]:
            marker = "PASS" if result["passed"] else "FAIL"
            print(f"[{marker}] {result['id']}: {result['name']}")
            if result["error"]:
                print(f"       Error: {result['error']}")
            for field, mismatch in result["mismatches"].items():
                print(
                    f"       {field}: expected={mismatch['expected']!r}, "
                    f"actual={mismatch['actual']!r}"
                )

        if args.output_dir:
            _write_reports(report, args.output_dir.resolve())
            print(f"Reports: {args.output_dir.resolve()}")
        print(
            "Interpretation: scenario pass rate is policy-contract coverage, "
            "not real-world detection accuracy."
        )
        return 0 if report["failed_count"] == 0 else 1
    except (OSError, json.JSONDecodeError, ValueError, FileExistsError) as exc:
        print(f"ERROR: {exc}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
