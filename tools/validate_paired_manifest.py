"""Validate a paired-event evaluation manifest without loading model artifacts."""

from __future__ import annotations

import argparse
import json
from pathlib import Path
import sys

PROJECT_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(PROJECT_ROOT))

from core.evaluation.paired_manifest import validate_paired_manifest


def main() -> int:
    parser = argparse.ArgumentParser(
        description=(
            "Validate a paired, labeled AI-NIDS/PhishVision evaluation manifest. "
            "This validates structure and split hygiene, not the truth of pairing claims."
        )
    )
    parser.add_argument("manifest", type=Path, help="Path to a JSON manifest")
    parser.add_argument("--json-output", type=Path, help="Optional path to save validation JSON")
    args = parser.parse_args()

    try:
        with args.manifest.open("r", encoding="utf-8-sig") as handle:
            payload = json.load(handle)
    except (OSError, json.JSONDecodeError) as exc:
        print(f"Cannot read manifest: {exc}", file=sys.stderr)
        return 2

    result = validate_paired_manifest(payload)
    report = {
        "manifest_file": args.manifest.name,
        **result,
        "interpretation": (
            "Structural validation cannot establish that source records truly belong to the same event. "
            "Pairing references and labels require independent verification."
        ),
    }

    output_text = json.dumps(report, indent=2, sort_keys=True)
    if args.json_output:
        try:
            args.json_output.parent.mkdir(parents=True, exist_ok=True)
            args.json_output.write_text(output_text + "\n", encoding="utf-8")
        except OSError as exc:
            print(f"Cannot write report: {exc}", file=sys.stderr)
            return 2

    print(json.dumps(result["summary"], indent=2, sort_keys=True))
    if result["valid"]:
        print("Manifest validation: PASS")
        print("Reminder: human verification of pairing and adjudication is still required.")
        if args.json_output:
            print(f"Report: {args.json_output}")
        return 0

    print("Manifest validation: FAIL")
    for error in result["errors"]:
        print(f"- {error}")
    if args.json_output:
        print(f"Report: {args.json_output}")
    return 1


if __name__ == "__main__":
    raise SystemExit(main())
