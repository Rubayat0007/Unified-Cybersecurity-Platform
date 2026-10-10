#!/usr/bin/env python3
"""Evaluate a CSV of binary labels/predictions and optionally probability scores.

Examples from the unified repository root:
  python tools/evaluate_predictions.py results/evaluation_predictions.csv \
      --output-dir reports/evaluation/nids-saved-2000
  python tools/evaluate_predictions.py "C:/path/to/v2_test_probs_035.csv" \
      --actual-column true_label --predicted-column predicted_label \
      --score-column p_phish --threshold 0.35 \
      --positive-name phishing --output-dir reports/evaluation/phishvision-v2-035

This tool reads prediction files only; it does not load, train, or change models.
Class 1 is always the positive class. Scores must be probabilities in [0, 1].
"""

from __future__ import annotations

import argparse
import csv
import hashlib
import json
import math
import platform
import sys
from collections import Counter
from datetime import datetime, timezone
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parents[1]
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from core.evaluation.metrics import evaluate_binary, roc_curve_points  # noqa: E402


def file_sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def read_binary(value: str, column: str, row_number: int) -> int:
    try:
        number = int(value.strip())
    except (AttributeError, ValueError) as exc:
        raise ValueError(
            f"Row {row_number}: column {column!r} must contain 0 or 1; got {value!r}"
        ) from exc
    if number not in (0, 1) or value.strip() not in ("0", "1"):
        raise ValueError(
            f"Row {row_number}: column {column!r} must contain 0 or 1; got {value!r}"
        )
    return number


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("input_csv", type=Path, help="CSV file containing existing predictions")
    parser.add_argument("--output-dir", type=Path, required=True, help="Directory for generated reports")
    parser.add_argument("--actual-column", default="actual", help="Ground-truth column (default: actual)")
    parser.add_argument("--predicted-column", default="predicted", help="Stored prediction column (default: predicted)")
    parser.add_argument("--score-column", help="Optional probability column; higher scores mean class 1")
    parser.add_argument("--threshold", type=float, help="Explicit probability threshold; requires --score-column")
    parser.add_argument("--positive-name", default="positive", help="Readable name for class 1")
    parser.add_argument("--run-label", default="", help="Optional descriptive label recorded in the JSON report")
    parser.add_argument("--overwrite", action="store_true", help="Allow replacing existing output report files")
    args = parser.parse_args()

    if args.threshold is not None:
        if args.score_column is None:
            parser.error("--threshold requires --score-column")
        if not 0.0 <= args.threshold <= 1.0:
            parser.error("--threshold must be between 0 and 1")
    return args


def main() -> int:
    args = parse_args()
    input_path = args.input_csv.expanduser().resolve()
    output_dir = args.output_dir.expanduser().resolve()
    if not input_path.is_file():
        print(f"ERROR: input CSV not found: {input_path}", file=sys.stderr)
        return 2

    output_names = ["summary.json", "per_class_metrics.csv"]
    if args.score_column:
        output_names.append("roc_curve.csv")
    if not args.overwrite:
        existing = [str(output_dir / name) for name in output_names if (output_dir / name).exists()]
        if existing:
            print("ERROR: output files already exist; choose a new --output-dir or use --overwrite:", file=sys.stderr)
            for item in existing:
                print(f"  {item}", file=sys.stderr)
            return 2

    actual: list[int] = []
    stored_predictions: list[int] = []
    scores: list[float] = []
    stored_prediction_available = True

    with input_path.open("r", encoding="utf-8-sig", newline="") as stream:
        reader = csv.DictReader(stream)
        if not reader.fieldnames:
            raise ValueError("Input CSV is empty or lacks a header row.")
        required = {args.actual_column}
        if args.threshold is None:
            required.add(args.predicted_column)
        if args.score_column:
            required.add(args.score_column)
        missing = sorted(required - set(reader.fieldnames))
        if missing:
            raise ValueError(f"Input CSV is missing required columns: {missing}")
        stored_prediction_available = args.predicted_column in reader.fieldnames

        for row_number, row in enumerate(reader, start=2):
            actual.append(read_binary(row.get(args.actual_column, ""), args.actual_column, row_number))
            if stored_prediction_available and row.get(args.predicted_column, "").strip() != "":
                stored_predictions.append(
                    read_binary(row[args.predicted_column], args.predicted_column, row_number)
                )
            elif args.threshold is None:
                raise ValueError(
                    f"Row {row_number}: missing prediction in {args.predicted_column!r}"
                )
            if args.score_column:
                raw_score = row.get(args.score_column, "")
                try:
                    score = float(raw_score)
                except (TypeError, ValueError) as exc:
                    raise ValueError(
                        f"Row {row_number}: score column {args.score_column!r} must be numeric; got {raw_score!r}"
                    ) from exc
                if not math.isfinite(score) or not 0.0 <= score <= 1.0:
                    raise ValueError(
                        f"Row {row_number}: score {score!r} must be finite and within [0, 1]"
                    )
                scores.append(score)

    if not actual:
        raise ValueError("Input CSV contains no data rows.")
    if stored_prediction_available and stored_predictions and len(stored_predictions) != len(actual):
        raise ValueError("Stored prediction column has missing values in one or more rows.")

    if args.threshold is not None:
        predicted = [int(score >= args.threshold) for score in scores]
        prediction_source = "score_threshold"
    else:
        predicted = stored_predictions
        prediction_source = "stored_prediction_column"

    metrics = evaluate_binary(actual, predicted)
    roc = roc_curve_points(actual, scores) if args.score_column else None
    if roc is not None:
        metrics["roc_auc"] = roc["auc"]

    agreement = None
    # Agreement is informative only when predictions were independently derived
    # from scores. Comparing the stored column with itself is tautological.
    if (
        prediction_source == "score_threshold"
        and stored_prediction_available
        and stored_predictions
        and len(stored_predictions) == len(actual)
    ):
        mismatches = sum(a != b for a, b in zip(stored_predictions, predicted))
        agreement = {
            "stored_prediction_column": args.predicted_column,
            "compared_with": prediction_source,
            "mismatch_count": mismatches,
            "agreement_count": len(actual) - mismatches,
            "agreement_rate": (len(actual) - mismatches) / len(actual),
        }

    label_counts = Counter(actual)
    summary = {
        "schema_version": 1,
        "run_label": args.run_label,
        "generated_at_utc": datetime.now(timezone.utc).isoformat(),
        "input_file_name": input_path.name,
        "input_file_sha256": file_sha256(input_path),
        "input_row_count": len(actual),
        "python_version": platform.python_version(),
        "label_columns": {"actual": args.actual_column, "predicted": args.predicted_column},
        "score_column": args.score_column,
        "positive_class": {"value": 1, "name": args.positive_name},
        "prediction_source": prediction_source,
        "threshold": args.threshold,
        "class_counts": {"0": label_counts.get(0, 0), "1": label_counts.get(1, 0)},
        "stored_prediction_agreement": agreement,
        "metrics": metrics,
        "roc_auc_note": (
            "Calculated from the supplied score column; higher scores indicate class 1."
            if roc is not None else None
        ),
    }

    output_dir.mkdir(parents=True, exist_ok=True)
    (output_dir / "summary.json").write_text(
        json.dumps(summary, indent=2, sort_keys=True) + "\n", encoding="utf-8"
    )

    with (output_dir / "per_class_metrics.csv").open("w", encoding="utf-8", newline="") as stream:
        writer = csv.DictWriter(
            stream, fieldnames=["class_value", "class_name", "precision", "recall", "f1", "support"]
        )
        writer.writeheader()
        names = {0: "class_0", 1: args.positive_name}
        for value in (0, 1):
            row = metrics["per_class"][str(value)]
            writer.writerow({"class_value": value, "class_name": names[value], **row})

    if roc is not None:
        with (output_dir / "roc_curve.csv").open("w", encoding="utf-8", newline="") as stream:
            writer = csv.DictWriter(stream, fieldnames=["threshold", "false_positive_rate", "true_positive_rate"])
            writer.writeheader()
            for point in roc["points"]:
                writer.writerow({
                    "threshold": "inf" if point["threshold"] is None else point["threshold"],
                    "false_positive_rate": point["fpr"],
                    "true_positive_rate": point["tpr"],
                })

    print(f"Evaluation complete: {len(actual)} rows")
    print(f"Accuracy: {metrics['accuracy']:.4%}")
    print(f"Precision (class 1): {metrics['precision']:.4%}")
    print(f"Recall (class 1): {metrics['recall']:.4%}")
    print(f"F1-score (class 1): {metrics['f1']:.4%}")
    if roc is not None:
        auc_text = "undefined (requires both classes)" if roc["auc"] is None else f"{roc['auc']:.6f}"
        print(f"ROC AUC: {auc_text}")
    if agreement is not None:
        print(f"Stored prediction mismatches: {agreement['mismatch_count']}")
    print(f"Reports: {output_dir}")
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except (OSError, ValueError, csv.Error) as exc:
        print(f"ERROR: {exc}", file=sys.stderr)
        raise SystemExit(2)
