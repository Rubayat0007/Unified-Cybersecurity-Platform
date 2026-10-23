"""Fixture-driven tests for tools/evaluate_predictions.py.

Exercises argument parsing, CSV reading, metric computation, and report
writing against six rows with hand-computed results. No dataset, model, or
network is involved.
"""

import csv
import json
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

REPO = Path(__file__).resolve().parents[2]
TOOL = REPO / "tools" / "evaluate_predictions.py"

# actual=[1,1,1,0,0,0] predicted=[1,0,1,0,1,0] -> TP=2 FN=1 TN=2 FP=1
ROWS = [(1, 1), (1, 0), (1, 1), (0, 0), (0, 1), (0, 0)]


class EvaluatePredictionsCliTest(unittest.TestCase):
    def setUp(self):
        self._temp = tempfile.TemporaryDirectory()
        self.addCleanup(self._temp.cleanup)
        self.tmp = Path(self._temp.name)

        self.input_csv = self.tmp / "predictions.csv"
        with self.input_csv.open("w", encoding="utf-8", newline="") as handle:
            writer = csv.writer(handle)
            writer.writerow(["actual", "predicted"])
            writer.writerows(ROWS)

        self.output_dir = self.tmp / "report"

    def run_tool(self, *arguments):
        return subprocess.run(
            [sys.executable, str(TOOL), *map(str, arguments)],
            cwd=REPO,
            capture_output=True,
            text=True,
            timeout=60,
        )

    def test_confusion_counts_and_metrics(self):
        result = self.run_tool(self.input_csv, "--output-dir", self.output_dir)

        self.assertEqual(result.returncode, 0, result.stderr)

        summary = json.loads((self.output_dir / "summary.json").read_text(encoding="utf-8"))
        metrics = summary["metrics"]

        self.assertEqual(metrics["counts"], {"tp": 2, "tn": 2, "fp": 1, "fn": 1})
        self.assertEqual(metrics["confusion_matrix"], [[2, 1], [1, 2]])
        self.assertAlmostEqual(metrics["accuracy"], 4 / 6)
        self.assertAlmostEqual(metrics["precision"], 2 / 3)
        self.assertAlmostEqual(metrics["recall"], 2 / 3)
        self.assertAlmostEqual(metrics["f1"], 2 / 3)
        self.assertEqual(metrics["sample_count"], 6)

    def test_reports_include_input_provenance(self):
        self.assertEqual(self.run_tool(self.input_csv, "--output-dir", self.output_dir).returncode, 0)

        summary = json.loads((self.output_dir / "summary.json").read_text(encoding="utf-8"))

        self.assertEqual(len(summary["input_file_sha256"]), 64)
        self.assertEqual(summary["input_row_count"], 6)

    def test_per_class_report_is_written(self):
        self.assertEqual(self.run_tool(self.input_csv, "--output-dir", self.output_dir).returncode, 0)

        with (self.output_dir / "per_class_metrics.csv").open(encoding="utf-8") as handle:
            rows = list(csv.DictReader(handle))

        self.assertEqual(len(rows), 2)
        self.assertEqual({row["class_value"] for row in rows}, {"0", "1"})

    def test_existing_report_is_not_overwritten(self):
        self.assertEqual(self.run_tool(self.input_csv, "--output-dir", self.output_dir).returncode, 0)

        second = self.run_tool(self.input_csv, "--output-dir", self.output_dir)

        self.assertEqual(second.returncode, 2)
        self.assertIn("already exist", second.stderr)

    def test_roc_curve_is_written_when_scores_are_supplied(self):
        result = self.run_tool(
            self.input_csv,
            "--output-dir",
            self.output_dir,
            "--score-column",
            "actual",
            "--threshold",
            "0.5",
        )

        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertTrue((self.output_dir / "roc_curve.csv").is_file())

    def test_missing_input_file_is_reported(self):
        result = self.run_tool(self.tmp / "absent.csv", "--output-dir", self.output_dir)

        self.assertEqual(result.returncode, 2)
        self.assertIn("not found", result.stderr.lower())


if __name__ == "__main__":
    unittest.main()
