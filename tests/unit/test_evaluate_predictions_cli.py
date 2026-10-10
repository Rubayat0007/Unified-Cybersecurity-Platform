"""CLI regression tests for prediction-report semantics."""
import csv
import json
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parents[2]
CLI = PROJECT_ROOT / "tools" / "evaluate_predictions.py"


class EvaluatePredictionsCliTests(unittest.TestCase):
    def _run(self, header, rows, extra_args=()):
        temp = tempfile.TemporaryDirectory()
        self.addCleanup(temp.cleanup)
        temp_root = Path(temp.name)
        input_path = temp_root / "predictions.csv"
        output_dir = temp_root / "reports"

        with input_path.open("w", encoding="utf-8", newline="") as stream:
            writer = csv.writer(stream)
            writer.writerow(header)
            writer.writerows(rows)

        result = subprocess.run(
            [
                sys.executable,
                str(CLI),
                str(input_path),
                "--output-dir",
                str(output_dir),
                *extra_args,
            ],
            cwd=PROJECT_ROOT,
            capture_output=True,
            text=True,
        )
        self.assertEqual(
            result.returncode,
            0,
            f"CLI failed.\nstdout:\n{result.stdout}\nstderr:\n{result.stderr}",
        )
        summary = json.loads(
            (output_dir / "summary.json").read_text(encoding="utf-8")
        )
        return summary

    def test_hard_label_run_does_not_report_tautological_agreement(self):
        summary = self._run(
            ["actual", "predicted"],
            [[0, 0], [1, 1], [1, 0]],
        )
        self.assertEqual(summary["prediction_source"], "stored_prediction_column")
        self.assertIsNone(summary["stored_prediction_agreement"])

    def test_score_threshold_run_reports_comparison_with_stored_labels(self):
        summary = self._run(
            ["actual", "predicted", "score"],
            [[0, 1, 0.1], [1, 1, 0.8]],
            ["--score-column", "score", "--threshold", "0.35"],
        )
        agreement = summary["stored_prediction_agreement"]
        self.assertIsNotNone(agreement)
        self.assertEqual(agreement["compared_with"], "score_threshold")
        self.assertEqual(agreement["mismatch_count"], 1)
        self.assertEqual(agreement["agreement_count"], 1)
        self.assertEqual(agreement["agreement_rate"], 0.5)


if __name__ == "__main__":
    unittest.main()
