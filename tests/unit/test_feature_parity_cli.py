import csv
import json
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest

from core.evaluation.feature_parity import FEATURE_NAMES


PROJECT_ROOT = Path(__file__).resolve().parents[2]
CLI_PATH = PROJECT_ROOT / "tools" / "compare_feature_parity.py"


def make_record(flow_id):
    record = {"flow_id": flow_id}
    record.update({
        name: float(index + 1)
        for index, name in enumerate(FEATURE_NAMES)
    })
    return record


def write_csv(path, records, fields=None):
    if fields is None:
        fields = ["flow_id", *FEATURE_NAMES]

    with path.open("w", encoding="utf-8", newline="") as handle:
        writer = csv.DictWriter(handle, fieldnames=fields)
        writer.writeheader()
        writer.writerows(records)


class TestFeatureParityCli(unittest.TestCase):
    def run_cli(self, reference, candidate, *extra_args):
        return subprocess.run(
            [
                sys.executable,
                str(CLI_PATH),
                str(reference),
                str(candidate),
                *extra_args,
            ],
            cwd=PROJECT_ROOT,
            capture_output=True,
            text=True,
            check=False,
        )

    def test_equivalent_csvs_pass_and_write_json_report(self):
        with tempfile.TemporaryDirectory() as temporary:
            folder = Path(temporary)
            reference = folder / "reference.csv"
            candidate = folder / "candidate.csv"
            report = folder / "report.json"

            write_csv(reference, [make_record("flow-001")])
            write_csv(candidate, [make_record("flow-001")])

            result = self.run_cli(
                reference,
                candidate,
                "--json-output",
                str(report),
            )

            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertIn("Feature comparison: PASS", result.stdout)

            payload = json.loads(report.read_text(encoding="utf-8"))
            self.assertTrue(payload["valid"])
            self.assertTrue(payload["equivalent"])
            self.assertEqual(
                payload["summary"]["feature_values_compared"], 20
            )
            self.assertIn("does not verify reference provenance",
                          payload["interpretation"])

    def test_json_output_cannot_overwrite_input_csv(self):
        with tempfile.TemporaryDirectory() as temporary:
            folder = Path(temporary)
            reference = folder / "reference.csv"
            candidate = folder / "candidate.csv"
            write_csv(reference, [make_record("flow-001")])
            write_csv(candidate, [make_record("flow-001")])
            original_reference = reference.read_bytes()
            original_candidate = candidate.read_bytes()

            result = self.run_cli(
                reference,
                candidate,
                "--json-output",
                str(reference),
            )

            self.assertEqual(result.returncode, 2)
            self.assertIn("must differ", result.stderr)
            self.assertEqual(reference.read_bytes(), original_reference)
            self.assertEqual(candidate.read_bytes(), original_candidate)

    def test_feature_mismatch_returns_one(self):
        with tempfile.TemporaryDirectory() as temporary:
            folder = Path(temporary)
            reference = folder / "reference.csv"
            candidate = folder / "candidate.csv"

            write_csv(reference, [make_record("flow-001")])
            changed = make_record("flow-001")
            changed["flow_bytes"] += 10
            write_csv(candidate, [changed])

            result = self.run_cli(
                reference,
                candidate,
                "--abs-tol",
                "0",
                "--rel-tol",
                "0",
            )

            self.assertEqual(result.returncode, 1)
            self.assertIn("Feature comparison: FAIL", result.stdout)
            self.assertIn("feature=flow_bytes", result.stdout)

    def test_missing_required_column_returns_two(self):
        with tempfile.TemporaryDirectory() as temporary:
            folder = Path(temporary)
            reference = folder / "reference.csv"
            candidate = folder / "candidate.csv"

            write_csv(reference, [{"flow_id": "flow-001"}],
                      fields=["flow_id"])
            write_csv(candidate, [make_record("flow-001")])

            result = self.run_cli(reference, candidate)

            self.assertEqual(result.returncode, 2)
            self.assertIn("missing required columns", result.stderr)

    def test_duplicate_flow_ids_are_invalid(self):
        with tempfile.TemporaryDirectory() as temporary:
            folder = Path(temporary)
            reference = folder / "reference.csv"
            candidate = folder / "candidate.csv"

            write_csv(reference, [
                make_record("flow-001"),
                make_record("flow-001"),
            ])
            write_csv(candidate, [make_record("flow-001")])

            result = self.run_cli(reference, candidate)

            self.assertEqual(result.returncode, 1)
            self.assertIn("Feature comparison: INVALID", result.stdout)
            self.assertIn("duplicate flow_id", result.stdout)

    def test_extra_metadata_columns_are_reported(self):
        with tempfile.TemporaryDirectory() as temporary:
            folder = Path(temporary)
            reference = folder / "reference.csv"
            candidate = folder / "candidate.csv"
            records = [make_record("flow-001")]
            records[0]["fixture_note"] = "synthetic test only"
            fields = ["flow_id", *FEATURE_NAMES, "fixture_note"]

            write_csv(reference, records, fields)
            write_csv(candidate, records, fields)

            result = self.run_cli(
                reference,
                candidate,
                "--json-output",
                str(folder / "report.json"),
            )

            self.assertEqual(result.returncode, 0, result.stderr)
            payload = json.loads(
                (folder / "report.json").read_text(encoding="utf-8")
            )
            self.assertEqual(
                payload["ignored_extra_columns"]["reference"],
                ["fixture_note"],
            )


if __name__ == "__main__":
    unittest.main()
