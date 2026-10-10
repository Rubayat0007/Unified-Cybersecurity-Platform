import json
import unittest
from pathlib import Path

from core.evaluation.policy_scenarios import evaluate_scenarios, run_scenario
from tools.evaluate_policy_scenarios import _scenarios_from_document

PROJECT_ROOT = Path(__file__).resolve().parents[2]
SCENARIO_FILE = PROJECT_ROOT / "fixtures" / "evaluation" / "policy_scenarios.json"


class PolicyScenarioEvaluationTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        with SCENARIO_FILE.open("r", encoding="utf-8") as handle:
            cls.document = json.load(handle)
        cls.scenarios = cls.document["scenarios"]

    def test_reference_scenarios_all_pass(self):
        report = evaluate_scenarios(self.scenarios)
        self.assertEqual(report["scenario_count"], 8)
        self.assertEqual(report["passed_count"], 8)
        self.assertEqual(report["failed_count"], 0)
        self.assertEqual(report["pass_rate"], 1.0)
        self.assertEqual(report["evaluation_type"], "rules_policy_contract_scenarios")

    def test_no_usable_signals_requires_human_review(self):
        scenario = next(
            item for item in self.scenarios
            if item["id"] == "no-usable-signals-fail-safe"
        )
        result = run_scenario(scenario)
        self.assertTrue(result["passed"], result["mismatches"])
        self.assertEqual(result["actual"]["overall_severity"], "unknown")
        self.assertTrue(result["actual"]["requires_human_review"])

    def test_multiple_components_from_one_source_are_not_corroboration(self):
        scenario = next(
            item for item in self.scenarios
            if item["id"] == "multiple-phishvision-components-one-source"
        )
        result = run_scenario(scenario)
        self.assertTrue(result["passed"], result["mismatches"])
        self.assertFalse(result["actual"]["cross_source_corroboration"])

    def test_policy_mismatch_is_reported(self):
        scenario = {
            "id": "deliberate-mismatch",
            "name": "A deliberately incorrect expectation",
            "signals": [
                {
                    "source": "phishvision",
                    "signal_type": "visual_threat",
                    "status": "available",
                    "severity": "low",
                }
            ],
            "expected": {"overall_severity": "high", "action": "investigate"},
        }
        result = run_scenario(scenario)
        self.assertFalse(result["passed"])
        self.assertEqual(result["mismatches"]["overall_severity"]["actual"], "low")
        self.assertEqual(result["mismatches"]["action"]["actual"], "monitor")

    def test_invalid_signal_becomes_visible_failed_scenario(self):
        scenario = {
            "id": "invalid-signal",
            "name": "Unsupported signal source",
            "signals": [
                {"source": "unknown_detector", "signal_type": "visual_threat", "status": "available", "severity": "low"}
            ],
            "expected": {"overall_severity": "low"},
        }
        result = run_scenario(scenario)
        self.assertFalse(result["passed"])
        self.assertIn("Unsupported source", result["error"])

    def test_empty_scenario_list_is_rejected(self):
        with self.assertRaisesRegex(ValueError, "At least one"):
            evaluate_scenarios([])

    def test_scenario_requires_expected_output(self):
        result = run_scenario({"id": "missing-expected", "name": "Missing expected", "signals": []})
        self.assertFalse(result["passed"])
        self.assertIn("expected must be", result["error"])

    def test_unknown_expected_field_is_rejected(self):
        scenario = {
            "id": "invalid-expected",
            "name": "Unknown expected field",
            "signals": [],
            "expected": {"invented_metric": True},
        }
        result = run_scenario(scenario)
        # Unsupported expectations are rejected and made visible in evaluation output.
        self.assertFalse(result["passed"])
        self.assertIn("unsupported expected fields", result["error"])



class ScenarioDocumentContractTests(unittest.TestCase):
    def test_integer_schema_version_is_accepted(self):
        self.assertEqual(
            _scenarios_from_document({"schema_version": 1, "scenarios": []}),
            [],
        )

    def test_boolean_schema_version_is_rejected(self):
        with self.assertRaisesRegex(ValueError, "integer schema_version"):
            _scenarios_from_document({"schema_version": True, "scenarios": []})

    def test_float_schema_version_is_rejected(self):
        with self.assertRaisesRegex(ValueError, "integer schema_version"):
            _scenarios_from_document({"schema_version": 1.0, "scenarios": []})


if __name__ == "__main__":
    unittest.main()
