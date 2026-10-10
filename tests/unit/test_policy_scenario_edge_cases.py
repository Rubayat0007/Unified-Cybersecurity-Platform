"""Regression checks for additional policy status and severity contracts."""
import json
import unittest
from pathlib import Path

from core.evaluation.policy_scenarios import evaluate_scenarios, run_scenario

PROJECT_ROOT = Path(__file__).resolve().parents[2]
SCENARIO_FILE = (
    PROJECT_ROOT / "fixtures" / "evaluation" / "policy_scenarios_edge_cases.json"
)


class PolicyScenarioEdgeCaseTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        with SCENARIO_FILE.open("r", encoding="utf-8") as handle:
            cls.document = json.load(handle)
        cls.scenarios = cls.document["scenarios"]
        cls.by_id = {scenario["id"]: scenario for scenario in cls.scenarios}

    def test_all_edge_case_contract_scenarios_pass(self):
        report = evaluate_scenarios(self.scenarios)
        self.assertEqual(report["scenario_count"], 4)
        self.assertEqual(report["passed_count"], 4)
        self.assertEqual(report["failed_count"], 0)
        self.assertEqual(report["pass_rate"], 1.0)

    def test_timeout_severity_is_ignored(self):
        result = run_scenario(
            self.by_id["timeout-signal-excluded-from-severity"]
        )
        self.assertTrue(result["passed"], result["mismatches"])
        self.assertEqual(result["actual"]["overall_severity"], "low")
        self.assertEqual(result["actual"]["available_signal_count"], 1)
        self.assertFalse(result["actual"]["cross_source_corroboration"])

    def test_not_applicable_signal_does_not_corroborate(self):
        result = run_scenario(
            self.by_id["not-applicable-signal-excluded-from-corroboration"]
        )
        self.assertTrue(result["passed"], result["mismatches"])
        self.assertEqual(result["actual"]["overall_severity"], "medium")
        self.assertEqual(result["actual"]["action"], "warn")
        self.assertFalse(result["actual"]["cross_source_corroboration"])

    def test_standalone_suspicious_severity_maps_to_warn(self):
        result = run_scenario(self.by_id["suspicious-standalone-warns"])
        self.assertTrue(result["passed"], result["mismatches"])
        self.assertEqual(result["actual"]["overall_severity"], "suspicious")
        self.assertEqual(result["actual"]["action"], "warn")
        self.assertEqual(result["actual"]["primary_threat"], "phishing")

    def test_timeout_and_not_applicable_without_available_signals_require_review(self):
        result = run_scenario(
            self.by_id["timeout-and-not-applicable-require-review"]
        )
        self.assertTrue(result["passed"], result["mismatches"])
        self.assertEqual(result["actual"]["overall_severity"], "unknown")
        self.assertEqual(result["actual"]["action"], "investigate")
        self.assertTrue(result["actual"]["requires_human_review"])
        self.assertEqual(result["actual"]["available_signal_count"], 0)


if __name__ == "__main__":
    unittest.main()
