import json
import unittest
from pathlib import Path

from core.models.enums import RecommendedAction, Severity
from core.orchestration.engine import assess


ROOT = Path(__file__).resolve().parents[2]


class TestUnifiedPipeline(unittest.TestCase):
    def _load_fixture(self, relative_path: str):
        path = ROOT / relative_path
        with path.open("r", encoding="utf-8") as handle:
            return json.load(handle)

    def test_high_risk_event_is_correlated_across_sources(self):
        nids_result = self._load_fixture(
            "fixtures/ai_nids/high_attack.json"
        )
        phishvision_result = self._load_fixture(
            "fixtures/phishvision/high_phishing.json"
        )

        result = assess(
            ai_nids_result=nids_result,
            phishvision_result=phishvision_result,
        )

        self.assertEqual(
            result.assessment.overall_severity,
            Severity.HIGH,
        )
        self.assertEqual(
            result.assessment.primary_threat,
            "network_intrusion",
        )
        self.assertTrue(
            result.assessment.metadata["cross_source_corroboration"]
        )
        self.assertEqual(
            result.decision.action,
            RecommendedAction.INVESTIGATE,
        )
        self.assertTrue(
            result.decision.requires_human_review
        )


if __name__ == "__main__":
    unittest.main()