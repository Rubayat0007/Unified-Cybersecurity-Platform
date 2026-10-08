import unittest

from core.models.enums import (
    RecommendedAction,
    Severity,
    SignalStatus,
)
from core.orchestration.engine import assess


class TestOrchestrationEngine(unittest.TestCase):
    def _nids_result(self):
        return {
            "prediction": 1,
            "confidence": 0.94,
            "attack_probability": 0.91,
            "severity": "HIGH",
            "packet_count": 100,
            "duration": 8.0,
            "flows": [],
        }

    def _phishvision_result(self):
        return {
            "text_analysis": {
                "matches": [],
                "score": 10.0,
            },
            "url_analysis": {
                "hostname": "example.test",
                "indicators": [],
                "matched_keywords": [],
                "score": 20.0,
            },
            "cnn_analysis": {
                "prediction": "phishing",
                "phishing_probability": 0.91,
                "legitimate_probability": 0.09,
                "threshold": 0.35,
                "model_loaded": True,
            },
            "risk": {
                "overall_score": 48.4,
                "risk_level": "MEDIUM",
            },
            "security_assessment": {
                "evidence": [
                    {
                        "source": "CNN",
                        "category": "visual_phishing_signal",
                        "severity": "HIGH",
                        "evidence": (
                            "CNN detected a visual phishing signal "
                            "with p(phishing)=0.9100"
                        ),
                    }
                ],
            },
        }

    def test_both_sources_produce_correlated_assessment(self):
        result = assess(
            ai_nids_result=self._nids_result(),
            phishvision_result=self._phishvision_result(),
        )

        self.assertEqual(
            result.assessment.overall_severity,
            Severity.HIGH,
        )
        self.assertTrue(
            result.assessment.metadata["cross_source_corroboration"]
        )
        self.assertEqual(
            result.decision.action,
            RecommendedAction.INVESTIGATE,
        )
        self.assertTrue(result.decision.requires_human_review)

    def test_missing_nids_is_explicitly_unavailable(self):
        result = assess(
            phishvision_result=self._phishvision_result(),
        )

        self.assertEqual(
            result.assessment.overall_severity,
            Severity.HIGH,
        )
        self.assertEqual(
            result.assessment.component_status["ai_nids"],
            SignalStatus.UNAVAILABLE,
        )
        self.assertEqual(
            result.assessment.component_status["phishvision"],
            SignalStatus.AVAILABLE,
        )

    def test_missing_phishvision_is_explicitly_unavailable(self):
        result = assess(
            ai_nids_result=self._nids_result(),
        )

        self.assertEqual(
            result.assessment.overall_severity,
            Severity.HIGH,
        )
        self.assertEqual(
            result.assessment.component_status["phishvision"],
            SignalStatus.UNAVAILABLE,
        )
        self.assertEqual(
            result.assessment.component_status["ai_nids"],
            SignalStatus.AVAILABLE,
        )

    def test_missing_both_sources_is_fail_safe(self):
        result = assess()

        self.assertEqual(
            result.assessment.overall_severity,
            Severity.UNKNOWN,
        )
        self.assertEqual(
            result.decision.action,
            RecommendedAction.INVESTIGATE,
        )
        self.assertTrue(result.decision.requires_human_review)
        self.assertEqual(
            result.assessment.component_status["ai_nids"],
            SignalStatus.UNAVAILABLE,
        )
        self.assertEqual(
            result.assessment.component_status["phishvision"],
            SignalStatus.UNAVAILABLE,
        )

    def test_invalid_nids_result_becomes_error_signal(self):
        result = assess(
            ai_nids_result={
                "prediction": 1,
            },
        )

        self.assertEqual(
            result.assessment.component_status["ai_nids"],
            SignalStatus.ERROR,
        )
        self.assertEqual(
            result.assessment.overall_severity,
            Severity.UNKNOWN,
        )
        self.assertEqual(
            result.decision.action,
            RecommendedAction.INVESTIGATE,
        )


    def test_event_id_is_generated_when_not_supplied(self):
        result = assess(
            ai_nids_result=self._nids_result(),
            phishvision_result=self._phishvision_result(),
        )

        self.assertIsInstance(result.audit.event_id, str)
        self.assertTrue(result.audit.event_id)

        parts = result.audit.event_id.split("-")
        self.assertEqual(len(parts), 5)

    def test_audit_matches_final_assessment_and_decision(self):
        result = assess(
            ai_nids_result=self._nids_result(),
            phishvision_result=self._phishvision_result(),
            event_id="evt-audit-0001",
        )

        self.assertEqual(
            result.audit.event_id,
            "evt-audit-0001",
        )
        self.assertEqual(
            result.audit.processed_at,
            result.assessment.timestamp,
        )
        self.assertEqual(
            result.audit.overall_severity,
            result.assessment.overall_severity,
        )
        self.assertEqual(
            result.audit.recommended_action,
            result.decision.action,
        )
        self.assertEqual(
            result.audit.primary_threat,
            result.assessment.primary_threat,
        )
        self.assertEqual(
            result.audit.human_review_required,
            result.decision.requires_human_review,
        )
        self.assertEqual(
            result.audit.source_statuses,
            result.assessment.component_status,
        )


if __name__ == "__main__":
    unittest.main()