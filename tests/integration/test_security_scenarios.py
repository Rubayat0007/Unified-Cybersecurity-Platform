import unittest

from core.models.enums import RecommendedAction, Severity, SignalStatus
from core.orchestration.engine import assess


class TestSecurityScenarios(unittest.TestCase):
    def _nids(self, severity="HIGH", probability=0.91):
        return {
            "prediction": 1,
            "confidence": 0.94,
            "attack_probability": probability,
            "severity": severity,
            "packet_count": 100,
            "duration": 8.0,
            "flows": [],
        }

    def _phishvision(self, cnn_probability=0.91, severity="HIGH"):
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
                "prediction": (
                    "phishing"
                    if cnn_probability >= 0.35
                    else "legitimate"
                ),
                "phishing_probability": cnn_probability,
                "legitimate_probability": 1.0 - cnn_probability,
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
                        "severity": severity,
                        "evidence": (
                            "CNN detected a visual phishing signal "
                            f"with p(phishing)={cnn_probability:.4f}"
                        ),
                    }
                ],
            },
        }

    def test_high_nids_high_phishvision_is_corroborated(self):
        result = assess(
            ai_nids_result=self._nids(),
            phishvision_result=self._phishvision(),
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
        self.assertTrue(
            result.decision.requires_human_review
        )

    def test_high_nids_with_low_phishvision_stays_high_without_corroboration(self):
        result = assess(
            ai_nids_result=self._nids(),
            phishvision_result=self._phishvision(
                cnn_probability=0.10,
                severity="LOW",
            ),
        )

        self.assertEqual(
            result.assessment.overall_severity,
            Severity.HIGH,
        )
        self.assertFalse(
            result.assessment.metadata["cross_source_corroboration"]
        )
        self.assertEqual(
            result.assessment.primary_threat,
            "network_intrusion",
        )

    def test_missing_nids_does_not_lower_high_phishing_assessment(self):
        result = assess(
            phishvision_result=self._phishvision(),
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

    def test_invalid_nids_result_becomes_error_without_hiding_phishing_signal(self):
        result = assess(
            ai_nids_result={
                "prediction": 1,
            },
            phishvision_result=self._phishvision(),
        )

        self.assertEqual(
            result.assessment.overall_severity,
            Severity.HIGH,
        )
        self.assertEqual(
            result.assessment.component_status["ai_nids"],
            SignalStatus.ERROR,
        )
        self.assertEqual(
            result.assessment.component_status["phishvision"],
            SignalStatus.AVAILABLE,
        )

    def test_only_medium_phishing_signal_produces_warning(self):
        result = assess(
            phishvision_result=self._phishvision(
                cnn_probability=0.60,
                severity="MEDIUM",
            ),
        )

        self.assertEqual(
            result.assessment.overall_severity,
            Severity.MEDIUM,
        )
        self.assertEqual(
            result.decision.action,
            RecommendedAction.WARN,
        )
        self.assertFalse(
            result.decision.requires_human_review
        )

    def test_no_sources_is_fail_safe(self):
        result = assess()

        self.assertEqual(
            result.assessment.overall_severity,
            Severity.UNKNOWN,
        )
        self.assertEqual(
            result.decision.action,
            RecommendedAction.INVESTIGATE,
        )
        self.assertTrue(
            result.decision.requires_human_review
        )
        self.assertFalse(
            result.assessment.metadata["cross_source_corroboration"]
        )


if __name__ == "__main__":
    unittest.main()