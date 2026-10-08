import unittest

from api.serialization import serialize_assessment
from api.service import run_assessment
from core.models.enums import RecommendedAction, Severity


class TestApiService(unittest.TestCase):
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

    def test_service_delegates_to_unified_assessment(self):
        result = run_assessment(
            self._nids_result(),
            self._phishvision_result(),
        )

        self.assertEqual(
            result.assessment.overall_severity,
            Severity.HIGH,
        )
        self.assertEqual(
            result.decision.action,
            RecommendedAction.INVESTIGATE,
        )

    def test_serialized_result_is_json_compatible(self):
        result = run_assessment(
            self._nids_result(),
            self._phishvision_result(),
        )

        payload = serialize_assessment(result)

        self.assertEqual(
            payload["assessment"]["overall_severity"],
            "high",
        )
        self.assertEqual(
            payload["decision"]["action"],
            "investigate",
        )
        self.assertIn(
            "cross_source_corroboration",
            payload["assessment"]["metadata"],
        )
        self.assertIsInstance(
            payload["assessment"]["timestamp"],
            str,
        )


if __name__ == "__main__":
    unittest.main()