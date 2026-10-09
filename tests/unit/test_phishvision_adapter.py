import unittest

from adapters.phishvision.adapter import adapt_result
from core.models.enums import (
    Severity,
    SignalSource,
    SignalStatus,
    SignalType,
)


class TestPhishVisionAdapter(unittest.TestCase):
    def _result(self):
        return {
            "text_analysis": {
                "matches": ["login", "password"],
                "score": 20.0,
                "is_suspicious": True,
            },
            "url_analysis": {
                "url": "http://example-login.test",
                "hostname": "example-login.test",
                "indicators": [
                    "uses_http",
                    "suspicious_keywords",
                ],
                "matched_keywords": ["login"],
                "score": 30.0,
                "is_suspicious": True,
            },
            "cnn_analysis": {
                "prediction": "phishing",
                "phishing_probability": 0.91,
                "legitimate_probability": 0.09,
                "threshold": 0.35,
                "model_loaded": True,
            },
            "risk": {
                "text_score": 20.0,
                "url_score": 30.0,
                "cnn_score": 91.0,
                "overall_score": 51.4,
                "risk_level": "MEDIUM",
            },
            "security_assessment": {
                "evidence": [
                    {
                        "source": "OCR",
                        "category": "credential_harvesting",
                        "severity": "HIGH",
                        "evidence": "password",
                    },
                    {
                        "source": "URL",
                        "category": "transport_security",
                        "severity": "MEDIUM",
                        "evidence": "URL uses HTTP instead of HTTPS",
                    },
                    {
                        "source": "CNN",
                        "category": "visual_phishing_signal",
                        "severity": "HIGH",
                        "evidence": "CNN detected a visual phishing signal",
                    },
                ]
            },
        }

    def test_component_signals_are_created(self):
        signals = adapt_result(self._result())

        self.assertEqual(len(signals), 3)

        self.assertEqual(
            signals[0].signal_type,
            SignalType.TEXT_THREAT,
        )
        self.assertEqual(
            signals[1].signal_type,
            SignalType.URL_THREAT,
        )
        self.assertEqual(
            signals[2].signal_type,
            SignalType.VISUAL_THREAT,
        )

    def test_text_signal(self):
        text_signal = adapt_result(self._result())[0]

        self.assertEqual(
            text_signal.source,
            SignalSource.PHISHVISION,
        )
        self.assertEqual(
            text_signal.status,
            SignalStatus.AVAILABLE,
        )
        self.assertEqual(text_signal.raw_score, 20.0)
        self.assertEqual(text_signal.normalized_score, 20.0)
        self.assertEqual(
            text_signal.raw_score_semantics,
            "heuristic_text_score",
        )
        self.assertEqual(text_signal.severity, Severity.HIGH)

    def test_url_signal(self):
        url_signal = adapt_result(self._result())[1]

        self.assertEqual(
            url_signal.status,
            SignalStatus.AVAILABLE,
        )
        self.assertEqual(url_signal.raw_score, 30.0)
        self.assertEqual(url_signal.normalized_score, 30.0)
        self.assertEqual(url_signal.severity, Severity.MEDIUM)

    def test_cnn_signal(self):
        cnn_signal = adapt_result(self._result())[2]

        self.assertEqual(
            cnn_signal.status,
            SignalStatus.AVAILABLE,
        )
        self.assertEqual(cnn_signal.raw_score, 0.91)
        self.assertEqual(cnn_signal.normalized_score, 91.0)
        self.assertEqual(
            cnn_signal.raw_score_semantics,
            "phishing_probability",
        )
        self.assertEqual(cnn_signal.severity, Severity.HIGH)

    def test_missing_url_is_not_treated_as_benign(self):
        result = self._result()
        result["url_analysis"] = None

        signals = adapt_result(result)
        url_signal = signals[1]

        self.assertEqual(
            url_signal.status,
            SignalStatus.NOT_APPLICABLE,
        )
        self.assertIsNone(url_signal.normalized_score)


    def test_low_risk_without_findings_gets_fallback_severity(self):
        result = self._result()
        result["security_assessment"]["evidence"] = []

        result["text_analysis"].update(
            matches=[],
            score=0.0,
            is_suspicious=False,
        )
        result["url_analysis"].update(
            indicators=[],
            matched_keywords=[],
            score=0.0,
            is_suspicious=False,
        )
        result["cnn_analysis"].update(
            prediction="legitimate",
            phishing_probability=0.1847,
            legitimate_probability=0.8153,
        )
        result["risk"].update(
            overall_score=7.39,
            risk_level="LOW",
        )

        signals = adapt_result(result)

        self.assertEqual(
            tuple(signal.severity for signal in signals),
            (Severity.LOW, Severity.LOW, Severity.LOW),
        )

    def test_suspicious_classifications_fallback_without_findings(self):
        result = self._result()
        result["security_assessment"]["evidence"] = []

        signals = adapt_result(result)

        self.assertEqual(
            tuple(signal.severity for signal in signals),
            (
                Severity.MEDIUM,
                Severity.MEDIUM,
                Severity.MEDIUM,
            ),
        )

    def test_unavailable_cnn_is_not_treated_as_benign(self):
        result = self._result()
        result["cnn_analysis"] = {
            "prediction": None,
            "phishing_probability": None,
            "legitimate_probability": None,
            "threshold": 0.35,
            "model_loaded": False,
            "error": "CNN model unavailable",
        }

        signals = adapt_result(result)
        cnn_signal = signals[2]

        self.assertEqual(
            cnn_signal.status,
            SignalStatus.UNAVAILABLE,
        )
        self.assertIsNone(cnn_signal.normalized_score)


if __name__ == "__main__":
    unittest.main()