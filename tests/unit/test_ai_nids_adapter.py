import unittest

from adapters.ai_nids.adapter import adapt_result
from core.models.enums import (
    Severity,
    SignalSource,
    SignalStatus,
    SignalType,
)


class TestAiNidsAdapter(unittest.TestCase):
    def test_attack_result_is_normalized(self):
        result = {
            "prediction": 1,
            "confidence": 0.94,
            "attack_probability": 0.91,
            "severity": "HIGH",
            "packet_count": 120,
            "duration": 8.0,
            "flows": [
                {"prediction": 0, "probabilities": [0.9, 0.1]},
                {"prediction": 1, "probabilities": [0.09, 0.91]},
            ],
        }

        signal = adapt_result(result)

        self.assertEqual(signal.source, SignalSource.AI_NIDS)
        self.assertEqual(
            signal.signal_type,
            SignalType.NETWORK_INTRUSION,
        )
        self.assertEqual(signal.status, SignalStatus.AVAILABLE)
        self.assertEqual(signal.raw_score, 0.91)
        self.assertEqual(signal.raw_score_semantics, "attack_probability")
        self.assertEqual(signal.normalized_score, 91.0)
        self.assertEqual(signal.confidence, 0.94)
        self.assertEqual(signal.severity, Severity.HIGH)
        self.assertEqual(signal.metadata["packet_count"], 120)
        self.assertEqual(signal.metadata["flow_count"], 2)

    def test_score_fields_reject_booleans_and_numeric_strings(self):
        base = {
            "prediction": 1,
            "confidence": 0.95,
            "attack_probability": 0.95,
            "severity": "HIGH",
        }

        invalid_values = (
            ("confidence", True),
            ("confidence", "0.95"),
            ("attack_probability", True),
            ("attack_probability", "0.95"),
        )

        for field, value in invalid_values:
            with self.subTest(field=field, value=value):
                result = {**base, field: value}
                with self.assertRaises(ValueError):
                    adapt_result(result)

    def test_suspicious_severity_is_preserved(self):
        result = {
            "prediction": 1,
            "confidence": 0.42,
            "attack_probability": 0.42,
            "severity": "SUSPICIOUS",
        }

        signal = adapt_result(result)

        self.assertEqual(signal.severity, Severity.SUSPICIOUS)

    def test_invalid_probability_is_rejected(self):
        result = {
            "prediction": 1,
            "confidence": 0.95,
            "attack_probability": 1.2,
            "severity": "HIGH",
        }

        with self.assertRaises(ValueError):
            adapt_result(result)

    def test_invalid_prediction_types_are_rejected(self):
        for prediction in (0.7, True, "1"):
            with self.subTest(prediction=prediction):
                result = {
                    "prediction": prediction,
                    "confidence": 0.95,
                    "attack_probability": 0.95,
                    "severity": "HIGH",
                }
                with self.assertRaises(ValueError):
                    adapt_result(result)

    def test_zero_prediction_is_preserved(self):
        result = {
            "prediction": 0,
            "confidence": 0.95,
            "attack_probability": 0.05,
            "severity": "LOW",
        }

        signal = adapt_result(result)

        self.assertEqual(signal.metadata["prediction"], 0)

    def test_missing_required_field_is_rejected(self):
        result = {
            "prediction": 1,
            "confidence": 0.95,
            "severity": "HIGH",
        }

        with self.assertRaises(ValueError):
            adapt_result(result)


if __name__ == "__main__":
    unittest.main()