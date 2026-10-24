"""Provenance must reach the unified response (Lane B, Step 1.6)."""

import unittest

from adapters.phishvision.adapter import adapt_result

DIGEST = "1403582CCE07BE1E36E70E4A0D425CFB152B86C7ABEE5D1074DEF79CBB2FB628"

RESULT = {
    "text_analysis": {"matches": [], "score": 0.0, "is_suspicious": False},
    "url_analysis": None,
    "cnn_analysis": {
        "prediction": "legitimate",
        "phishing_probability": 0.2,
        "legitimate_probability": 0.8,
        "threshold": 0.35,
        "model_loaded": True,
    },
    "risk": {"overall_score": 8.0, "risk_level": "LOW"},
    "security_assessment": {"evidence": []},
    "model": {
        "name": "phishvision_cnn_v2",
        "loaded": True,
        "sha256": DIGEST,
        "threshold": 0.35,
    },
}


class ProvenancePropagationTest(unittest.TestCase):
    def test_every_signal_carries_the_model_digest(self):
        signals = adapt_result(RESULT)

        self.assertEqual(len(signals), 3)

        for signal in signals:
            self.assertEqual(signal.metadata["model_sha256"], DIGEST)
            self.assertEqual(signal.metadata["model_threshold"], 0.35)
            self.assertEqual(signal.metadata["model_name"], "phishvision_cnn_v2")
            self.assertIs(signal.metadata["model_loaded"], True)

    def test_missing_model_block_is_tolerated(self):
        payload = {k: v for k, v in RESULT.items() if k != "model"}

        signals = adapt_result(payload)

        self.assertEqual(len(signals), 3)
        for signal in signals:
            self.assertNotIn("model_sha256", signal.metadata)

    def test_existing_metadata_is_preserved(self):
        signals = adapt_result(RESULT)

        self.assertEqual(signals[0].metadata["overall_score"], 8.0)


if __name__ == "__main__":
    unittest.main()
