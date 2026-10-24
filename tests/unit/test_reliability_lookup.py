"""Published profiles must reach the signals that cite them (Phase 5.2b)."""

import unittest
from pathlib import Path

from adapters.phishvision.adapter import adapt_result

DIGEST = "1403582CCE07BE1E36E70E4A0D425CFB152B86C7ABEE5D1074DEF79CBB2FB628"
UNKNOWN = "0" * 64


def payload(digest=DIGEST):
    return {
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
            "sha256": digest,
            "threshold": 0.35,
        },
    }


class ReliabilityLookupTest(unittest.TestCase):
    def test_published_bounds_are_attached(self):
        signals = adapt_result(payload())

        for signal in signals:
            self.assertAlmostEqual(signal.metadata["sensitivity_lower"], 0.5383, places=4)
            self.assertAlmostEqual(signal.metadata["false_positive_upper"], 0.5673, places=4)
            self.assertEqual(signal.metadata["reliability_provider"], "phishvision")

    def test_unknown_digest_gets_no_bounds(self):
        signals = adapt_result(payload(UNKNOWN))

        for signal in signals:
            self.assertNotIn("sensitivity_lower", signal.metadata)

    def test_matched_profile_fails_the_benign_gate(self):
        from core.reliability import gate, reliability_from_metadata

        signals = adapt_result(payload())
        metadata = signals[0].metadata

        self.assertFalse(reliability_from_metadata(metadata, 0.5))

    def test_profile_directory_is_the_published_one(self):
        from core.reliability import PROFILE_DIR

        self.assertTrue(PROFILE_DIR.is_dir())
        self.assertTrue(list(PROFILE_DIR.glob("*.json")))


if __name__ == "__main__":
    unittest.main()
