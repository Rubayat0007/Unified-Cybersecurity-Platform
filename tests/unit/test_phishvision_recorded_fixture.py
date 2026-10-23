"""Adapter contract test against a recorded PhishVision analyzer result.

The fixture ``fixtures/phishvision/real_analyzer_output.json`` was captured
from the real ``PhishVisionAnalyzer`` (OCR + URL + v2 production CNN). It
keeps the seam test hermetic: no torch, no EasyOCR, no checkpoint, no
network — while still exercising the adapter on genuine payload shapes
rather than a hand-written approximation.
"""

import json
import unittest
from pathlib import Path

from adapters.phishvision.adapter import adapt_result

FIXTURE = (
    Path(__file__).resolve().parents[2]
    / "fixtures"
    / "phishvision"
    / "real_analyzer_output.json"
)


class PhishVisionRecordedFixtureTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.payload = json.loads(FIXTURE.read_text(encoding="utf-8-sig"))
        cls.signals = adapt_result(cls.payload)
        cls.by_type = {signal.signal_type.value: signal for signal in cls.signals}

    def test_three_signals_are_produced(self):
        self.assertEqual(
            sorted(self.by_type),
            ["text_threat", "url_threat", "visual_threat"],
        )

    def test_all_components_are_available(self):
        for name in ("text_threat", "url_threat", "visual_threat"):
            self.assertEqual(self.by_type[name].status.value, "available", name)

    def test_visual_signal_preserves_the_cnn_probability(self):
        cnn = self.payload["cnn_analysis"]
        signal = self.by_type["visual_threat"]

        self.assertAlmostEqual(signal.raw_score, cnn["phishing_probability"], places=12)
        self.assertAlmostEqual(
            signal.normalized_score, cnn["phishing_probability"] * 100.0, places=9
        )
        self.assertEqual(signal.metadata["prediction"], cnn["prediction"])
        self.assertEqual(signal.metadata["threshold"], cnn["threshold"])

    def test_text_signal_preserves_heuristic_score(self):
        text = self.payload["text_analysis"]
        signal = self.by_type["text_threat"]

        self.assertEqual(signal.raw_score, text["score"])
        self.assertEqual(signal.normalized_score, text["score"])
        self.assertEqual(signal.raw_score_semantics, "heuristic_text_score")
        self.assertEqual(tuple(text["matches"]), tuple(signal.metadata["matches"]))

    def test_url_signal_preserves_indicators(self):
        url = self.payload["url_analysis"]
        signal = self.by_type["url_threat"]

        self.assertEqual(signal.raw_score, url["score"])
        self.assertEqual(signal.metadata["hostname"], url["hostname"])
        self.assertEqual(tuple(url["indicators"]), tuple(signal.metadata["indicators"]))

    def test_evidence_is_attributed_to_its_component(self):
        sources = {
            finding["source"]
            for finding in self.payload["security_assessment"]["evidence"]
        }
        self.assertTrue(sources)

        for signal, source in (
            (self.by_type["text_threat"], "OCR"),
            (self.by_type["url_threat"], "URL"),
            (self.by_type["visual_threat"], "CNN"),
        ):
            expected = sum(
                1
                for finding in self.payload["security_assessment"]["evidence"]
                if finding["source"] == source
            )
            self.assertEqual(len(signal.evidence), expected, source)

    def test_no_signal_claims_a_calibrated_probability(self):
        for signal in self.signals:
            if signal.raw_score_semantics == "phishing_probability":
                self.assertEqual(signal.signal_type.value, "visual_threat")
            self.assertIn(
                signal.raw_score_semantics,
                {"heuristic_text_score", "heuristic_url_score", "phishing_probability"},
            )


if __name__ == "__main__":
    unittest.main()
