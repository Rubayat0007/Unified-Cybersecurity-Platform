"""Published reliability profiles fail the gate, as measured."""

import unittest
from pathlib import Path

from core.reliability import load

REPO = Path(__file__).resolve().parents[2]


class PublishedProfileTest(unittest.TestCase):
    def test_phishvision_profile_fails_benign_gate(self):
        profile = load(REPO / "docs" / "profiles" / "phishvision-v2-cnn.json")

        self.assertFalse(profile.benign_verdict_is_informative(0.5))
        self.assertGreater(profile.false_positive_upper, 0.2)

    def test_ai_nids_profile_fails_benign_gate(self):
        profile = load(REPO / "docs" / "profiles" / "ai-nids-cicids2017.json")

        self.assertFalse(profile.benign_verdict_is_informative(0.5))
        self.assertLess(profile.sensitivity_lower, 0.5)

    def test_profiles_carry_provenance(self):
        for name in ("phishvision-v2-cnn.json", "ai-nids-cicids2017.json"):
            profile = load(REPO / "docs" / "profiles" / name)
            self.assertGreaterEqual(len(profile.model_digest), 8)
            self.assertTrue(profile.evaluation_set)
            self.assertTrue(profile.commit)


if __name__ == "__main__":
    unittest.main()
