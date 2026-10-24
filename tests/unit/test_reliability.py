"""Tests for reliability profiles and the benign-verdict gate (Phase 5.1)."""

import json
import unittest

from core.reliability import ReliabilityProfile, from_dict, gate, load

BASE = {
    "provider": "ai_nids",
    "model_digest": "1992228D",
    "threshold": 0.5,
    "evaluation_set": "live-lab-2026-10",
    "n_positive": 75,
    "n_negative": 45,
    "sensitivity": 0.0,
    "sensitivity_lower": 0.0,
    "false_positive_rate": 0.0,
    "false_positive_upper": 0.079,
    "conditions": "loopback lab, one host",
    "valid_until": "2027-10-24",
    "commit": "a0147f9",
}


def profile(**overrides):
    return from_dict({**BASE, **overrides})


class SchemaTest(unittest.TestCase):
    def test_round_trip(self):
        instance = profile()
        self.assertEqual(from_dict(instance.as_dict()), instance)

    def test_missing_field_rejected(self):
        payload = dict(BASE)
        del payload["sensitivity_lower"]
        with self.assertRaises(ValueError):
            from_dict(payload)

    def test_out_of_range_rejected(self):
        for field in ("sensitivity", "false_positive_rate", "threshold"):
            with self.assertRaises(ValueError):
                profile(**{field: 1.5})

    def test_inconsistent_bounds_rejected(self):
        with self.assertRaises(ValueError):
            profile(sensitivity=0.4, sensitivity_lower=0.6)

        with self.assertRaises(ValueError):
            profile(false_positive_rate=0.2, false_positive_upper=0.1)

    def test_zero_samples_rejected(self):
        with self.assertRaises(ValueError):
            profile(n_positive=0)

    def test_load_from_json(self):
        payload = json.dumps(BASE)
        import tempfile, pathlib
        with tempfile.TemporaryDirectory() as tmp:
            path = pathlib.Path(tmp) / "profile.json"
            path.write_text(payload, encoding="utf-8")
            self.assertEqual(load(path).provider, "ai_nids")


class GateTest(unittest.TestCase):
    def test_signal_with_no_sensitivity_is_not_informative(self):
        self.assertFalse(profile(sensitivity=0.0,
                                 sensitivity_lower=0.0).benign_verdict_is_informative(0.5))

    def test_signal_above_floor_is_informative(self):
        instance = profile(sensitivity=0.9, sensitivity_lower=0.82)

        self.assertTrue(instance.benign_verdict_is_informative(0.5))

    def test_missing_profile_is_unreliable(self):
        result = gate({"phishvision": None}, floor=0.5)

        self.assertFalse(result["phishvision"]["informative"])
        self.assertEqual(result["phishvision"]["reason"], "no reliability profile")

    def test_reason_explains_rejection(self):
        result = gate({"ai_nids": profile()}, floor=0.5)

        self.assertFalse(result["ai_nids"]["informative"])
        self.assertIn("below floor", result["ai_nids"]["reason"])

    def test_floor_must_be_in_range(self):
        for floor in (0.0, 1.0, -0.1):
            with self.assertRaises(ValueError):
                gate({}, floor)


if __name__ == "__main__":
    unittest.main()
