"""The reliability gate applied to decisions (Phase 5.3).

A benign verdict from an unmeasured sensor must not produce ALLOW. These tests
exercise the decision layer directly, independent of any adapter.
"""

import unittest

from core.decision.assessment import SecurityAssessment
from core.decision.engine import decide
from core.models.enums import RecommendedAction, Severity, SignalSource, SignalStatus, SignalType
from core.models.signal import SecuritySignal
from core.reliability import resolve_floor, signal_is_informative


def signal(severity=Severity.MINIMAL, sensitivity_lower=None, status=SignalStatus.AVAILABLE,
           false_positive_upper=0.1):
    metadata = (
        {} if sensitivity_lower is None
        else {"sensitivity_lower": sensitivity_lower,
              "false_positive_upper": false_positive_upper}
    )
    return SecuritySignal(
        source=SignalSource.PHISHVISION,
        signal_type=SignalType.PHISHING,
        status=status,
        severity=severity,
        metadata=metadata,
    )


def assessment(signals, severity=Severity.MINIMAL, action=RecommendedAction.ALLOW):
    return SecurityAssessment(
        overall_severity=severity,
        signals=tuple(signals),
        recommended_action=action,
    )


class ReliabilityGateTest(unittest.TestCase):
    def test_allow_without_profile_is_escalated(self):
        decision = decide(assessment([signal()]))

        self.assertEqual(decision.action, RecommendedAction.INVESTIGATE)
        self.assertEqual(decision.severity, Severity.UNKNOWN)
        self.assertTrue(decision.requires_human_review)
        self.assertIn("cannot justify ALLOW", decision.reason)

    def test_allow_with_measured_profile_is_kept(self):
        decision = decide(assessment([signal(sensitivity_lower=0.9)]))

        self.assertEqual(decision.action, RecommendedAction.ALLOW)
        self.assertEqual(decision.severity, Severity.MINIMAL)
        self.assertFalse(decision.requires_human_review)

    def test_profile_below_floor_does_not_count(self):
        decision = decide(assessment([signal(sensitivity_lower=0.2)]))

        self.assertEqual(decision.action, RecommendedAction.INVESTIGATE)

    def test_unavailable_signal_cannot_justify_allow(self):
        decision = decide(assessment([signal(status=SignalStatus.UNAVAILABLE,
                                             sensitivity_lower=0.9)]))

        self.assertEqual(decision.action, RecommendedAction.INVESTIGATE)

    def test_high_severity_is_unaffected(self):
        decision = decide(assessment([signal(severity=Severity.HIGH)],
                                     severity=Severity.HIGH,
                                     action=RecommendedAction.INVESTIGATE))

        self.assertEqual(decision.action, RecommendedAction.INVESTIGATE)
        self.assertEqual(decision.severity, Severity.HIGH)
        self.assertNotIn("cannot justify ALLOW", decision.reason)

    def test_unrelated_metadata_does_not_count(self):
        instance = signal()
        instance.metadata["model_sha256"] = "A" * 64

        self.assertFalse(signal_is_informative(instance, 0.5))

    def test_floor_override_from_environment(self):
        self.assertEqual(resolve_floor({"UCP_RELIABILITY_FLOOR": "0.7"}), 0.7)
        self.assertEqual(resolve_floor({}), 0.5)

        with self.assertRaises(ValueError):
            resolve_floor({"UCP_RELIABILITY_FLOOR": "bad"})


if __name__ == "__main__":
    unittest.main()
