import unittest

from core.decision.assessment import SecurityAssessment
from core.models.enums import (
    RecommendedAction,
    Severity,
    SignalSource,
    SignalStatus,
    SignalType,
)
from core.models.signal import SecuritySignal


class TestSecuritySignal(unittest.TestCase):
    def test_valid_signal(self):
        signal = SecuritySignal(
            source=SignalSource.AI_NIDS,
            signal_type=SignalType.NETWORK_INTRUSION,
            status=SignalStatus.AVAILABLE,
            raw_score=0.91,
            raw_score_semantics="attack_probability",
            normalized_score=91.0,
            confidence=0.94,
            severity=Severity.HIGH,
        )

        self.assertEqual(signal.normalized_score, 91.0)
        self.assertEqual(signal.confidence, 0.94)

    def test_normalized_score_must_be_0_to_100(self):
        with self.assertRaises(ValueError):
            SecuritySignal(
                source=SignalSource.AI_NIDS,
                signal_type=SignalType.NETWORK_INTRUSION,
                status=SignalStatus.AVAILABLE,
                normalized_score=100.1,
            )

    def test_confidence_must_be_0_to_1(self):
        with self.assertRaises(ValueError):
            SecuritySignal(
                source=SignalSource.AI_NIDS,
                signal_type=SignalType.NETWORK_INTRUSION,
                status=SignalStatus.AVAILABLE,
                confidence=1.01,
            )

    def test_missing_score_is_allowed(self):
        signal = SecuritySignal(
            source=SignalSource.AI_NIDS,
            signal_type=SignalType.NETWORK_INTRUSION,
            status=SignalStatus.UNAVAILABLE,
        )

        self.assertIsNone(signal.normalized_score)
        self.assertIsNone(signal.confidence)

    def test_unknown_severity_exists(self):
        self.assertEqual(Severity.UNKNOWN.value, "unknown")


class TestSecurityAssessment(unittest.TestCase):
    def test_default_action(self):
        assessment = SecurityAssessment(
            overall_severity=Severity.LOW,
        )

        self.assertEqual(
            assessment.recommended_action,
            RecommendedAction.MONITOR,
        )

    def test_component_status_is_preserved(self):
        assessment = SecurityAssessment(
            overall_severity=Severity.HIGH,
            component_status={
                SignalSource.AI_NIDS.value: SignalStatus.AVAILABLE,
                SignalSource.PHISHVISION.value: SignalStatus.UNAVAILABLE,
            },
        )

        self.assertEqual(
            assessment.component_status["ai_nids"],
            SignalStatus.AVAILABLE,
        )
        self.assertEqual(
            assessment.component_status["phishvision"],
            SignalStatus.UNAVAILABLE,
        )


if __name__ == "__main__":
    unittest.main()
