import unittest

from core.correlation.engine import correlate
from core.decision.engine import decide
from core.models.enums import (
    RecommendedAction,
    Severity,
    SignalSource,
    SignalStatus,
    SignalType,
)
from core.models.signal import SecuritySignal


class TestDecisionEngine(unittest.TestCase):
    def _signal(
        self,
        source: SignalSource,
        signal_type: SignalType,
        severity: Severity,
    ) -> SecuritySignal:
        return SecuritySignal(
            source=source,
            signal_type=signal_type,
            status=SignalStatus.AVAILABLE,
            raw_score=0.9,
            raw_score_semantics="test_score",
            normalized_score=90.0,
            confidence=0.9,
            severity=severity,
        )

    def test_high_assessment_requires_human_review(self):
        assessment = correlate(
            (
                self._signal(
                    SignalSource.AI_NIDS,
                    SignalType.NETWORK_INTRUSION,
                    Severity.HIGH,
                ),
            )
        )

        decision = decide(assessment)

        self.assertEqual(decision.severity, Severity.HIGH)
        self.assertEqual(
            decision.action,
            RecommendedAction.INVESTIGATE,
        )
        self.assertTrue(decision.requires_human_review)
        self.assertEqual(
            decision.primary_threat,
            "network_intrusion",
        )

    def test_corrobated_high_assessment_mentions_multiple_sources(self):
        assessment = correlate(
            (
                self._signal(
                    SignalSource.AI_NIDS,
                    SignalType.NETWORK_INTRUSION,
                    Severity.HIGH,
                ),
                self._signal(
                    SignalSource.PHISHVISION,
                    SignalType.PHISHING,
                    Severity.HIGH,
                ),
            )
        )

        decision = decide(assessment)

        self.assertEqual(decision.action, RecommendedAction.INVESTIGATE)
        self.assertTrue(decision.requires_human_review)
        self.assertIn("Multiple security sources corroborate", decision.reason)

    def test_medium_assessment_warns_without_human_review(self):
        assessment = correlate(
            (
                self._signal(
                    SignalSource.PHISHVISION,
                    SignalType.PHISHING,
                    Severity.MEDIUM,
                ),
            )
        )

        decision = decide(assessment)

        self.assertEqual(decision.severity, Severity.MEDIUM)
        self.assertEqual(decision.action, RecommendedAction.WARN)
        self.assertFalse(decision.requires_human_review)

    def test_minimal_assessment_allows(self):
        assessment = correlate(
            (
                self._signal(
                    SignalSource.AI_NIDS,
                    SignalType.NETWORK_INTRUSION,
                    Severity.MINIMAL,
                ),
            )
        )

        decision = decide(assessment)

        self.assertEqual(decision.action, RecommendedAction.ALLOW)
        self.assertFalse(decision.requires_human_review)

    def test_unknown_assessment_is_fail_safe(self):
        assessment = correlate(())

        decision = decide(assessment)

        self.assertEqual(decision.severity, Severity.UNKNOWN)
        self.assertEqual(
            decision.action,
            RecommendedAction.INVESTIGATE,
        )
        self.assertTrue(decision.requires_human_review)
        self.assertIn("rather than assuming", decision.reason)


if __name__ == "__main__":
    unittest.main()