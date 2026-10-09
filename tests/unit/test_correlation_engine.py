import unittest

from adapters.ai_nids.adapter import adapt_result as adapt_ai_nids
from adapters.phishvision.adapter import adapt_result as adapt_phishvision
from core.correlation.engine import correlate
from core.models.enums import (
    RecommendedAction,
    Severity,
    SignalSource,
    SignalStatus,
    SignalType,
)
from core.models.signal import SecuritySignal


class TestCorrelationEngine(unittest.TestCase):
    def _nids_signal(
        self,
        severity: Severity,
        probability: float = 0.9,
    ) -> SecuritySignal:
        return SecuritySignal(
            source=SignalSource.AI_NIDS,
            signal_type=SignalType.NETWORK_INTRUSION,
            status=SignalStatus.AVAILABLE,
            raw_score=probability,
            raw_score_semantics="attack_probability",
            normalized_score=probability * 100.0,
            confidence=probability,
            severity=severity,
        )

    def _phishing_signal(
        self,
        severity: Severity,
        score: float = 80.0,
    ) -> SecuritySignal:
        return SecuritySignal(
            source=SignalSource.PHISHVISION,
            signal_type=SignalType.PHISHING,
            status=SignalStatus.AVAILABLE,
            raw_score=score / 100.0,
            raw_score_semantics="phishing_probability",
            normalized_score=score,
            severity=severity,
        )

    def test_high_nids_and_low_phishvision_remains_high(self):
        assessment = correlate(
            (
                self._nids_signal(Severity.HIGH),
                self._phishing_signal(Severity.LOW),
            )
        )

        self.assertEqual(
            assessment.overall_severity,
            Severity.HIGH,
        )
        self.assertEqual(
            assessment.recommended_action,
            RecommendedAction.INVESTIGATE,
        )

    def test_high_signals_from_two_sources_have_corroboration(self):
        assessment = correlate(
            (
                self._nids_signal(Severity.HIGH),
                self._phishing_signal(Severity.HIGH),
            )
        )

        self.assertEqual(
            assessment.overall_severity,
            Severity.HIGH,
        )
        self.assertTrue(
            assessment.metadata["cross_source_corroboration"]
        )
        self.assertEqual(
            set(assessment.threats),
            {
                "network_intrusion",
                "phishing",
            },
        )

    def test_unavailable_signal_is_not_benign(self):
        unavailable = SecuritySignal(
            source=SignalSource.AI_NIDS,
            signal_type=SignalType.NETWORK_INTRUSION,
            status=SignalStatus.UNAVAILABLE,
        )

        assessment = correlate((unavailable,))

        self.assertEqual(
            assessment.overall_severity,
            Severity.UNKNOWN,
        )
        self.assertEqual(
            assessment.recommended_action,
            RecommendedAction.INVESTIGATE,
        )
        self.assertEqual(
            assessment.component_status["ai_nids"],
            SignalStatus.UNAVAILABLE,
        )

    def test_high_signal_with_unavailable_other_component(self):
        nids = self._nids_signal(Severity.HIGH)

        unavailable = SecuritySignal(
            source=SignalSource.PHISHVISION,
            signal_type=SignalType.PHISHING,
            status=SignalStatus.UNAVAILABLE,
        )

        assessment = correlate((nids, unavailable))

        self.assertEqual(
            assessment.overall_severity,
            Severity.HIGH,
        )
        self.assertEqual(
            assessment.component_status["phishvision"],
            SignalStatus.UNAVAILABLE,
        )

    def test_no_signals_produce_unknown_assessment(self):
        assessment = correlate(())

        self.assertEqual(
            assessment.overall_severity,
            Severity.UNKNOWN,
        )
        self.assertIsNone(
            assessment.primary_threat
        )
        self.assertEqual(
            assessment.threats,
            (),
        )
        self.assertEqual(
            assessment.component_status,
            {},
        )

    def test_minimal_signal_allows(self):
        assessment = correlate(
            (self._nids_signal(Severity.MINIMAL),)
        )

        self.assertEqual(
            assessment.overall_severity,
            Severity.MINIMAL,
        )
        self.assertEqual(
            assessment.recommended_action,
            RecommendedAction.ALLOW,
        )
        self.assertEqual(
            assessment.threats,
            (),
        )

    def test_medium_signal_warns(self):
        assessment = correlate(
            (self._phishing_signal(Severity.MEDIUM),)
        )

        self.assertEqual(
            assessment.overall_severity,
            Severity.MEDIUM,
        )
        self.assertEqual(
            assessment.recommended_action,
            RecommendedAction.WARN,
        )

    def test_low_risk_phishvision_without_findings_is_not_unknown(self):
        result = {
            "text_analysis": {
                "matches": [],
                "score": 0.0,
                "is_suspicious": False,
            },
            "url_analysis": {
                "hostname": "example.com",
                "indicators": [],
                "matched_keywords": [],
                "score": 0.0,
                "is_suspicious": False,
            },
            "cnn_analysis": {
                "prediction": "legitimate",
                "phishing_probability": 0.1847,
                "legitimate_probability": 0.8153,
                "threshold": 0.35,
                "model_loaded": True,
            },
            "risk": {
                "overall_score": 7.39,
                "risk_level": "LOW",
            },
            "security_assessment": {
                "evidence": [],
            },
        }

        assessment = correlate(adapt_phishvision(result))

        self.assertEqual(assessment.overall_severity, Severity.LOW)
        self.assertEqual(
            assessment.recommended_action,
            RecommendedAction.MONITOR,
        )
        self.assertEqual(assessment.threats, ())
        self.assertIsNone(assessment.primary_threat)

    def test_real_adapter_outputs_can_be_correlated(self):
        nids_result = {
            "prediction": 1,
            "confidence": 0.94,
            "attack_probability": 0.91,
            "severity": "HIGH",
            "packet_count": 100,
            "duration": 8.0,
            "flows": [],
        }

        phishvision_result = {
            "text_analysis": {
                "matches": [],
                "score": 10.0,
            },
            "url_analysis": {
                "hostname": "example.test",
                "indicators": [],
                "matched_keywords": [],
                "score": 20.0,
            },
            "cnn_analysis": {
                "prediction": "phishing",
                "phishing_probability": 0.91,
                "legitimate_probability": 0.09,
                "threshold": 0.35,
                "model_loaded": True,
            },
            "risk": {
                "overall_score": 48.4,
                "risk_level": "MEDIUM",
            },
            "security_assessment": {
                "evidence": [
                    {
                        "source": "CNN",
                        "category": "visual_phishing_signal",
                        "severity": "HIGH",
                        "evidence": "CNN detected a visual phishing signal with p(phishing)=0.9100",
                    }
                ],
            },
        }

        nids_signal = (adapt_ai_nids(nids_result),)
        phishvision_signals = adapt_phishvision(
            phishvision_result
        )

        assessment = correlate(
            nids_signal + phishvision_signals
        )

        self.assertEqual(
            assessment.overall_severity,
            Severity.HIGH,
        )
        self.assertTrue(
            assessment.metadata["cross_source_corroboration"]
        )
        self.assertEqual(
            assessment.component_status["ai_nids"],
            SignalStatus.AVAILABLE,
        )
        self.assertEqual(
            assessment.component_status["phishvision"],
            SignalStatus.AVAILABLE,
        )


if __name__ == "__main__":
    unittest.main()

