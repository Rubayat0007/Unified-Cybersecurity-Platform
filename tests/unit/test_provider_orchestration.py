
import json
from pathlib import Path
import unittest

from adapters.phishvision.adapter import adapt_result
from core.models.enums import (
    Severity,
    SignalSource,
    SignalStatus,
    SignalType,
)
from core.orchestration.engine import assess


ROOT = Path(__file__).resolve().parents[2]


class TestProviderOrchestration(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        with (
            ROOT / "fixtures" / "phishvision" / "high_phishing.json"
        ).open(encoding="utf-8") as handle:
            cls.phishvision_result = json.load(handle)

        with (
            ROOT / "fixtures" / "ai_nids" / "high_attack.json"
        ).open(encoding="utf-8") as handle:
            cls.ai_nids_result = json.load(handle)

    def test_runtime_signals_are_used_directly(self):
        expected = adapt_result(self.phishvision_result)

        result = assess(
            phishvision_signals=expected,
            event_id="runtime-event",
        )

        actual = tuple(
            signal
            for signal in result.assessment.signals
            if signal.source is SignalSource.PHISHVISION
        )

        self.assertEqual(actual, expected)
        self.assertEqual(
            result.audit.event_id,
            "runtime-event",
        )

    def test_provider_failure_creates_error_signals(self):
        result = assess(
            phishvision_error=TimeoutError(),
        )

        phishing_signals = [
            signal
            for signal in result.assessment.signals
            if signal.source is SignalSource.PHISHVISION
        ]

        self.assertEqual(len(phishing_signals), 3)

        self.assertEqual(
            {signal.signal_type for signal in phishing_signals},
            {
                SignalType.TEXT_THREAT,
                SignalType.URL_THREAT,
                SignalType.VISUAL_THREAT,
            },
        )

        self.assertTrue(
            all(
                signal.status is SignalStatus.ERROR
                for signal in phishing_signals
            )
        )

        self.assertTrue(
            all(
                signal.severity is Severity.UNKNOWN
                for signal in phishing_signals
            )
        )

    def test_provider_failure_does_not_hide_high_nids_signal(self):
        result = assess(
            ai_nids_result=self.ai_nids_result,
            phishvision_error=RuntimeError(),
        )

        nids_signals = [
            signal
            for signal in result.assessment.signals
            if signal.source is SignalSource.AI_NIDS
        ]

        self.assertEqual(len(nids_signals), 1)
        self.assertEqual(
            nids_signals[0].severity,
            Severity.HIGH,
        )
        self.assertEqual(
            result.assessment.overall_severity,
            Severity.HIGH,
        )

    def test_legacy_phishvision_result_still_works(self):
        result = assess(
            phishvision_result=self.phishvision_result,
        )

        phishing_signals = [
            signal
            for signal in result.assessment.signals
            if signal.source is SignalSource.PHISHVISION
        ]

        self.assertEqual(len(phishing_signals), 3)

    def test_conflicting_phishvision_modes_are_rejected(self):
        with self.assertRaises(ValueError):
            assess(
                phishvision_result=self.phishvision_result,
                phishvision_signals=adapt_result(
                    self.phishvision_result
                ),
            )

    def test_non_phishvision_runtime_signal_is_rejected(self):
        nids_signal = assess(
            ai_nids_result=self.ai_nids_result,
        ).assessment.signals[0]

        with self.assertRaises(ValueError):
            assess(
                phishvision_signals=(nids_signal,),
            )


if __name__ == "__main__":
    unittest.main()
