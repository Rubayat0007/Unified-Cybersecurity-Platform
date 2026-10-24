"""Tests for the fail-closed audit sink (Phase 6.1b)."""

import os
import tempfile
import unittest
from datetime import datetime, timezone
from pathlib import Path
from unittest.mock import patch

from api import audit_sink
from core.audit.store import AuditStore
from core.decision.assessment import SecurityAssessment
from core.decision.engine import OperationalDecision
from core.models.enums import RecommendedAction, Severity, SignalStatus
from core.orchestration.engine import UnifiedAssessment


def outcome():
    assessment = SecurityAssessment(
        overall_severity=Severity.HIGH,
        component_status={"phishvision": SignalStatus.AVAILABLE},
        recommended_action=RecommendedAction.INVESTIGATE,
    )
    decision = OperationalDecision(
        severity=Severity.HIGH,
        action=RecommendedAction.INVESTIGATE,
        reason="test",
        requires_human_review=True,
    )

    class Audit:
        event_id = "evt-1"
        processed_at = datetime(2026, 10, 24, tzinfo=timezone.utc)

    return UnifiedAssessment(assessment=assessment, decision=decision, audit=Audit())


class AuditSinkTest(unittest.TestCase):
    def setUp(self):
        self._temp = tempfile.TemporaryDirectory()
        self.addCleanup(self._temp.cleanup)
        self.path = Path(self._temp.name) / "audit.db"
        audit_sink.reset()
        self.addCleanup(audit_sink.reset)

    def test_disabled_when_unset(self):
        with patch.dict(os.environ, {}, clear=False):
            os.environ.pop("UCP_AUDIT_DB", None)
            audit_sink.reset()
            self.assertIsNone(audit_sink.record(outcome()))

    def test_records_when_configured(self):
        os.environ["UCP_AUDIT_DB"] = str(self.path)
        audit_sink.reset()

        entry = audit_sink.record(outcome())

        self.assertIsNotNone(entry)
        self.assertEqual(entry["seq"], 1)

        with AuditStore(self.path) as store:
            self.assertEqual(store.verify(), (True, None))
            record = store.records()[0]
            self.assertEqual(record["payload"]["event_id"], "evt-1")
            self.assertEqual(record["payload"]["overall_severity"], "high")
            self.assertTrue(record["payload"]["requires_human_review"])

    def test_write_failure_fails_closed(self):
        os.environ["UCP_AUDIT_DB"] = str(self.path)
        audit_sink.reset()
        audit_sink.record(outcome())

        with patch.object(audit_sink, "_get_store") as getter:
            getter.return_value.append.side_effect = OSError("disk full")

            with self.assertRaises(audit_sink.AuditUnavailable):
                audit_sink.record(outcome())

    def test_payload_has_no_signal_content(self):
        payload = audit_sink.payload_for(outcome())

        self.assertNotIn("evidence", payload)
        self.assertNotIn("extracted_text", payload)


if __name__ == "__main__":
    unittest.main()
