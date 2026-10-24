"""Tests for the hash-chained audit store (Phase 6.1)."""

import sqlite3
import unittest
from pathlib import Path
import tempfile

from core.audit.store import AuditStore


class AuditStoreTest(unittest.TestCase):
    def setUp(self):
        self._temp = tempfile.TemporaryDirectory()
        self.addCleanup(self._temp.cleanup)
        self.path = Path(self._temp.name) / "audit.db"

    def test_append_chains_records(self):
        with AuditStore(self.path) as store:
            first = store.append({"event_id": "a"}, "2026-10-24T00:00:00+00:00")
            second = store.append({"event_id": "b"}, "2026-10-24T00:00:01+00:00")

            self.assertEqual(first["prev_hash"], "0" * 64)
            self.assertEqual(second["prev_hash"], first["hash"])
            self.assertEqual(store.verify(), (True, None))

    def test_persists_across_reopen(self):
        with AuditStore(self.path) as store:
            store.append({"event_id": "a"}, "2026-10-24T00:00:00+00:00")

        with AuditStore(self.path) as reopened:
            self.assertEqual(len(reopened.records()), 1)
            self.assertEqual(reopened.verify(), (True, None))

    def test_edited_payload_breaks_the_chain(self):
        with AuditStore(self.path) as store:
            store.append({"event_id": "a"}, "2026-10-24T00:00:00+00:00")
            store.append({"event_id": "b"}, "2026-10-24T00:00:01+00:00")

        db = sqlite3.connect(self.path)
        try:
            db.execute("UPDATE audit SET payload = ? WHERE seq = 2",
                       ('{"event_id":"tampered"}',))
            db.commit()
        finally:
            db.close()

        with AuditStore(self.path) as store:
            self.assertEqual(store.verify(), (False, 2))

    def test_deleting_a_row_breaks_the_chain(self):
        with AuditStore(self.path) as store:
            for index in range(3):
                store.append({"event_id": str(index)}, f"2026-10-24T00:00:0{index}+00:00")

        db = sqlite3.connect(self.path)
        try:
            db.execute("DELETE FROM audit WHERE seq = 2")
            db.commit()
        finally:
            db.close()

        with AuditStore(self.path) as store:
            ok, bad = store.verify()
            self.assertFalse(ok)

    def test_canonical_payload_is_key_order_independent(self):
        with AuditStore(self.path) as store:
            store.append({"b": 1, "a": 2}, "2026-10-24T00:00:00+00:00")
            self.assertEqual(store.verify(), (True, None))
            self.assertEqual(store.records()[0]["payload"], {"a": 2, "b": 1})

    def test_empty_store_verifies(self):
        with AuditStore(self.path) as store:
            self.assertEqual(store.verify(), (True, None))
            self.assertEqual(store.records(), [])


if __name__ == "__main__":
    unittest.main()
