"""Append-only, hash-chained audit store.

Each record carries the hash of its predecessor over canonical JSON, so editing
or deleting a row in the middle breaks the chain at a verifiable position.

This module is the storage layer only; wiring it into the request path is a
separate step (6.1b) so the chain can be tested without HTTP.
"""

from __future__ import annotations

import hashlib
import json
import sqlite3
from pathlib import Path

SCHEMA = """
CREATE TABLE IF NOT EXISTS audit (
    seq INTEGER PRIMARY KEY,
    recorded_at TEXT NOT NULL,
    payload TEXT NOT NULL,
    prev_hash TEXT NOT NULL,
    hash TEXT NOT NULL
);
"""

GENESIS = "0" * 64


def canonical(payload: dict) -> str:
    return json.dumps(payload, sort_keys=True, separators=(",", ":"), default=str)


def chain_hash(prev_hash: str, seq: int, recorded_at: str, payload: str) -> str:
    material = f"{prev_hash}|{seq}|{recorded_at}|{payload}".encode("utf-8")
    return hashlib.sha256(material).hexdigest()


class AuditStore:
    def __init__(self, path: Path | str):
        self.path = str(path)
        self._db = sqlite3.connect(self.path)
        self._db.execute(SCHEMA)
        self._db.commit()

    def close(self) -> None:
        self._db.close()

    def __enter__(self):
        return self

    def __exit__(self, *exc):
        self.close()

    def last(self) -> tuple[int, str]:
        row = self._db.execute(
            "SELECT seq, hash FROM audit ORDER BY seq DESC LIMIT 1"
        ).fetchone()
        return (0, GENESIS) if row is None else (row[0], row[1])

    def append(self, payload: dict, recorded_at: str) -> dict:
        seq, prev_hash = self.last()
        seq += 1
        body = canonical(payload)
        digest = chain_hash(prev_hash, seq, recorded_at, body)

        self._db.execute(
            "INSERT INTO audit (seq, recorded_at, payload, prev_hash, hash) "
            "VALUES (?, ?, ?, ?, ?)",
            (seq, recorded_at, body, prev_hash, digest),
        )
        self._db.commit()

        return {"seq": seq, "hash": digest, "prev_hash": prev_hash}

    def verify(self) -> tuple[bool, int | None]:
        """Recompute the chain; return (ok, first_bad_seq)."""
        prev_hash = GENESIS

        for seq, recorded_at, payload, stored_prev, stored_hash in self._db.execute(
            "SELECT seq, recorded_at, payload, prev_hash, hash FROM audit ORDER BY seq"
        ):
            if stored_prev != prev_hash:
                return False, seq

            expected = chain_hash(prev_hash, seq, recorded_at, payload)

            if expected != stored_hash:
                return False, seq

            prev_hash = stored_hash

        return True, None

    def records(self) -> list[dict]:
        return [
            {"seq": seq, "recorded_at": recorded_at, "payload": json.loads(payload),
             "hash": digest}
            for seq, recorded_at, payload, digest in self._db.execute(
                "SELECT seq, recorded_at, payload, hash FROM audit ORDER BY seq"
            )
        ]
