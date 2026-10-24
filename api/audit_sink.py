"""Audit sink: persist each assessment into the hash-chained store.

Policy: fail closed. If persistence is configured and the write fails, the
request fails with 503 - an audit trail that silently drops entries is worse
than no trail, because it looks complete.

Persistence is enabled by setting UCP_AUDIT_DB to a file path. It is not
required in development, so the existing suites and the container smoke keep
working without a database.
"""

from __future__ import annotations

import os
from datetime import datetime, timezone
from pathlib import Path

from core.audit.store import AuditStore


class AuditUnavailable(RuntimeError):
    """Raised when a configured audit write cannot be completed."""


_store: AuditStore | None = None
_initialised = False


def configured_path() -> Path | None:
    raw = (os.environ.get("UCP_AUDIT_DB") or "").strip()
    return Path(raw) if raw else None


def reset() -> None:
    """Forget the cached store (tests, or a configuration change)."""
    global _store, _initialised
    if _store is not None:
        _store.close()
    _store = None
    _initialised = False


def _get_store() -> AuditStore | None:
    global _store, _initialised

    if not _initialised:
        path = configured_path()
        if path is not None:
            path.parent.mkdir(parents=True, exist_ok=True)
            _store = AuditStore(path)
        _initialised = True

    return _store


def payload_for(outcome) -> dict:
    assessment = outcome.assessment
    decision = outcome.decision
    audit = outcome.audit

    return {
        "event_id": audit.event_id,
        "processed_at": audit.processed_at.isoformat(),
        "overall_severity": assessment.overall_severity.value,
        "primary_threat": assessment.primary_threat,
        "recommended_action": decision.action.value,
        "requires_human_review": decision.requires_human_review,
        "component_status": {
            (key.value if hasattr(key, "value") else str(key)):
            (value.value if hasattr(value, "value") else str(value))
            for key, value in assessment.component_status.items()
        },
        "models": sorted(
            {
                signal.metadata.get("model_sha256")
                for signal in assessment.signals
                if isinstance(signal.metadata, dict)
                and signal.metadata.get("model_sha256")
            }
        ),
    }


def record(outcome, recorded_at: datetime | None = None) -> dict | None:
    """Append the outcome to the audit chain, or raise AuditUnavailable."""
    store = _get_store()

    if store is None:
        return None

    moment = (recorded_at or datetime.now(timezone.utc)).isoformat()

    try:
        return store.append(payload_for(outcome), moment)
    except Exception as exc:  # noqa: BLE001 - fail closed on any storage error
        raise AuditUnavailable(str(exc)) from exc
