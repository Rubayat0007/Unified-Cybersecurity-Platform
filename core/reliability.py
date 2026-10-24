"""Reliability profiles for detector signals.

A profile is the measured evidence a detector ships with its model: how often it
finds positives (sensitivity) and how often it fires on negatives (false-positive
rate), with confidence bounds and the conditions those numbers were measured
under.

This module defines the schema and the predicates. Wiring them into the
correlation policy is Phase 5.2/5.3 work and is deliberately not done here.
"""

from __future__ import annotations

import json
from dataclasses import dataclass
from pathlib import Path

REQUIRED = (
    "provider",
    "model_digest",
    "threshold",
    "evaluation_set",
    "n_positive",
    "n_negative",
    "sensitivity",
    "sensitivity_lower",
    "false_positive_rate",
    "false_positive_upper",
    "conditions",
    "valid_until",
    "commit",
)


@dataclass(frozen=True)
class ReliabilityProfile:
    provider: str
    model_digest: str
    threshold: float
    evaluation_set: str
    n_positive: int
    n_negative: int
    sensitivity: float
    sensitivity_lower: float
    false_positive_rate: float
    false_positive_upper: float
    conditions: str
    valid_until: str
    commit: str

    def __post_init__(self):
        for name in ("sensitivity", "sensitivity_lower",
                     "false_positive_rate", "false_positive_upper"):
            value = getattr(self, name)
            if not 0.0 <= value <= 1.0:
                raise ValueError(f"{name} must be within [0, 1]")

        if self.sensitivity_lower > self.sensitivity:
            raise ValueError("sensitivity_lower must not exceed sensitivity")
        if self.false_positive_upper < self.false_positive_rate:
            raise ValueError("false_positive_upper must not be below the point estimate")
        if self.n_positive <= 0 or self.n_negative <= 0:
            raise ValueError("n_positive and n_negative must be positive")
        if not 0.0 <= self.threshold <= 1.0:
            raise ValueError("threshold must be within [0, 1]")

    def benign_verdict_is_informative(self, floor: float) -> bool:
        """True when a benign verdict from this signal carries weight.

        A signal whose lower-bound sensitivity is below the floor is treated as
        unable to speak for safety: its benign verdict must not lower severity
        and must not justify ALLOW on its own.
        """
        return self.sensitivity_lower >= floor

    def as_dict(self) -> dict:
        return {name: getattr(self, name) for name in REQUIRED}


def from_dict(payload: dict) -> ReliabilityProfile:
    missing = [name for name in REQUIRED if name not in payload]
    if missing:
        raise ValueError(f"reliability profile missing fields: {missing}")

    return ReliabilityProfile(
        provider=str(payload["provider"]),
        model_digest=str(payload["model_digest"]),
        threshold=float(payload["threshold"]),
        evaluation_set=str(payload["evaluation_set"]),
        n_positive=int(payload["n_positive"]),
        n_negative=int(payload["n_negative"]),
        sensitivity=float(payload["sensitivity"]),
        sensitivity_lower=float(payload["sensitivity_lower"]),
        false_positive_rate=float(payload["false_positive_rate"]),
        false_positive_upper=float(payload["false_positive_upper"]),
        conditions=str(payload["conditions"]),
        valid_until=str(payload["valid_until"]),
        commit=str(payload["commit"]),
    )


def load(path: Path | str) -> ReliabilityProfile:
    return from_dict(json.loads(Path(path).read_text(encoding="utf-8")))


DEFAULT_FLOOR = 0.5


def resolve_floor(environ=None) -> float:
    """Floor for the benign-verdict gate, overridable by environment."""
    import os

    raw = (environ if environ is not None else os.environ).get("UCP_RELIABILITY_FLOOR")

    if raw is None or not str(raw).strip():
        return DEFAULT_FLOOR

    try:
        value = float(raw)
    except ValueError as exc:
        raise ValueError("UCP_RELIABILITY_FLOOR must be numeric") from exc

    if not 0.0 < value < 1.0:
        raise ValueError("UCP_RELIABILITY_FLOOR must be within (0, 1)")

    return value


def signal_is_informative(signal, floor: float) -> bool:
    """A signal may speak for safety only if it carries a measured bound."""
    metadata = getattr(signal, "metadata", None) or {}

    if not isinstance(metadata, dict):
        return False

    value = metadata.get("sensitivity_lower")

    if not isinstance(value, (int, float)) or isinstance(value, bool):
        return False

    return float(value) >= floor


def has_informative_benign(signals, floor: float) -> bool:
    """True when at least one available signal can justify a benign verdict."""
    for signal in signals:
        status = getattr(signal, "status", None)
        status_value = getattr(status, "value", status)

        if status_value != "available":
            continue

        if signal_is_informative(signal, floor):
            return True

    return False


def gate(profiles: dict[str, ReliabilityProfile | None], floor: float) -> dict:
    """Decide which providers may speak for safety.

    Providers without a profile are treated as unreliable: absent evidence is
    not evidence of reliability.
    """
    if not 0.0 < floor < 1.0:
        raise ValueError("floor must be within (0, 1)")

    return {
        provider: {
            "informative": (
                profile is not None
                and profile.benign_verdict_is_informative(floor)
            ),
            "reason": (
                "no reliability profile" if profile is None
                else "sensitivity lower bound below floor"
                if not profile.benign_verdict_is_informative(floor)
                else "meets floor"
            ),
        }
        for provider, profile in profiles.items()
    }
