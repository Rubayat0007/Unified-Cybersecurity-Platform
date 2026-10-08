from dataclasses import dataclass
from typing import Any, Mapping, Protocol

from core.models.signal import SecuritySignal


@dataclass(frozen=True)
class ProviderResult:
    provider_name: str
    signals: tuple[SecuritySignal, ...]
    metadata: Mapping[str, Any]


class SecurityProvider(Protocol):
    name: str

    def assess(
        self,
        payload: Mapping[str, Any],
    ) -> ProviderResult:
        """Execute a provider and return normalized security signals."""