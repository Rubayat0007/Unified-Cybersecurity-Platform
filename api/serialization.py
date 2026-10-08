from dataclasses import asdict
from datetime import datetime
from enum import Enum
from typing import Any


def _serialize(value: Any) -> Any:
    if isinstance(value, Enum):
        return value.value

    if isinstance(value, datetime):
        return value.isoformat()

    if isinstance(value, tuple):
        return [_serialize(item) for item in value]

    if isinstance(value, list):
        return [_serialize(item) for item in value]

    if isinstance(value, dict):
        return {
            str(key): _serialize(item)
            for key, item in value.items()
        }

    if hasattr(value, "__dataclass_fields__"):
        return {
            key: _serialize(item)
            for key, item in asdict(value).items()
        }

    return value


def serialize_assessment(result: Any) -> dict[str, Any]:
    """Convert a UnifiedAssessment into JSON-compatible data."""
    return _serialize(result)