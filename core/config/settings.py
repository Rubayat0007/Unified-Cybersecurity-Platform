from dataclasses import dataclass
import os


def _positive_int(name: str, default: int) -> int:
    raw = os.getenv(name, str(default))

    try:
        value = int(raw)
    except ValueError as exc:
        raise ValueError(
            f"{name} must be an integer"
        ) from exc

    if value <= 0:
        raise ValueError(
            f"{name} must be greater than zero"
        )

    return value


@dataclass(frozen=True)
class Settings:
    environment: str
    log_level: str
    request_timeout_seconds: int
    max_request_bytes: int
    provider_timeout_seconds: int
    provider_max_output_bytes: int
    ai_nids_enabled: bool
    phishvision_enabled: bool


def _bool(name: str, default: bool) -> bool:
    raw = os.getenv(name)

    if raw is None:
        return default

    normalized = raw.strip().lower()

    if normalized in {"1", "true", "yes", "on"}:
        return True

    if normalized in {"0", "false", "no", "off"}:
        return False

    raise ValueError(
        f"{name} must be a boolean"
    )


def load_settings() -> Settings:
    environment = os.getenv(
        "UCP_ENVIRONMENT",
        "development",
    ).strip().lower()

    log_level = os.getenv(
        "UCP_LOG_LEVEL",
        "INFO",
    ).strip().upper()

    if environment not in {
        "development",
        "test",
        "staging",
        "production",
    }:
        raise ValueError(
            "UCP_ENVIRONMENT must be one of "
            "development, test, staging, production"
        )

    return Settings(
        environment=environment,
        log_level=log_level,
        request_timeout_seconds=_positive_int(
            "UCP_REQUEST_TIMEOUT_SECONDS",
            10,
        ),
        max_request_bytes=_positive_int(
            "UCP_MAX_REQUEST_BYTES",
            1_048_576,
        ),
        provider_timeout_seconds=_positive_int(
            "UCP_PROVIDER_TIMEOUT_SECONDS",
            10,
        ),
        provider_max_output_bytes=_positive_int(
            "UCP_PROVIDER_MAX_OUTPUT_BYTES",
            1_048_576,
        ),
        ai_nids_enabled=_bool(
            "UCP_AI_NIDS_ENABLED",
            True,
        ),
        phishvision_enabled=_bool(
            "UCP_PHISHVISION_ENABLED",
            True,
        ),
    )