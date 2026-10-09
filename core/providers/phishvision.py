from __future__ import annotations

import base64
import os
from collections.abc import Mapping
from pathlib import Path
from typing import Any

from adapters.phishvision.adapter import adapt_result
from core.config.settings import Settings, load_settings
from core.providers.contract import ProviderResult
from core.providers.worker import (
    WorkerClient,
    WorkerClientConfig,
    WorkerProtocolError,
)


DEFAULT_MAX_IMAGE_BYTES = 10 * 1024 * 1024
DEFAULT_MAX_URL_LENGTH = 2048


class PhishVisionProviderConfigurationError(RuntimeError):
    """Raised when the PhishVision runtime is not configured."""


class PhishVisionProvider:
    """
    Execute PhishVision through an isolated, persistent worker.

    Expected assessment payload:
        {
            "image_bytes": bytes,
            "url": "https://example.com" | None
        }

    The source repositories remain independent. Runtime locations are
    provided through environment variables rather than hard-coded paths.
    """

    name = "phishvision"

    def __init__(
        self,
        client: WorkerClient,
        *,
        max_image_bytes: int = DEFAULT_MAX_IMAGE_BYTES,
        max_url_length: int = DEFAULT_MAX_URL_LENGTH,
    ) -> None:
        if max_image_bytes <= 0:
            raise ValueError(
                "max_image_bytes must be greater than zero"
            )

        if max_url_length <= 0:
            raise ValueError(
                "max_url_length must be greater than zero"
            )

        self._client = client
        self._max_image_bytes = max_image_bytes
        self._max_url_length = max_url_length

    @classmethod
    def from_environment(
        cls,
        settings: Settings | None = None,
    ) -> PhishVisionProvider:
        """
        Build the provider using deployment environment configuration.

        Required:
            UCP_PHISHVISION_PYTHON
            UCP_PHISHVISION_ROOT
        """
        settings = settings or load_settings()

        python_executable = os.getenv(
            "UCP_PHISHVISION_PYTHON",
            "",
        ).strip()

        project_root_value = os.getenv(
            "UCP_PHISHVISION_ROOT",
            "",
        ).strip()

        missing = []

        if not python_executable:
            missing.append("UCP_PHISHVISION_PYTHON")

        if not project_root_value:
            missing.append("UCP_PHISHVISION_ROOT")

        if missing:
            raise PhishVisionProviderConfigurationError(
                "Missing required configuration: "
                + ", ".join(missing)
            )

        project_root = Path(
            project_root_value
        ).expanduser().resolve()

        analyzer_path = (
            project_root
            / "src"
            / "security"
            / "analyzer.py"
        )

        if not analyzer_path.is_file():
            raise PhishVisionProviderConfigurationError(
                "UCP_PHISHVISION_ROOT does not contain "
                "src/security/analyzer.py"
            )

        worker_path = (
            Path(__file__).resolve().with_name(
                "phishvision_worker.py"
            )
        )

        if not worker_path.is_file():
            raise PhishVisionProviderConfigurationError(
                "PhishVision worker script was not found"
            )

        client = WorkerClient(
            WorkerClientConfig(
                command=(
                    python_executable,
                    str(worker_path),
                ),
                startup_timeout_seconds=max(
                    settings.provider_timeout_seconds,
                    30,
                ),
                request_timeout_seconds=(
                    settings.provider_timeout_seconds
                ),
                max_output_bytes=(
                    settings.provider_max_output_bytes
                ),
                environment={
                    "UCP_PHISHVISION_ROOT": str(project_root),
                    "UCP_MAX_IMAGE_REQUEST_BYTES": str(
                        settings.max_image_request_bytes
                    ),
                },
                cwd=str(project_root),
            )
        )

        return cls(
            client,
            max_image_bytes=settings.max_image_request_bytes,
        )

    def assess(
        self,
        payload: Mapping[str, Any],
    ) -> ProviderResult:
        if not isinstance(payload, Mapping):
            raise TypeError(
                "provider payload must be a mapping"
            )

        image_value = payload.get("image_bytes")

        if not isinstance(
            image_value,
            (bytes, bytearray, memoryview),
        ):
            raise TypeError(
                "image_bytes must be bytes-like"
            )

        image_bytes = bytes(image_value)

        if not image_bytes:
            raise ValueError(
                "image_bytes must not be empty"
            )

        if len(image_bytes) > self._max_image_bytes:
            raise ValueError(
                "image exceeds the configured size limit"
            )

        url = payload.get("url")

        if url is not None:
            if not isinstance(url, str):
                raise TypeError(
                    "url must be a string or None"
                )

            if len(url) > self._max_url_length:
                raise ValueError(
                    "url exceeds the configured length limit"
                )

            url = url.strip() or None

        request = {
            "image_base64": base64.b64encode(
                image_bytes
            ).decode("ascii"),
            "url": url,
        }

        response = self._client.request(request)

        if not isinstance(response, Mapping):
            raise WorkerProtocolError(
                "worker response must be a mapping"
            )

        result = response.get("result")

        if not isinstance(result, Mapping):
            raise WorkerProtocolError(
                "worker response is missing its result object"
            )

        signals = adapt_result(result)

        risk = result.get("risk")
        assessment = result.get("security_assessment")

        risk = risk if isinstance(risk, Mapping) else {}
        assessment = (
            assessment
            if isinstance(assessment, Mapping)
            else {}
        )

        raw_errors = assessment.get(
            "component_errors",
            [],
        )

        component_errors = (
            tuple(raw_errors)
            if isinstance(raw_errors, list)
            else ()
        )

        metadata = {
            "overall_score": risk.get("overall_score"),
            "overall_risk_level": risk.get("risk_level"),
            "component_errors": component_errors,
            "signal_count": len(signals),
        }

        return ProviderResult(
            provider_name=self.name,
            signals=signals,
            metadata=metadata,
        )

    def close(self) -> None:
        """Stop the worker and release its resources."""
        self._client.close()