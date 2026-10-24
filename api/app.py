from threading import Lock

from fastapi import FastAPI, HTTPException, Query, Request
from starlette.concurrency import run_in_threadpool
from core.providers.phishvision import PhishVisionProvider
from core.providers.worker import WorkerResponseError

from pathlib import Path

from fastapi.staticfiles import StaticFiles
from typing import Any

from core.config.settings import load_settings
from core.models.enums import ComponentHealth
from api.middleware import MaxRequestBodySizeMiddleware
from api.auth import (
    RateLimitMiddleware,
    TokenAuthMiddleware,
    TokenBucket,
    resolve_rate_limit,
    resolve_token,
)

from fastapi import FastAPI
from pydantic import BaseModel, ConfigDict, Field, model_validator

from api.schemas import UnifiedAssessmentResponse
from api.serialization import serialize_assessment
from api.service import run_assessment
from api import audit_sink


MAX_DEPTH = 8
MAX_COLLECTION_ITEMS = 128
MAX_STRING_LENGTH = 4096
MAX_TOTAL_NODES = 2048


def _validate_payload(value: Any) -> None:
    node_count = 0

    def walk(current: Any, depth: int) -> None:
        nonlocal node_count

        node_count += 1

        if node_count > MAX_TOTAL_NODES:
            raise ValueError("request payload contains too many values")

        if depth > MAX_DEPTH:
            raise ValueError("request payload is too deeply nested")

        if isinstance(current, str):
            if len(current) > MAX_STRING_LENGTH:
                raise ValueError("request payload contains an oversized string")
            return

        if isinstance(current, dict):
            if len(current) > MAX_COLLECTION_ITEMS:
                raise ValueError("request payload contains too many object fields")

            for key, item in current.items():
                if isinstance(key, str) and len(key) > MAX_STRING_LENGTH:
                    raise ValueError("request payload contains an oversized field name")
                walk(item, depth + 1)
            return

        if isinstance(current, list):
            if len(current) > MAX_COLLECTION_ITEMS:
                raise ValueError("request payload contains too many list items")

            for item in current:
                walk(item, depth + 1)

    walk(value, 0)


app = FastAPI(
    title="Unified Cybersecurity Platform",
    version="0.1.0",
)

settings = load_settings()

_phishvision_provider: PhishVisionProvider | None = None
_phishvision_provider_lock = Lock()


def get_phishvision_provider() -> PhishVisionProvider:
    """Initialize the PhishVision worker only when the image API is used."""
    global _phishvision_provider

    if not settings.phishvision_enabled:
        raise RuntimeError("PhishVision provider is disabled")

    with _phishvision_provider_lock:
        if _phishvision_provider is None:
            _phishvision_provider = (
                PhishVisionProvider.from_environment(settings)
            )

        return _phishvision_provider


@app.on_event("shutdown")
def shutdown_phishvision_provider() -> None:
    """Release the persistent PhishVision worker during application shutdown."""
    global _phishvision_provider

    with _phishvision_provider_lock:
        provider = _phishvision_provider
        _phishvision_provider = None

    if provider is not None:
        provider.close()

app.add_middleware(
    MaxRequestBodySizeMiddleware,
    max_body_size=settings.max_request_bytes,
    path_limits={
        "/v1/assess/image": settings.max_image_request_bytes,
    },
)

# Authentication is disabled unless UCP_API_TOKEN is set; production refuses
# to start without it. Rate limiting wraps authentication so unauthenticated
# floods are throttled before token comparison.
_auth_token = resolve_token(settings.environment)
_rate_limit = resolve_rate_limit(settings.environment)

app.add_middleware(TokenAuthMiddleware, token=_auth_token)
if _rate_limit is not None:
    app.add_middleware(
        RateLimitMiddleware,
        bucket=TokenBucket(*_rate_limit),
    )

DASHBOARD_DIR = Path(__file__).resolve().parents[1] / "dashboard"

app.mount(
    "/dashboard",
    StaticFiles(directory=str(DASHBOARD_DIR), html=True),
    name="dashboard",
)


class AssessmentRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    event_id: str | None = Field(
        default=None,
        min_length=1,
        max_length=128,
    )

    ai_nids_result: dict[str, Any] | None = None
    phishvision_result: dict[str, Any] | None = None

    @model_validator(mode="after")
    def validate_payload(self):
        if self.ai_nids_result is not None:
            _validate_payload(self.ai_nids_result)

        if self.phishvision_result is not None:
            _validate_payload(self.phishvision_result)

        return self


@app.get("/health")
def health() -> dict[str, str]:
    return {
        "status": "ok",
        "environment": settings.environment,
    }


@app.get("/ready")
def readiness() -> dict[str, object]:
    """Report component state honestly: lazy worker means "not_started"."""
    if not settings.phishvision_enabled:
        phishvision = "disabled"
    elif _phishvision_provider is None:
        phishvision = "not_started"
    else:
        phishvision = "started"

    components = {
        "ai_nids": "ingestion_only" if settings.ai_nids_enabled else "disabled",
        "phishvision": phishvision,
    }

    return {
        "ready": True,
        "mode": "result_ingestion",
        "components": components,
    }


@app.post(
    "/v1/assess",
    response_model=UnifiedAssessmentResponse,
)
def assess_endpoint(
    request: AssessmentRequest,
) -> dict[str, Any]:
    result = run_assessment(
        ai_nids_result=request.ai_nids_result,
        phishvision_result=request.phishvision_result,
        event_id=request.event_id,
    )

    try:
        audit_sink.record(result)
    except audit_sink.AuditUnavailable as exc:
        raise HTTPException(
            status_code=503,
            detail="assessment could not be recorded in the audit trail",
        ) from exc

    return serialize_assessment(result)


@app.post(
    "/v1/assess/image",
    response_model=UnifiedAssessmentResponse,
)
async def assess_image_endpoint(
    request: Request,
    event_id: str | None = Query(
        default=None,
        min_length=1,
        max_length=128,
    ),
    url: str | None = Query(
        default=None,
        max_length=2048,
    ),
) -> dict[str, Any]:
    """Assess a screenshot using the isolated PhishVision runtime."""

    content_type = request.headers.get(
        "content-type",
        "",
    ).split(";", 1)[0].strip().lower()

    allowed_content_types = {
        "image/jpeg",
        "image/png",
        "image/webp",
    }

    if content_type not in allowed_content_types:
        raise HTTPException(
            status_code=415,
            detail="Content-Type must be image/jpeg, image/png, or image/webp",
        )

    image_bytes = await request.body()

    if not image_bytes:
        raise HTTPException(
            status_code=422,
            detail="image request body must not be empty",
        )

    if len(image_bytes) > settings.max_image_request_bytes:
        raise HTTPException(
            status_code=413,
            detail="image exceeds the configured size limit",
        )

    try:
        provider = get_phishvision_provider()

        provider_result = await run_in_threadpool(
            provider.assess,
            {
                "image_bytes": image_bytes,
                "url": url,
            },
        )

    except WorkerResponseError as exc:
        if exc.error_type == "payload_too_large":
            raise HTTPException(
                status_code=413,
                detail="image exceeds the configured size limit",
            ) from exc

        if exc.error_type == "invalid_request":
            raise HTTPException(
                status_code=422,
                detail="uploaded image could not be processed",
            ) from exc

        result = run_assessment(
            event_id=event_id,
            phishvision_error=exc,
        )

    except Exception as exc:
        result = run_assessment(
            event_id=event_id,
            phishvision_error=exc,
        )

    else:
        result = run_assessment(
            event_id=event_id,
            phishvision_signals=provider_result.signals,
        )

    try:
        audit_sink.record(result)
    except audit_sink.AuditUnavailable as exc:
        raise HTTPException(
            status_code=503,
            detail="assessment could not be recorded in the audit trail",
        ) from exc

    return serialize_assessment(result)