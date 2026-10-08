from typing import Any

from fastapi import FastAPI
from pydantic import BaseModel, ConfigDict, model_validator

from api.schemas import UnifiedAssessmentResponse
from api.serialization import serialize_assessment
from api.service import run_assessment


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


class AssessmentRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

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
    return {"status": "ok"}


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
    )

    return serialize_assessment(result)