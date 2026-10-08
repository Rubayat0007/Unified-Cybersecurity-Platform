from typing import Any

from fastapi import FastAPI
from pydantic import BaseModel

from api.serialization import serialize_assessment
from api.service import run_assessment


app = FastAPI(
    title="Unified Cybersecurity Platform",
    version="0.1.0",
)


class AssessmentRequest(BaseModel):
    ai_nids_result: dict[str, Any] | None = None
    phishvision_result: dict[str, Any] | None = None


@app.get("/health")
def health() -> dict[str, str]:
    return {"status": "ok"}


@app.post("/v1/assess")
def assess_endpoint(request: AssessmentRequest) -> dict[str, Any]:
    result = run_assessment(
        ai_nids_result=request.ai_nids_result,
        phishvision_result=request.phishvision_result,
    )

    return serialize_assessment(result)