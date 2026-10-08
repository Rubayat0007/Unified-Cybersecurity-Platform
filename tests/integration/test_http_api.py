import json
import unittest
from pathlib import Path

from fastapi.testclient import TestClient

from api.app import app


ROOT = Path(__file__).resolve().parents[2]


class TestHttpApi(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.client = TestClient(app)

    def _load_fixture(self, relative_path: str):
        path = ROOT / relative_path
        with path.open("r", encoding="utf-8") as handle:
            return json.load(handle)

    def test_health_endpoint(self):
        response = self.client.get("/health")

        self.assertEqual(response.status_code, 200)
        self.assertEqual(
            response.json(),
            {"status": "ok"},
        )

    def test_assessment_endpoint_returns_unified_result(self):
        nids_result = self._load_fixture(
            "fixtures/ai_nids/high_attack.json"
        )
        phishvision_result = self._load_fixture(
            "fixtures/phishvision/high_phishing.json"
        )

        response = self.client.post(
            "/v1/assess",
            json={
                "ai_nids_result": nids_result,
                "phishvision_result": phishvision_result,
            },
        )

        self.assertEqual(response.status_code, 200)

        payload = response.json()

        self.assertEqual(
            payload["assessment"]["overall_severity"],
            "high",
        )
        self.assertEqual(
            payload["decision"]["action"],
            "investigate",
        )
        self.assertTrue(
            payload["assessment"]["metadata"][
                "cross_source_corroboration"
            ]
        )

    def test_empty_request_is_fail_safe(self):
        response = self.client.post(
            "/v1/assess",
            json={},
        )

        self.assertEqual(response.status_code, 200)

        payload = response.json()

        self.assertEqual(
            payload["assessment"]["overall_severity"],
            "unknown",
        )
        self.assertEqual(
            payload["decision"]["action"],
            "investigate",
        )
        self.assertTrue(
            payload["decision"]["requires_human_review"]
        )
        self.assertEqual(
            payload["assessment"]["component_status"]["ai_nids"],
            "unavailable",
        )
        self.assertEqual(
            payload["assessment"]["component_status"]["phishvision"],
            "unavailable",
        )



    def test_openapi_exposes_assessment_response_schema(self):
        response = self.client.get("/openapi.json")

        self.assertEqual(response.status_code, 200)

        payload = response.json()
        schemas = payload["components"]["schemas"]

        self.assertIn(
            "UnifiedAssessmentResponse",
            schemas,
        )
        self.assertIn(
            "SecurityAssessmentResponse",
            schemas,
        )
        self.assertIn(
            "OperationalDecisionResponse",
            schemas,
        )

        operation = payload["paths"]["/v1/assess"]["post"]

        self.assertEqual(
            operation["responses"]["200"]["content"][
                "application/json"
            ]["schema"]["$ref"],
            "#/components/schemas/UnifiedAssessmentResponse",
        )


if __name__ == "__main__":
    unittest.main()