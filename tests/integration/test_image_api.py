
import json
import unittest
from pathlib import Path
from unittest.mock import Mock, patch
from core.providers.worker import WorkerResponseError

from fastapi.testclient import TestClient

from adapters.phishvision.adapter import adapt_result
from api.app import app, settings
from core.providers.contract import ProviderResult


ROOT = Path(__file__).resolve().parents[2]


class TestImageAssessmentApi(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.client = TestClient(app)

        fixture_path = (
            ROOT / "fixtures" / "phishvision" / "high_phishing.json"
        )
        with fixture_path.open(encoding="utf-8") as handle:
            fixture = json.load(handle)

        cls.provider_result = ProviderResult(
            provider_name="phishvision",
            signals=adapt_result(fixture),
            metadata={
                "overall_score": 48.4,
                "overall_risk_level": "MEDIUM",
            },
        )

    def _fake_provider(self):
        provider = Mock()
        provider.assess.return_value = self.provider_result
        return provider

    def test_image_endpoint_returns_unified_assessment(self):
        provider = self._fake_provider()
        image_bytes = b"fake image bytes"

        with patch(
            "api.app.get_phishvision_provider",
            return_value=provider,
        ):
            response = self.client.post(
                "/v1/assess/image",
                params={
                    "event_id": "evt-image-0001",
                    "url": "https://secure-login-example.com",
                },
                content=image_bytes,
                headers={"Content-Type": "image/png"},
            )

        self.assertEqual(response.status_code, 200)
        payload = response.json()

        self.assertEqual(
            payload["audit"]["event_id"],
            "evt-image-0001",
        )
        self.assertEqual(
            payload["assessment"]["component_status"]["phishvision"],
            "available",
        )

        provider.assess.assert_called_once_with(
            {
                "image_bytes": image_bytes,
                "url": "https://secure-login-example.com",
            }
        )

    def test_image_endpoint_accepts_missing_optional_url(self):
        provider = self._fake_provider()

        with patch(
            "api.app.get_phishvision_provider",
            return_value=provider,
        ):
            response = self.client.post(
                "/v1/assess/image",
                content=b"fake image bytes",
                headers={"Content-Type": "image/jpeg"},
            )

        self.assertEqual(response.status_code, 200)

        provider.assess.assert_called_once_with(
            {
                "image_bytes": b"fake image bytes",
                "url": None,
            }
        )

    def test_unsupported_content_type_is_rejected(self):
        provider = self._fake_provider()

        with patch(
            "api.app.get_phishvision_provider",
            return_value=provider,
        ):
            response = self.client.post(
                "/v1/assess/image",
                content=b"fake image bytes",
                headers={"Content-Type": "application/json"},
            )

        self.assertEqual(response.status_code, 415)
        provider.assess.assert_not_called()

    def test_empty_image_body_is_rejected(self):
        provider = self._fake_provider()

        with patch(
            "api.app.get_phishvision_provider",
            return_value=provider,
        ):
            response = self.client.post(
                "/v1/assess/image",
                content=b"",
                headers={"Content-Type": "image/png"},
            )

        self.assertEqual(response.status_code, 422)
        provider.assess.assert_not_called()

    def test_image_request_size_limit_is_enforced(self):
        provider = self._fake_provider()
        oversized_body = b"x" * (
            settings.max_image_request_bytes + 1
        )

        with patch(
            "api.app.get_phishvision_provider",
            return_value=provider,
        ):
            response = self.client.post(
                "/v1/assess/image",
                content=oversized_body,
                headers={"Content-Type": "image/png"},
            )

        self.assertEqual(response.status_code, 413)
        provider.assess.assert_not_called()

    def test_invalid_event_id_is_rejected(self):
        provider = self._fake_provider()

        with patch(
            "api.app.get_phishvision_provider",
            return_value=provider,
        ):
            response = self.client.post(
                "/v1/assess/image",
                params={"event_id": "x" * 129},
                content=b"fake image bytes",
                headers={"Content-Type": "image/png"},
            )

        self.assertEqual(response.status_code, 422)
        provider.assess.assert_not_called()

    def test_invalid_url_length_is_rejected(self):
        provider = self._fake_provider()

        with patch(
            "api.app.get_phishvision_provider",
            return_value=provider,
        ):
            response = self.client.post(
                "/v1/assess/image",
                params={"url": "x" * 2049},
                content=b"fake image bytes",
                headers={"Content-Type": "image/png"},
            )

        self.assertEqual(response.status_code, 422)
        provider.assess.assert_not_called()

    def test_provider_failure_returns_fail_safe_assessment(self):
        with patch(
            "api.app.get_phishvision_provider",
            side_effect=RuntimeError("internal path must not leak"),
        ):
            response = self.client.post(
                "/v1/assess/image",
                content=b"fake image bytes",
                headers={"Content-Type": "image/png"},
            )

        self.assertEqual(response.status_code, 200)

        payload = response.json()

        self.assertEqual(
            payload["assessment"]["component_status"]["phishvision"],
            "error",
        )
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
        self.assertNotIn(
            "internal path must not leak",
            response.text,
        )


    def test_invalid_image_from_worker_returns_422(self):
        provider = self._fake_provider()
        provider.assess.side_effect = WorkerResponseError(
            "uploaded image could not be decoded safely",
            error_type="invalid_request",
        )

        with patch(
            "api.app.get_phishvision_provider",
            return_value=provider,
        ):
            response = self.client.post(
                "/v1/assess/image",
                content=b"not-an-image",
                headers={"Content-Type": "image/png"},
            )

        self.assertEqual(response.status_code, 422)
        self.assertNotIn(
            "could not be decoded safely",
            response.text,
        )

    def test_worker_upload_limit_returns_413(self):
        provider = self._fake_provider()
        provider.assess.side_effect = WorkerResponseError(
            "internal worker diagnostic: C:\\private\\worker-root",
            error_type="payload_too_large",
        )

        with patch(
            "api.app.get_phishvision_provider",
            return_value=provider,
        ):
            response = self.client.post(
                "/v1/assess/image",
                content=b"image-bytes",
                headers={"Content-Type": "image/png"},
            )

        self.assertEqual(response.status_code, 413)
        self.assertEqual(
            response.json()["detail"],
            "image exceeds the configured size limit",
        )
        self.assertNotIn(
            "private\\worker-root",
            response.text,
        )


if __name__ == "__main__":
    unittest.main()
