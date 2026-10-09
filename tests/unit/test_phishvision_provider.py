import base64
import os
from pathlib import Path
import sys
import tempfile
import unittest
from unittest.mock import Mock, patch

from core.providers.contract import ProviderResult
from core.providers.phishvision import (
    PhishVisionProvider,
    PhishVisionProviderConfigurationError,
)
from core.providers.worker import WorkerProtocolError


class TestPhishVisionProvider(unittest.TestCase):
    def setUp(self):
        self.client = Mock()
        self.provider = PhishVisionProvider(
            self.client,
            max_image_bytes=1024,
            max_url_length=128,
        )

    def _result(self):
        return {
            "text_analysis": {
                "matches": ["sign in"],
                "score": 20.0,
            },
            "url_analysis": {
                "hostname": "secure-login-example.com",
                "indicators": ["hyphen_in_domain"],
                "matched_keywords": ["login"],
                "score": 30.0,
            },
            "cnn_analysis": {
                "prediction": "phishing",
                "phishing_probability": 0.91,
                "legitimate_probability": 0.09,
                "threshold": 0.35,
                "model_loaded": True,
            },
            "risk": {
                "overall_score": 53.16,
                "risk_level": "MEDIUM",
            },
            "security_assessment": {
                "evidence": [
                    {
                        "source": "OCR",
                        "category": "credential_harvesting",
                        "severity": "HIGH",
                        "evidence": "sign in",
                    },
                    {
                        "source": "CNN",
                        "category": "visual_phishing_signal",
                        "severity": "HIGH",
                        "evidence": (
                            "CNN detected visual phishing "
                            "with p(phishing)=0.9100"
                        ),
                    },
                ],
                "component_errors": [],
            },
        }

    def _successful_response(self):
        return {
            "status": "ok",
            "result": self._result(),
        }

    def test_assess_encodes_image_and_normalizes_result(self):
        image_bytes = b"test image bytes"
        self.client.request.return_value = (
            self._successful_response()
        )

        result = self.provider.assess(
            {
                "image_bytes": image_bytes,
                "url": "  https://example.com  ",
            }
        )

        self.assertIsInstance(result, ProviderResult)
        self.assertEqual(result.provider_name, "phishvision")
        self.assertEqual(len(result.signals), 3)

        request = self.client.request.call_args.args[0]

        self.assertEqual(
            base64.b64decode(request["image_base64"]),
            image_bytes,
        )
        self.assertEqual(
            request["url"],
            "https://example.com",
        )

        self.assertEqual(
            result.metadata["overall_risk_level"],
            "MEDIUM",
        )
        self.assertEqual(
            result.metadata["signal_count"],
            3,
        )
        self.assertEqual(
            result.metadata["component_errors"],
            (),
        )

    def test_missing_url_is_sent_as_none(self):
        self.client.request.return_value = (
            self._successful_response()
        )

        self.provider.assess(
            {"image_bytes": b"image"}
        )

        request = self.client.request.call_args.args[0]

        self.assertIsNone(request["url"])

    def test_payload_must_be_a_mapping(self):
        with self.assertRaises(TypeError):
            self.provider.assess(b"image")

    def test_image_must_be_bytes_like(self):
        with self.assertRaises(TypeError):
            self.provider.assess(
                {"image_bytes": "not bytes"}
            )

    def test_empty_image_is_rejected(self):
        with self.assertRaises(ValueError):
            self.provider.assess(
                {"image_bytes": b""}
            )

    def test_image_size_limit_is_enforced(self):
        with self.assertRaises(ValueError):
            self.provider.assess(
                {"image_bytes": b"x" * 1025}
            )

        self.client.request.assert_not_called()

    def test_url_type_is_validated(self):
        with self.assertRaises(TypeError):
            self.provider.assess(
                {
                    "image_bytes": b"image",
                    "url": 123,
                }
            )

    def test_url_length_limit_is_enforced(self):
        with self.assertRaises(ValueError):
            self.provider.assess(
                {
                    "image_bytes": b"image",
                    "url": "x" * 129,
                }
            )

        self.client.request.assert_not_called()

    def test_missing_worker_result_is_rejected(self):
        self.client.request.return_value = {
            "status": "ok",
        }

        with self.assertRaises(WorkerProtocolError):
            self.provider.assess(
                {"image_bytes": b"image"}
            )

    def test_close_delegates_to_worker_client(self):
        self.provider.close()

        self.client.close.assert_called_once()

    def test_runtime_configuration_is_required(self):
        with patch.dict(
            os.environ,
            {
                "UCP_PHISHVISION_PYTHON": "",
                "UCP_PHISHVISION_ROOT": "",
            },
        ):
            with self.assertRaises(
                PhishVisionProviderConfigurationError
            ):
                PhishVisionProvider.from_environment()

    def test_runtime_configuration_uses_supplied_paths(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            analyzer_path = (
                root / "src" / "security" / "analyzer.py"
            )
            analyzer_path.parent.mkdir(parents=True)
            analyzer_path.write_text(
                "# test analyzer placeholder\n",
                encoding="utf-8",
            )

            with patch.dict(
                os.environ,
                {
                    "UCP_PHISHVISION_PYTHON": sys.executable,
                    "UCP_PHISHVISION_ROOT": str(root),
                },
            ):
                provider = PhishVisionProvider.from_environment()

            try:
                self.assertEqual(provider.name, "phishvision")
            finally:
                provider.close()

    def test_invalid_runtime_root_is_rejected(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            with patch.dict(
                os.environ,
                {
                    "UCP_PHISHVISION_PYTHON": sys.executable,
                    "UCP_PHISHVISION_ROOT": temp_dir,
                },
            ):
                with self.assertRaises(
                    PhishVisionProviderConfigurationError
                ):
                    PhishVisionProvider.from_environment()


if __name__ == "__main__":
    unittest.main()