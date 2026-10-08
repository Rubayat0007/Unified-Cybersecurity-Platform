import os
import unittest

from core.config.settings import load_settings


class TestSettings(unittest.TestCase):
    def tearDown(self):
        for name in (
            "UCP_ENVIRONMENT",
            "UCP_LOG_LEVEL",
            "UCP_REQUEST_TIMEOUT_SECONDS",
            "UCP_MAX_REQUEST_BYTES",
            "UCP_AI_NIDS_ENABLED",
            "UCP_PHISHVISION_ENABLED",
            "UCP_PROVIDER_TIMEOUT_SECONDS",
            "UCP_PROVIDER_MAX_OUTPUT_BYTES",
        ):
            os.environ.pop(name, None)

    def test_defaults_are_safe_for_local_development(self):
        settings = load_settings()

        self.assertEqual(
            settings.environment,
            "development",
        )
        self.assertEqual(
            settings.request_timeout_seconds,
            10,
        )
        self.assertEqual(
            settings.max_request_bytes,
            1_048_576,
        )
        self.assertTrue(settings.ai_nids_enabled)
        self.assertTrue(settings.phishvision_enabled)

    def test_boolean_configuration_is_parsed(self):
        os.environ["UCP_AI_NIDS_ENABLED"] = "false"
        os.environ["UCP_PHISHVISION_ENABLED"] = "0"

        settings = load_settings()

        self.assertFalse(settings.ai_nids_enabled)
        self.assertFalse(settings.phishvision_enabled)

    def test_invalid_environment_is_rejected(self):
        os.environ["UCP_ENVIRONMENT"] = "unknown"

        with self.assertRaises(ValueError):
            load_settings()

    def test_invalid_timeout_is_rejected(self):
        os.environ["UCP_REQUEST_TIMEOUT_SECONDS"] = "0"

        with self.assertRaises(ValueError):
            load_settings()



    def test_provider_runtime_defaults_are_safe(self):
        settings = load_settings()

        self.assertEqual(
            settings.provider_timeout_seconds,
            10,
        )
        self.assertEqual(
            settings.provider_max_output_bytes,
            1_048_576,
        )

    def test_invalid_provider_timeout_is_rejected(self):
        os.environ["UCP_PROVIDER_TIMEOUT_SECONDS"] = "0"

        with self.assertRaises(ValueError):
            load_settings()


if __name__ == "__main__":
    unittest.main()