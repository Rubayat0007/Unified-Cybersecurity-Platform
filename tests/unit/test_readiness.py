"""Readiness must describe the real component state (Lane B, Step 1.7)."""

import unittest

from fastapi.testclient import TestClient

from api import app as app_module


class ReadinessTest(unittest.TestCase):
    def setUp(self):
        self.client = TestClient(app_module.app)
        self.saved_provider = app_module._phishvision_provider

    def tearDown(self):
        app_module._phishvision_provider = self.saved_provider

    def test_provider_not_started_before_first_request(self):
        app_module._phishvision_provider = None

        body = self.client.get("/ready").json()

        self.assertEqual(body["components"]["phishvision"], "not_started")
        self.assertEqual(body["components"]["ai_nids"], "ingestion_only")

    def test_started_provider_is_reported(self):
        app_module._phishvision_provider = object()

        body = self.client.get("/ready").json()

        self.assertEqual(body["components"]["phishvision"], "started")

    def test_disabled_provider_is_reported(self):
        app_module._phishvision_provider = None
        original = app_module.settings

        class Disabled:
            phishvision_enabled = False
            ai_nids_enabled = True

        app_module.settings = Disabled()
        try:
            body = self.client.get("/ready").json()
        finally:
            app_module.settings = original

        self.assertEqual(body["components"]["phishvision"], "disabled")

    def test_static_degraded_is_gone(self):
        body = self.client.get("/ready").json()

        self.assertNotIn("degraded", body["components"].values())


if __name__ == "__main__":
    unittest.main()
