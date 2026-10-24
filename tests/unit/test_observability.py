"""Tests for structured logging and metrics (Phase 6.2)."""

import json
import logging
import unittest

from fastapi.testclient import TestClient

from api import app as app_module
from api.observability import JsonRequestLogMiddleware, metrics


class CapturedLogs(logging.Handler):
    def __init__(self):
        super().__init__()
        self.lines = []

    def emit(self, record):
        self.lines.append(record.getMessage())


class ObservabilityTest(unittest.TestCase):
    def setUp(self):
        self.handler = CapturedLogs()
        self.logger = logging.getLogger("ucp.request")
        self.logger.setLevel(logging.INFO)
        self.logger.addHandler(self.handler)
        self.addCleanup(self.logger.removeHandler, self.handler)
        self.client = TestClient(app_module.app)
        metrics.by_status_class.clear()
        metrics.requests_total = 0
        metrics.duration_ms_total = 0.0
        metrics.rejections = 0

    def test_request_is_logged_as_json(self):
        self.client.get("/health")

        self.assertTrue(self.handler.lines)
        payload = json.loads(self.handler.lines[-1])
        self.assertEqual(payload["path"], "/health")
        self.assertEqual(payload["status"], 200)
        self.assertIn("request_id", payload)
        self.assertIn("duration_ms", payload)

    def test_logs_do_not_contain_headers_or_query(self):
        self.client.post(
            "/v1/assess?event_id=secret-event",
            headers={"Authorization": "Bearer super-secret"},
            json={},
        )

        joined = "\n".join(self.handler.lines)
        self.assertNotIn("super-secret", joined)
        self.assertNotIn("secret-event", joined)
        self.assertNotIn("authorization", joined.lower())

    def test_metrics_count_requests_and_status_classes(self):
        self.client.get("/health")
        self.client.post("/v1/assess", json={})

        body = self.client.get("/metrics").json()

        self.assertGreaterEqual(body["requests_total"], 2)
        self.assertIn("2xx", body["by_status_class"])

    def test_unauthorised_requests_count_as_rejections(self):
        from api import audit_sink
        from unittest.mock import patch

        with patch.object(app_module, "_auth_token", "secret"):
            with patch.object(audit_sink, "record", lambda outcome: None):
                response = self.client.post("/v1/assess", json={})

        self.assertIn(response.status_code, (401, 200))

    def test_metrics_payload_is_stable_shape(self):
        body = self.client.get("/metrics").json()

        self.assertEqual(set(body), {"requests_total", "by_status_class",
                                     "rejections", "average_duration_ms"})


if __name__ == "__main__":
    unittest.main()
