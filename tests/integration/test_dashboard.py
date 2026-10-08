import unittest

from fastapi.testclient import TestClient

from api.app import app


class TestDashboard(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.client = TestClient(app)

    def test_dashboard_is_served(self):
        response = self.client.get("/dashboard/")

        self.assertEqual(response.status_code, 200)
        self.assertIn(
            "Unified Cybersecurity Platform",
            response.text,
        )

    def test_dashboard_contains_assessment_controls(self):
        response = self.client.get("/dashboard/")

        self.assertIn(
            "Run Demo Assessment",
            response.text,
        )
        self.assertIn(
            "/v1/assess",
            response.text,
        )

    def test_dashboard_is_not_an_api_error_page(self):
        response = self.client.get("/dashboard/")

        self.assertNotIn(
            "Internal Server Error",
            response.text,
        )


    def test_dashboard_contains_audit_fields(self):
        response = self.client.get("/dashboard/")

        self.assertEqual(response.status_code, 200)
        self.assertIn('id="event-id"', response.text)
        self.assertIn('id="processed-at"', response.text)
        self.assertIn("payload.audit.event_id", response.text)


if __name__ == "__main__":
    unittest.main()