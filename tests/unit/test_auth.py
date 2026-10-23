"""Tests for token authentication and rate limiting."""

import unittest

from fastapi import FastAPI
from fastapi.testclient import TestClient

from api.auth import (
    RateLimitMiddleware,
    TokenAuthMiddleware,
    TokenBucket,
    resolve_rate_limit,
    resolve_token,
)


def build_app(token=None, capacity=3, refill=1.0, clock=None):
    app = FastAPI()

    @app.get("/health")
    def health():
        return {"status": "ok"}

    @app.post("/v1/assess")
    def assess():
        return {"ok": True}

    bucket = TokenBucket(capacity, refill, clock=clock or (lambda: 0.0))
    app.add_middleware(TokenAuthMiddleware, token=token)
    app.add_middleware(RateLimitMiddleware, bucket=bucket)
    return app


class TokenAuthTest(unittest.TestCase):
    def test_public_path_needs_no_token(self):
        client = TestClient(build_app(token="secret"))

        self.assertEqual(client.get("/health").status_code, 200)

    def test_missing_token_is_rejected(self):
        client = TestClient(build_app(token="secret"))

        response = client.post("/v1/assess")

        self.assertEqual(response.status_code, 401)
        self.assertIn("www-authenticate", response.headers)
        self.assertEqual(response.json()["detail"], "missing or invalid bearer token")

    def test_wrong_token_is_rejected(self):
        client = TestClient(build_app(token="secret"))

        response = client.post("/v1/assess", headers={"Authorization": "Bearer nope"})

        self.assertEqual(response.status_code, 401)

    def test_correct_token_is_accepted(self):
        client = TestClient(build_app(token="secret"))

        response = client.post("/v1/assess", headers={"Authorization": "Bearer secret"})

        self.assertEqual(response.status_code, 200)

    def test_scheme_is_case_insensitive(self):
        client = TestClient(build_app(token="secret"))

        response = client.post("/v1/assess", headers={"Authorization": "bearer secret"})

        self.assertEqual(response.status_code, 200)

    def test_non_bearer_scheme_is_rejected(self):
        client = TestClient(build_app(token="secret"))

        response = client.post("/v1/assess", headers={"Authorization": "Basic c2VjcmV0"})

        self.assertEqual(response.status_code, 401)

    def test_auth_disabled_when_no_token(self):
        client = TestClient(build_app(token=None))

        self.assertEqual(client.post("/v1/assess").status_code, 200)


class RateLimitTest(unittest.TestCase):
    def test_burst_is_allowed_then_limited(self):
        now = [0.0]
        client = TestClient(build_app(token=None, capacity=2, refill=1.0, clock=lambda: now[0]))

        self.assertEqual(client.post("/v1/assess").status_code, 200)
        self.assertEqual(client.post("/v1/assess").status_code, 200)

        blocked = client.post("/v1/assess")

        self.assertEqual(blocked.status_code, 429)
        self.assertIn("retry-after", blocked.headers)
        self.assertEqual(blocked.json()["detail"], "rate limit exceeded")

    def test_tokens_refill_over_time(self):
        now = [0.0]
        client = TestClient(build_app(token=None, capacity=1, refill=1.0, clock=lambda: now[0]))

        self.assertEqual(client.post("/v1/assess").status_code, 200)
        self.assertEqual(client.post("/v1/assess").status_code, 429)

        now[0] = 1.0
        self.assertEqual(client.post("/v1/assess").status_code, 200)


class ConfigurationTest(unittest.TestCase):
    def test_token_from_environment(self):
        self.assertEqual(resolve_token("development", {"UCP_API_TOKEN": " abc "}), "abc")

    def test_production_requires_token(self):
        with self.assertRaises(RuntimeError):
            resolve_token("production", {})

    def test_development_allows_absent_token(self):
        self.assertIsNone(resolve_token("development", {}))

    def test_rate_limit_disabled_in_development_by_default(self):
        self.assertIsNone(resolve_rate_limit("development", {}))

    def test_rate_limit_enabled_in_development_when_configured(self):
        self.assertEqual(
            resolve_rate_limit("development", {"UCP_RATE_LIMIT_CAPACITY": "5"}),
            (5, 1.0),
        )

    def test_rate_limit_defaults_in_production(self):
        self.assertEqual(resolve_rate_limit("production", {}), (30, 1.0))

    def test_rate_limit_parsing(self):
        self.assertEqual(
            resolve_rate_limit(
                "production",
                {"UCP_RATE_LIMIT_CAPACITY": "5", "UCP_RATE_LIMIT_REFILL_PER_SECOND": "0.5"},
            ),
            (5, 0.5),
        )

    def test_rate_limit_rejects_invalid_values(self):
        for values in (
            {"UCP_RATE_LIMIT_CAPACITY": "0"},
            {"UCP_RATE_LIMIT_CAPACITY": "abc"},
            {"UCP_RATE_LIMIT_REFILL_PER_SECOND": "-1"},
        ):
            with self.assertRaises(ValueError):
                resolve_rate_limit("production", values)


class BucketTest(unittest.TestCase):
    def test_rejects_invalid_construction(self):
        with self.assertRaises(ValueError):
            TokenBucket(0, 1.0)
        with self.assertRaises(ValueError):
            TokenBucket(1, 0.0)

    def test_clients_are_isolated(self):
        bucket = TokenBucket(1, 1.0, clock=lambda: 0.0)

        self.assertEqual(bucket.consume("a")[0], True)
        self.assertEqual(bucket.consume("a")[0], False)
        self.assertEqual(bucket.consume("b")[0], True)


if __name__ == "__main__":
    unittest.main()
