"""Authentication and rate limiting for the assessment API.

Design notes:
- The token comes from the environment; there is no default.
- In `production` mode a missing token is a startup error, not a warning.
- `development` and `test` run unauthenticated so local work and the existing
  suite keep working; that is stated in the API contract.
- Comparison uses `hmac.compare_digest`; rate limiting is per client address
  with a token bucket, so a burst is allowed but sustained floods are not.
"""

from __future__ import annotations

import hmac
import os
import threading
import time
from collections.abc import Mapping

PUBLIC_PATHS = frozenset({"/health", "/ready"})
PUBLIC_PREFIXES = ("/dashboard", "/docs", "/redoc", "/openapi.json")

DEFAULT_RATE_CAPACITY = 30
DEFAULT_RATE_REFILL = 1.0


def resolve_token(environment: str, environ: Mapping[str, str] | None = None) -> str | None:
    """Return the configured token, or None when auth is disabled."""
    values = environ if environ is not None else os.environ
    token = (values.get("UCP_API_TOKEN") or "").strip()

    if token:
        return token

    if environment == "production":
        raise RuntimeError(
            "UCP_API_TOKEN must be set when UCP_ENVIRONMENT=production"
        )

    return None


def resolve_rate_limit(
    environment: str,
    environ: Mapping[str, str] | None = None,
) -> tuple[int, float] | None:
    """Return (capacity, refill_per_second), or None when disabled.

    Production is always rate limited. Development and test are only limited
    when configured explicitly, so local work and the test suite are not
    throttled.
    """
    values = environ if environ is not None else os.environ

    if environment != "production" and not (
        values.get("UCP_RATE_LIMIT_CAPACITY")
        or values.get("UCP_RATE_LIMIT_REFILL_PER_SECOND")
    ):
        return None

    def positive(name: str, default):
        raw = values.get(name)
        if raw is None or not str(raw).strip():
            return default
        try:
            value = type(default)(raw)
        except ValueError as exc:
            raise ValueError(f"{name} must be numeric") from exc
        if value <= 0:
            raise ValueError(f"{name} must be greater than zero")
        return value

    return (
        positive("UCP_RATE_LIMIT_CAPACITY", DEFAULT_RATE_CAPACITY),
        positive("UCP_RATE_LIMIT_REFILL_PER_SECOND", DEFAULT_RATE_REFILL),
    )


class TokenBucket:
    """Per-client token bucket, safe for concurrent use."""

    def __init__(self, capacity: int, refill_per_second: float, clock=time.monotonic):
        if capacity <= 0 or refill_per_second <= 0:
            raise ValueError("capacity and refill must be positive")
        self.capacity = float(capacity)
        self.refill = float(refill_per_second)
        self.clock = clock
        self._lock = threading.Lock()
        self._state: dict[str, tuple[float, float]] = {}

    def consume(self, key: str) -> tuple[bool, float]:
        """Take one token; return (allowed, retry_after_seconds)."""
        now = self.clock()

        with self._lock:
            tokens, last = self._state.get(key, (self.capacity, now))
            tokens = min(self.capacity, tokens + (now - last) * self.refill)

            if tokens >= 1.0:
                self._state[key] = (tokens - 1.0, now)
                return True, 0.0

            self._state[key] = (tokens, now)
            return False, round((1.0 - tokens) / self.refill, 3)


class TokenAuthMiddleware:
    def __init__(self, app, token: str | None):
        self.app = app
        self.token = token

    @staticmethod
    def _is_public(path: str) -> bool:
        return path in PUBLIC_PATHS or path.startswith(PUBLIC_PREFIXES)

    def _authorized(self, headers) -> bool:
        raw = b""

        for name, value in headers:
            if name.lower() == b"authorization":
                raw = value
                break

        scheme, _, presented = raw.decode("latin-1").partition(" ")

        if scheme.lower() != "bearer" or not presented:
            return False

        return hmac.compare_digest(presented, self.token or "")

    async def __call__(self, scope, receive, send):
        if scope["type"] != "http" or self.token is None:
            await self.app(scope, receive, send)
            return

        if self._is_public(scope["path"]):
            await self.app(scope, receive, send)
            return

        if not self._authorized(scope.get("headers", [])):
            await self._reject(
                send,
                401,
                {"detail": "missing or invalid bearer token"},
                [(b"www-authenticate", b"Bearer")],
            )
            return

        await self.app(scope, receive, send)

    @staticmethod
    async def _reject(send, status: int, payload: dict, extra_headers=()):
        import json

        body = json.dumps(payload).encode()
        headers = [
            (b"content-type", b"application/json"),
            (b"content-length", str(len(body)).encode()),
            *extra_headers,
        ]
        await send({"type": "http.response.start", "status": status, "headers": headers})
        await send({"type": "http.response.body", "body": body})


class RateLimitMiddleware:
    def __init__(self, app, bucket: TokenBucket):
        self.app = app
        self.bucket = bucket

    async def __call__(self, scope, receive, send):
        if scope["type"] != "http":
            await self.app(scope, receive, send)
            return

        client = scope.get("client") or ("unknown", 0)
        allowed, retry_after = self.bucket.consume(str(client[0]))

        if not allowed:
            import json

            body = json.dumps({"detail": "rate limit exceeded"}).encode()
            headers = [
                (b"content-type", b"application/json"),
                (b"content-length", str(len(body)).encode()),
                (b"retry-after", str(max(1, int(retry_after + 0.999))).encode()),
            ]
            await send({"type": "http.response.start", "status": 429, "headers": headers})
            await send({"type": "http.response.body", "body": body})
            return

        await self.app(scope, receive, send)
