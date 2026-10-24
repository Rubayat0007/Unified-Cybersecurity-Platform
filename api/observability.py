"""Structured request logging and in-process metrics.

One JSON line per request: request id, method, path, status, duration. Never the
query string, headers, or body - a URL or an Authorization header must not reach
the logs.
"""

from __future__ import annotations

import json
import logging
import time
import uuid
from collections import Counter

logger = logging.getLogger("ucp.request")


class Metrics:
    def __init__(self) -> None:
        self.by_status_class: Counter = Counter()
        self.requests_total = 0
        self.duration_ms_total = 0.0
        self.rejections = 0

    def record(self, status: int, duration_ms: float) -> None:
        self.requests_total += 1
        self.duration_ms_total += duration_ms
        self.by_status_class[f"{status // 100}xx"] += 1
        if status in (401, 403):
            self.rejections += 1

    def snapshot(self) -> dict:
        average = (self.duration_ms_total / self.requests_total
                   if self.requests_total else 0.0)
        return {
            "requests_total": self.requests_total,
            "by_status_class": dict(sorted(self.by_status_class.items())),
            "rejections": self.rejections,
            "average_duration_ms": round(average, 3),
        }


metrics = Metrics()


class JsonRequestLogMiddleware:
    def __init__(self, app):
        self.app = app

    async def __call__(self, scope, receive, send):
        if scope["type"] != "http":
            await self.app(scope, receive, send)
            return

        request_id = str(uuid.uuid4())
        started = time.perf_counter()
        status_holder = {"status": 500}

        async def send_wrapper(message):
            if message["type"] == "http.response.start":
                status_holder["status"] = message["status"]
            await send(message)

        try:
            await self.app(scope, receive, send_wrapper)
        finally:
            duration_ms = (time.perf_counter() - started) * 1000.0
            status = status_holder["status"]
            metrics.record(status, duration_ms)
            logger.info(json.dumps({
                "request_id": request_id,
                "method": scope.get("method"),
                "path": scope.get("path"),
                "status": status,
                "duration_ms": round(duration_ms, 3),
            }, separators=(",", ":")))
