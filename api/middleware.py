
from collections.abc import Mapping

from starlette.responses import JSONResponse
from starlette.types import ASGIApp, Message, Receive, Scope, Send


class RequestBodyTooLarge(Exception):
    """Raised when a request body exceeds its path-specific limit."""


class MaxRequestBodySizeMiddleware:
    def __init__(
        self,
        app: ASGIApp,
        max_body_size: int,
        path_limits: Mapping[str, int] | None = None,
    ):
        if max_body_size <= 0:
            raise ValueError("max_body_size must be greater than zero")

        self.app = app
        self.max_body_size = max_body_size
        self.path_limits = dict(path_limits or {})

        for path, limit in self.path_limits.items():
            if not path.startswith("/"):
                raise ValueError("path limit keys must be absolute paths")
            if limit <= 0:
                raise ValueError("path-specific limits must be positive")

    async def __call__(
        self,
        scope: Scope,
        receive: Receive,
        send: Send,
    ) -> None:
        if scope["type"] != "http":
            await self.app(scope, receive, send)
            return

        request_path = scope.get("path", "")
        body_limit = self.path_limits.get(
            request_path,
            self.max_body_size,
        )

        headers = dict(scope.get("headers", []))
        content_length = headers.get(b"content-length")

        if content_length is not None:
            try:
                declared_length = int(content_length)
            except ValueError:
                response = JSONResponse(
                    status_code=400,
                    content={"detail": "invalid Content-Length header"},
                )
                await response(scope, receive, send)
                return

            if declared_length < 0:
                response = JSONResponse(
                    status_code=400,
                    content={"detail": "invalid Content-Length header"},
                )
                await response(scope, receive, send)
                return

            if declared_length > body_limit:
                response = JSONResponse(
                    status_code=413,
                    content={
                        "detail": "request body exceeds the configured size limit"
                    },
                )
                await response(scope, receive, send)
                return

        received_bytes = 0

        async def limited_receive() -> Message:
            nonlocal received_bytes

            message = await receive()

            if message["type"] == "http.request":
                received_bytes += len(message.get("body", b""))

                if received_bytes > body_limit:
                    raise RequestBodyTooLarge

            return message

        try:
            await self.app(scope, limited_receive, send)
        except RequestBodyTooLarge:
            response = JSONResponse(
                status_code=413,
                content={
                    "detail": "request body exceeds the configured size limit"
                },
            )
            await response(scope, receive, send)
