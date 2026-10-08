from starlette.responses import JSONResponse
from starlette.types import ASGIApp, Message, Receive, Scope, Send


class RequestBodyTooLarge(Exception):
    pass


class MaxRequestBodySizeMiddleware:
    def __init__(self, app: ASGIApp, max_body_size: int):
        self.app = app
        self.max_body_size = max_body_size

    async def __call__(
        self,
        scope: Scope,
        receive: Receive,
        send: Send,
    ) -> None:
        if scope["type"] != "http":
            await self.app(scope, receive, send)
            return

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

            if declared_length > self.max_body_size:
                response = JSONResponse(
                    status_code=413,
                    content={
                        "detail": (
                            "request body exceeds the configured size limit"
                        )
                    },
                )
                await response(scope, receive, send)
                return

        received_bytes = 0

        async def limited_receive() -> Message:
            nonlocal received_bytes

            message = await receive()

            if message["type"] == "http.request":
                body = message.get("body", b"")
                received_bytes += len(body)

                if received_bytes > self.max_body_size:
                    raise RequestBodyTooLarge

            return message

        try:
            await self.app(scope, limited_receive, send)
        except RequestBodyTooLarge:
            response = JSONResponse(
                status_code=413,
                content={
                    "detail": (
                        "request body exceeds the configured size limit"
                    )
                },
            )
            await response(scope, receive, send)