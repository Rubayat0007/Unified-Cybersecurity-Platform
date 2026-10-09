import base64
from contextlib import redirect_stdout
from io import BytesIO
import json
import os
from pathlib import Path
import sys
from typing import Any


PROTOCOL_VERSION = 1


class WorkerRequestError(ValueError):
    """Raised when a worker request violates the protocol."""

    def __init__(
        self,
        message: str,
        error_type: str = "invalid_request",
    ) -> None:
        super().__init__(message)
        self.error_type = error_type


def emit(message: dict[str, Any]) -> None:
    sys.stdout.write(
        json.dumps(
            message,
            ensure_ascii=False,
            separators=(",", ":"),
        )
        + "\n"
    )
    sys.stdout.flush()


def _load_runtime():
    project_root = os.environ.get("UCP_PHISHVISION_ROOT")

    if not project_root:
        raise WorkerRequestError(
            "UCP_PHISHVISION_ROOT is not configured"
        )

    root = Path(project_root).resolve()

    if not (root / "src").is_dir():
        raise WorkerRequestError(
            "configured PhishVision project root is invalid"
        )

    sys.path.insert(0, str(root))

    # PhishVision currently emits initialization messages to stdout.
    # Redirect them so stdout remains a strict JSON protocol stream.
    with redirect_stdout(sys.stderr):
        from PIL import Image
        from src.config import (
            MAX_IMAGE_HEIGHT,
            MAX_IMAGE_PIXELS,
            MAX_IMAGE_WIDTH,
            MAX_UPLOAD_SIZE_BYTES,
            MAX_URL_LENGTH,
        )
        from src.security.analyzer import PhishVisionAnalyzer

        analyzer = PhishVisionAnalyzer()

    configured_limit = os.environ.get(
        "UCP_MAX_IMAGE_REQUEST_BYTES"
    )

    if configured_limit is None:
        effective_upload_limit = MAX_UPLOAD_SIZE_BYTES
    else:
        try:
            requested_limit = int(configured_limit)
        except ValueError as exc:
            raise WorkerRequestError(
                "configured image request limit is invalid"
            ) from exc

        if requested_limit <= 0:
            raise WorkerRequestError(
                "configured image request limit must be positive"
            )

        effective_upload_limit = min(
            MAX_UPLOAD_SIZE_BYTES,
            requested_limit,
        )

    return (
        Image,
        analyzer,
        MAX_IMAGE_HEIGHT,
        MAX_IMAGE_PIXELS,
        MAX_IMAGE_WIDTH,
        effective_upload_limit,
        MAX_URL_LENGTH,
    )


def _decode_request(
    request: dict[str, Any],
    *,
    Image,
    max_image_height: int,
    max_image_pixels: int,
    max_image_width: int,
    max_upload_size_bytes: int,
    max_url_length: int,
) -> tuple[Any, str | None]:
    if not isinstance(request, dict):
        raise WorkerRequestError(
            "worker request must be a JSON object"
        )

    encoded_image = request.get("image_base64")

    if not isinstance(encoded_image, str):
        raise WorkerRequestError(
            "image_base64 must be a string"
        )

    if not encoded_image:
        raise WorkerRequestError(
            "image_base64 must not be empty"
        )

    max_encoded_length = ((max_upload_size_bytes + 2) // 3) * 4

    if len(encoded_image) > max_encoded_length:
        raise WorkerRequestError(
            "image exceeds the configured size limit",
            error_type="payload_too_large",
        )

    try:
        image_bytes = base64.b64decode(
            encoded_image,
            validate=True,
        )
    except (ValueError, base64.binascii.Error) as exc:
        raise WorkerRequestError(
            "image_base64 is not valid base64"
        ) from exc

    if not image_bytes:
        raise WorkerRequestError(
            "decoded image is empty"
        )

    if len(image_bytes) > max_upload_size_bytes:
        raise WorkerRequestError(
            "image exceeds the configured size limit",
            error_type="payload_too_large",
        )

    url = request.get("url")

    if url is not None:
        if not isinstance(url, str):
            raise WorkerRequestError(
                "url must be a string or null"
            )

        if len(url) > max_url_length:
            raise WorkerRequestError(
                "url exceeds the configured length limit"
            )

        if not url.strip():
            url = None
        else:
            url = url.strip()

    try:
        image_stream = BytesIO(image_bytes)
        image = Image.open(image_stream)
        image.load()

        width, height = image.size

        if width <= 0 or height <= 0:
            raise WorkerRequestError(
                "image dimensions must be greater than zero"
            )

        if width > max_image_width:
            raise WorkerRequestError(
                "image width exceeds the configured limit"
            )

        if height > max_image_height:
            raise WorkerRequestError(
                "image height exceeds the configured limit"
            )

        if width * height > max_image_pixels:
            raise WorkerRequestError(
                "image pixel count exceeds the configured limit"
            )

        image = image.convert("RGB")

        return image, url

    except WorkerRequestError:
        raise
    except Exception as exc:
        raise WorkerRequestError(
            "uploaded image could not be decoded safely"
        ) from exc


def main() -> int:
    try:
        (
            Image,
            analyzer,
            max_image_height,
            max_image_pixels,
            max_image_width,
            max_upload_size_bytes,
            max_url_length,
        ) = _load_runtime()

    except Exception as exc:
        print(
            f"PhishVision worker startup failed: "
            f"{type(exc).__name__}: {exc}",
            file=sys.stderr,
        )
        return 2

    emit(
        {
            "status": "ready",
            "protocol_version": PROTOCOL_VERSION,
        }
    )

    for raw_line in sys.stdin:
        line = raw_line.strip()

        if not line:
            continue

        try:
            request = json.loads(line)

            image, url = _decode_request(
                request,
                Image=Image,
                max_image_height=max_image_height,
                max_image_pixels=max_image_pixels,
                max_image_width=max_image_width,
                max_upload_size_bytes=max_upload_size_bytes,
                max_url_length=max_url_length,
            )

            # Keep the provider protocol clean: PhishVision diagnostics
            # must go to stderr rather than corrupt JSON stdout.
            with redirect_stdout(sys.stderr):
                result = analyzer.analyze(
                    image,
                    url,
                )

            emit(
                {
                    "status": "ok",
                    "result": result,
                }
            )

        except json.JSONDecodeError:
            emit(
                {
                    "status": "error",
                    "error": {
                        "type": "invalid_json",
                        "message": "worker request was not valid JSON",
                    },
                }
            )

        except WorkerRequestError as exc:
            emit(
                {
                    "status": "error",
                    "error": {
                        "type": exc.error_type,
                        "message": str(exc),
                    },
                }
            )

        except Exception as exc:
            print(
                f"PhishVision worker request failed: "
                f"{type(exc).__name__}: {exc}",
                file=sys.stderr,
            )

            emit(
                {
                    "status": "error",
                    "error": {
                        "type": "provider_failure",
                        "message": "PhishVision analysis failed",
                    },
                }
            )

    return 0


if __name__ == "__main__":
    raise SystemExit(main())