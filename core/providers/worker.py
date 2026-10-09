from __future__ import annotations

import json
import os
import queue
import subprocess
import threading
from collections.abc import Mapping
from dataclasses import dataclass
from typing import Any, Sequence


PROTOCOL_VERSION = 1
_READ_CHUNK_SIZE = 4096
_EVENT_QUEUE_SIZE = 16
_PROCESS_JOIN_TIMEOUT_SECONDS = 2


@dataclass(frozen=True)
class WorkerClientConfig:
    command: tuple[str, ...]
    startup_timeout_seconds: float
    request_timeout_seconds: float
    max_output_bytes: int
    environment: Mapping[str, str] | None = None
    cwd: str | None = None


class WorkerClientError(RuntimeError):
    """Base exception for persistent worker failures."""


class WorkerStartupError(WorkerClientError):
    """Raised when a worker cannot become ready."""


class WorkerTimeoutError(WorkerClientError):
    """Raised when a worker exceeds its configured timeout."""


class WorkerProtocolError(WorkerClientError):
    """Raised when a worker violates the JSON-line protocol."""


class WorkerResponseError(WorkerClientError):
    """Raised when a worker returns an application-level error."""

    def __init__(
        self,
        message: str,
        error_type: str = "provider_failure",
    ) -> None:
        super().__init__(message)
        self.error_type = error_type


class WorkerClient:
    """
    Persistent JSON-lines subprocess client.

    One request is permitted at a time. Failed workers are discarded so the
    next request starts a fresh worker automatically.
    """

    def __init__(self, config: WorkerClientConfig):
        if not config.command:
            raise ValueError("worker command must not be empty")

        if config.startup_timeout_seconds <= 0:
            raise ValueError(
                "startup_timeout_seconds must be greater than zero"
            )

        if config.request_timeout_seconds <= 0:
            raise ValueError(
                "request_timeout_seconds must be greater than zero"
            )

        if config.max_output_bytes <= 0:
            raise ValueError(
                "max_output_bytes must be greater than zero"
            )

        self._config = config
        self._process: subprocess.Popen[bytes] | None = None

        self._stdout_events: queue.Queue[tuple[str, Any]] = queue.Queue(
            maxsize=_EVENT_QUEUE_SIZE
        )

        self._stderr_bytes = 0
        self._stderr_tail = bytearray()

        self._stdout_thread: threading.Thread | None = None
        self._stderr_thread: threading.Thread | None = None

        self._request_lock = threading.RLock()
        self._lifecycle_lock = threading.RLock()

        self._closed = False

    @property
    def is_running(self) -> bool:
        process = self._process
        return process is not None and process.poll() is None

    @property
    def stderr_tail(self) -> str:
        return bytes(self._stderr_tail).decode(
            "utf-8",
            errors="replace",
        )

    def start(self) -> None:
        with self._lifecycle_lock:
            if self._closed:
                raise WorkerClientError("worker client is closed")

            if self.is_running:
                return

            self._reset_runtime_state()

            environment = os.environ.copy()

            if self._config.environment:
                environment.update(
                    self._config.environment
                )

            try:
                process = subprocess.Popen(
                    list(self._config.command),
                    stdin=subprocess.PIPE,
                    stdout=subprocess.PIPE,
                    stderr=subprocess.PIPE,
                    cwd=self._config.cwd,
                    env=environment,
                    shell=False,
                )
            except OSError as exc:
                raise WorkerStartupError(
                    "worker process could not be started"
                ) from exc

            self._process = process

            self._stdout_thread = threading.Thread(
                target=self._read_stdout,
                args=(process.stdout,),
                daemon=True,
                name="provider-worker-stdout",
            )

            self._stderr_thread = threading.Thread(
                target=self._read_stderr,
                args=(process.stderr,),
                daemon=True,
                name="provider-worker-stderr",
            )

            self._stdout_thread.start()
            self._stderr_thread.start()

            try:
                event_type, value = self._wait_for_event(
                    self._config.startup_timeout_seconds
                )

                if event_type == "error":
                    raise WorkerStartupError(str(value))

                if event_type == "eof":
                    raise WorkerStartupError(
                        "worker exited before sending ready"
                    )

                if event_type != "line":
                    raise WorkerStartupError(
                        "worker produced an invalid startup event"
                    )

                try:
                    response = self._parse_json_line(value)
                except WorkerProtocolError as exc:
                    raise WorkerStartupError(
                        "worker returned invalid startup JSON"
                    ) from exc

                if response.get("status") != "ready":
                    raise WorkerStartupError(
                        "worker did not return a ready response"
                    )

                protocol_version = response.get(
                    "protocol_version"
                )

                if protocol_version != PROTOCOL_VERSION:
                    raise WorkerStartupError(
                        "worker protocol version is unsupported"
                    )

            except queue.Empty as exc:
                self._terminate_process()
                raise WorkerStartupError(
                    "worker startup timed out"
                ) from exc
            except WorkerStartupError:
                self._terminate_process()
                raise

    def request(
        self,
        payload: Mapping[str, Any],
    ) -> dict[str, Any]:
        if not isinstance(payload, Mapping):
            raise TypeError(
                "worker payload must be a mapping"
            )

        with self._request_lock:
            if self._closed:
                raise WorkerClientError(
                    "worker client is closed"
                )

            if not self.is_running:
                self._terminate_process()
                self.start()

            process = self._process

            if process is None or process.stdin is None:
                self._terminate_process()
                raise WorkerClientError(
                    "worker stdin is unavailable"
                )

            request_body = (
                json.dumps(
                    dict(payload),
                    ensure_ascii=False,
                    separators=(",", ":"),
                )
                + "\n"
            ).encode("utf-8")

            try:
                process.stdin.write(request_body)
                process.stdin.flush()
            except (BrokenPipeError, OSError) as exc:
                self._terminate_process()
                raise WorkerClientError(
                    "worker stdin became unavailable"
                ) from exc

            try:
                event_type, value = self._wait_for_event(
                    self._config.request_timeout_seconds
                )
            except queue.Empty as exc:
                self._terminate_process()
                raise WorkerTimeoutError(
                    "worker request timed out"
                ) from exc

            if event_type == "error":
                self._terminate_process()
                raise WorkerProtocolError(str(value))

            if event_type == "eof":
                stderr_tail = self.stderr_tail

                self._terminate_process()

                detail = "worker exited unexpectedly"

                if stderr_tail:
                    detail += f": {stderr_tail}"

                raise WorkerClientError(detail)

            if event_type != "line":
                self._terminate_process()
                raise WorkerProtocolError(
                    "worker returned an invalid response event"
                )


            try:
                response = self._parse_json_line(value)
            except WorkerProtocolError:
                self._terminate_process()
                raise

            if response.get("status") == "error":
                error = response.get("error")

                if isinstance(error, Mapping):
                    message = error.get(
                        "message",
                        "worker returned an error",
                    )
                    raw_error_type = error.get(
                        "type",
                        "provider_failure",
                    )
                    error_type = (
                        raw_error_type
                        if isinstance(raw_error_type, str)
                        else "provider_failure"
                    )
                else:
                    message = "worker returned an error"
                    error_type = "provider_failure"

                raise WorkerResponseError(
                    str(message),
                    error_type=error_type,
                )

            if response.get("status") != "ok":
                self._terminate_process()
                raise WorkerProtocolError(
                    "worker response status must be 'ok'"
                )

            return response

    def close(self) -> None:
        with self._lifecycle_lock:
            self._closed = True
            self._terminate_process()

    def _wait_for_event(
        self,
        timeout_seconds: float,
    ) -> tuple[str, Any]:
        return self._stdout_events.get(
            timeout=timeout_seconds
        )

    def _parse_json_line(
        self,
        raw_line: bytes,
    ) -> dict[str, Any]:
        try:
            value = json.loads(raw_line)
        except json.JSONDecodeError as exc:
            raise WorkerProtocolError(
                "worker returned invalid JSON"
            ) from exc

        if not isinstance(value, dict):
            raise WorkerProtocolError(
                "worker response must be a JSON object"
            )

        return value

    def _read_stdout(self, stream) -> None:
        try:
            while True:
                line = stream.readline(
                    self._config.max_output_bytes + 1
                )

                if not line:
                    self._publish_event(
                        ("eof", None)
                    )
                    return

                line = line.rstrip(b"\r\n")

                if len(line) > self._config.max_output_bytes:
                    self._publish_event(
                        (
                            "error",
                            WorkerProtocolError(
                                "worker response exceeded "
                                "the configured output limit"
                            ),
                        )
                    )
                    self._kill_process()
                    return

                self._publish_event(
                    (
                        "line",
                        line,
                    )
                )

        except Exception:
            self._publish_event(
                (
                    "error",
                    WorkerProtocolError(
                        "worker stdout reader failed"
                    ),
                )
            )
            self._kill_process()

    def _read_stderr(self, stream) -> None:
        try:
            while True:
                chunk = stream.read(_READ_CHUNK_SIZE)

                if not chunk:
                    return

                self._stderr_tail.extend(chunk)

                excess = (
                    len(self._stderr_tail)
                    - self._config.max_output_bytes
                )

                if excess > 0:
                    del self._stderr_tail[:excess]

        except Exception:
            self._kill_process()

    def _publish_event(
        self,
        event: tuple[str, Any],
    ) -> None:
        try:
            self._stdout_events.put(
                event,
                timeout=0.5,
            )
        except queue.Full:
            self._kill_process()

    def _kill_process(self) -> None:
        process = self._process

        if process is None:
            return

        if process.poll() is None:
            try:
                process.kill()
            except OSError:
                pass

    def _terminate_process(self) -> None:
        process = self._process

        if process is None:
            return

        try:
            if process.poll() is None:
                process.kill()

            try:
                process.wait(
                    timeout=_PROCESS_JOIN_TIMEOUT_SECONDS
                )
            except subprocess.TimeoutExpired:
                pass

        finally:
            if process.stdin is not None:
                try:
                    process.stdin.close()
                except OSError:
                    pass

            if process.stdout is not None:
                try:
                    process.stdout.close()
                except OSError:
                    pass

            if process.stderr is not None:
                try:
                    process.stderr.close()
                except OSError:
                    pass

            self._process = None
            self._stdout_thread = None
            self._stderr_thread = None
            self._reset_runtime_state()

    def _reset_runtime_state(self) -> None:
        self._stdout_events = queue.Queue(
            maxsize=_EVENT_QUEUE_SIZE
        )
        self._stderr_bytes = 0
        self._stderr_tail.clear()