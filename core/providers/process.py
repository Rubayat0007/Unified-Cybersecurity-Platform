from dataclasses import dataclass
import json
import subprocess
import tempfile
import threading
import time
from typing import Any, Sequence


@dataclass(frozen=True)
class ProcessExecutionResult:
    return_code: int
    stdout: str
    stderr: str
    timed_out: bool


class ProviderProcessError(RuntimeError):
    """Raised when a provider process cannot produce a valid result."""


def _read_stream(
    stream,
    output: bytearray,
    max_output_bytes: int,
    output_exceeded: threading.Event,
) -> None:
    while True:
        chunk = stream.read(4096)

        if not chunk:
            return

        output.extend(chunk)

        if len(output) > max_output_bytes:
            output_exceeded.set()
            return


def execute_json_process(
    command: Sequence[str],
    payload: dict[str, Any],
    timeout_seconds: int,
    max_output_bytes: int,
) -> ProcessExecutionResult:
    if not command:
        raise ValueError("provider command must not be empty")

    if timeout_seconds <= 0:
        raise ValueError("timeout_seconds must be greater than zero")

    if max_output_bytes <= 0:
        raise ValueError("max_output_bytes must be greater than zero")

    request_body = json.dumps(
        payload,
        ensure_ascii=False,
    ).encode("utf-8")

    stdout_buffer = bytearray()
    stderr_buffer = bytearray()
    output_exceeded = threading.Event()
    process = None

    try:
        with tempfile.TemporaryFile() as stdin_file:
            stdin_file.write(request_body)
            stdin_file.seek(0)

            process = subprocess.Popen(
                list(command),
                stdin=stdin_file,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                shell=False,
            )

            stdout_thread = threading.Thread(
                target=_read_stream,
                args=(
                    process.stdout,
                    stdout_buffer,
                    max_output_bytes,
                    output_exceeded,
                ),
                daemon=True,
            )

            stderr_thread = threading.Thread(
                target=_read_stream,
                args=(
                    process.stderr,
                    stderr_buffer,
                    max_output_bytes,
                    output_exceeded,
                ),
                daemon=True,
            )

            stdout_thread.start()
            stderr_thread.start()

            deadline = time.monotonic() + timeout_seconds
            timed_out = False

            while process.poll() is None:
                if output_exceeded.is_set():
                    process.kill()
                    process.wait()
                    break

                if time.monotonic() >= deadline:
                    timed_out = True
                    process.kill()
                    process.wait()
                    break

                time.sleep(0.01)

            stdout_thread.join()
            stderr_thread.join()

            if output_exceeded.is_set():
                raise ProviderProcessError(
                    "provider process output exceeded the configured size limit"
                )

            return ProcessExecutionResult(
                return_code=-1 if timed_out else process.returncode,
                stdout=bytes(stdout_buffer).decode(
                    "utf-8",
                    errors="replace",
                ),
                stderr=bytes(stderr_buffer).decode(
                    "utf-8",
                    errors="replace",
                ),
                timed_out=timed_out,
            )

    except ProviderProcessError:
        raise
    except OSError as exc:
        raise ProviderProcessError(
            f"provider process could not be started: {type(exc).__name__}"
        ) from exc

    finally:
        if process is not None:
            if process.stdout is not None:
                process.stdout.close()

            if process.stderr is not None:
                process.stderr.close()


def parse_json_stdout(
    result: ProcessExecutionResult,
) -> dict[str, Any]:
    if result.timed_out:
        raise ProviderProcessError(
            "provider process timed out"
        )

    if result.return_code != 0:
        raise ProviderProcessError(
            f"provider process exited with code {result.return_code}"
        )

    if not result.stdout.strip():
        raise ProviderProcessError(
            "provider process returned empty stdout"
        )

    try:
        value = json.loads(result.stdout)
    except json.JSONDecodeError as exc:
        raise ProviderProcessError(
            "provider process returned invalid JSON"
        ) from exc

    if not isinstance(value, dict):
        raise ProviderProcessError(
            "provider process must return a JSON object"
        )

    return value