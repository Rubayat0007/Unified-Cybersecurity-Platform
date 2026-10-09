import os
from pathlib import Path
import sys
import tempfile
import textwrap
import unittest

from core.providers.worker import (
    WorkerClient,
    WorkerClientConfig,
    WorkerClientError,
    WorkerProtocolError,
    WorkerResponseError,
    WorkerStartupError,
    WorkerTimeoutError,
)


class TestWorkerClient(unittest.TestCase):
    def _config(
        self,
        script: str,
        *,
        startup_timeout=2,
        request_timeout=2,
        max_output_bytes=1024,
        environment=None,
    ):
        return WorkerClientConfig(
            command=(
                sys.executable,
                "-u",
                "-c",
                textwrap.dedent(script),
            ),
            startup_timeout_seconds=startup_timeout,
            request_timeout_seconds=request_timeout,
            max_output_bytes=max_output_bytes,
            environment=environment,
        )

    def test_successful_request(self):
        client = WorkerClient(
            self._config(
                """
                import json
                import sys

                print(json.dumps({
                    "status": "ready",
                    "protocol_version": 1
                }), flush=True)

                for line in sys.stdin:
                    request = json.loads(line)
                    print(json.dumps({
                        "status": "ok",
                        "result": request
                    }), flush=True)
                """
            )
        )

        try:
            response = client.request(
                {"event_id": "evt-1"}
            )

            self.assertEqual(
                response["status"],
                "ok",
            )
            self.assertEqual(
                response["result"],
                {"event_id": "evt-1"},
            )
            self.assertTrue(client.is_running)

        finally:
            client.close()

    def test_worker_error_response_is_rejected(self):
        client = WorkerClient(
            self._config(
                """
                import json
                import sys

                print(json.dumps({
                    "status": "ready",
                    "protocol_version": 1
                }), flush=True)

                for _ in sys.stdin:
                    print(json.dumps({
                        "status": "error",
                        "error": {
                            "type": "invalid_request",
                            "message": "bad request"
                        }
                    }), flush=True)
                """
            )
        )

        try:
            with self.assertRaises(WorkerResponseError):
                client.request({})
        finally:
            client.close()

    def test_invalid_json_response_is_rejected(self):
        client = WorkerClient(
            self._config(
                """
                import sys

                print(
                    '{"status":"ready","protocol_version":1}',
                    flush=True,
                )

                for _ in sys.stdin:
                    print("not-json", flush=True)
                """
            )
        )

        try:
            with self.assertRaises(WorkerProtocolError):
                client.request({})
        finally:
            client.close()

    def test_startup_timeout_is_rejected(self):
        client = WorkerClient(
            self._config(
                """
                import time
                time.sleep(2)
                """,
                startup_timeout=0.2,
            )
        )

        with self.assertRaises(WorkerStartupError):
            client.start()

        client.close()

    def test_request_timeout_is_rejected(self):
        client = WorkerClient(
            self._config(
                """
                import json
                import sys
                import time

                print(json.dumps({
                    "status": "ready",
                    "protocol_version": 1
                }), flush=True)

                for _ in sys.stdin:
                    time.sleep(2)
                """,
                request_timeout=0.2,
            )
        )

        try:
            with self.assertRaises(WorkerTimeoutError):
                client.request({})
        finally:
            client.close()

    def test_oversized_stdout_is_rejected(self):
        client = WorkerClient(
            self._config(
                """
                import json
                import sys

                print(json.dumps({
                    "status": "ready",
                    "protocol_version": 1
                }), flush=True)

                for _ in sys.stdin:
                    print("x" * 5000, flush=True)
                """,
                max_output_bytes=1024,
            )
        )

        try:
            with self.assertRaises(WorkerProtocolError):
                client.request({})
        finally:
            client.close()

    def test_crashed_worker_is_restarted_on_next_request(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            marker = Path(temp_dir) / "started.marker"

            client = WorkerClient(
                self._config(
                    """
                    import json
                    import os
                    from pathlib import Path
                    import sys

                    print(json.dumps({
                        "status": "ready",
                        "protocol_version": 1
                    }), flush=True)

                    marker = Path(
                        os.environ["UCP_TEST_WORKER_MARKER"]
                    )

                    for line in sys.stdin:
                        if not marker.exists():
                            marker.touch()
                            raise SystemExit(7)

                        print(json.dumps({
                            "status": "ok",
                            "result": json.loads(line)
                        }), flush=True)
                    """,
                    environment={
                        "UCP_TEST_WORKER_MARKER": str(marker)
                    },
                )
            )

            try:
                with self.assertRaises(WorkerClientError):
                    client.request({"attempt": 1})

                self.assertFalse(
                    client.is_running
                )

                response = client.request(
                    {"attempt": 2}
                )

                self.assertEqual(
                    response["result"]["attempt"],
                    2,
                )

            finally:
                client.close()

    def test_close_prevents_future_start(self):
        client = WorkerClient(
            self._config(
                """
                import json
                print(json.dumps({
                    "status": "ready",
                    "protocol_version": 1
                }), flush=True)
                """
            )
        )

        client.close()

        with self.assertRaises(WorkerClientError):
            client.request({})

    def test_invalid_configuration_is_rejected(self):
        with self.assertRaises(ValueError):
            WorkerClient(
                WorkerClientConfig(
                    command=(),
                    startup_timeout_seconds=2,
                    request_timeout_seconds=2,
                    max_output_bytes=1024,
                )
            )


    def test_invalid_startup_json_is_rejected(self):
        client = WorkerClient(
            self._config(
                """
                print("not-json", flush=True)
                """
            )
        )

        with self.assertRaises(WorkerStartupError):
            client.start()

        self.assertFalse(client.is_running)
        client.close()

    def test_invalid_response_discards_worker(self):
        client = WorkerClient(
            self._config(
                """
                import json
                import sys

                print(json.dumps({
                    "status": "ready",
                    "protocol_version": 1
                }), flush=True)

                for _ in sys.stdin:
                    print("not-json", flush=True)
                """
            )
        )

        try:
            with self.assertRaises(WorkerProtocolError):
                client.request({})

            self.assertFalse(client.is_running)

        finally:
            client.close()


    def test_stderr_is_bounded_without_killing_worker(self):
        client = WorkerClient(
            self._config(
                """
                import json
                import sys

                sys.stderr.write("startup diagnostic " * 100)
                sys.stderr.flush()

                print(json.dumps({
                    "status": "ready",
                    "protocol_version": 1
                }), flush=True)

                for line in sys.stdin:
                    sys.stderr.write("request diagnostic " * 100)
                    sys.stderr.flush()

                    print(json.dumps({
                        "status": "ok",
                        "result": json.loads(line)
                    }), flush=True)
                """,
                max_output_bytes=1024,
            )
        )

        try:
            response = client.request({"event_id": "evt-1"})

            self.assertEqual(response["status"], "ok")
            self.assertTrue(client.is_running)
            self.assertLessEqual(len(client.stderr_tail), 1024)

        finally:
            client.close()


if __name__ == "__main__":
    unittest.main()