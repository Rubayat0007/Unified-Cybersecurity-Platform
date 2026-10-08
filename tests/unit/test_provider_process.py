import sys
import unittest

from core.providers.process import (
    ProviderProcessError,
    execute_json_process,
    parse_json_stdout,
)


class TestProviderProcess(unittest.TestCase):
    def _python_command(self, script: str):
        return (
            sys.executable,
            "-c",
            script,
        )

    def test_successful_json_process(self):
        command = self._python_command(
            "import json; print(json.dumps({'status': 'ok'}))"
        )

        result = execute_json_process(
            command=command,
            payload={"event_id": "evt-1"},
            timeout_seconds=5,
            max_output_bytes=1024,
        )

        self.assertEqual(result.return_code, 0)
        self.assertFalse(result.timed_out)

        payload = parse_json_stdout(result)

        self.assertEqual(
            payload,
            {"status": "ok"},
        )

    def test_nonzero_exit_is_rejected(self):
        command = self._python_command(
            "raise SystemExit(3)"
        )

        result = execute_json_process(
            command=command,
            payload={},
            timeout_seconds=5,
            max_output_bytes=1024,
        )

        self.assertEqual(result.return_code, 3)

        with self.assertRaises(ProviderProcessError):
            parse_json_stdout(result)

    def test_invalid_json_is_rejected(self):
        command = self._python_command(
            "print('not-json')"
        )

        result = execute_json_process(
            command=command,
            payload={},
            timeout_seconds=5,
            max_output_bytes=1024,
        )

        with self.assertRaises(ProviderProcessError):
            parse_json_stdout(result)

    def test_non_object_json_is_rejected(self):
        command = self._python_command(
            "import json; print(json.dumps(['not', 'an', 'object']))"
        )

        result = execute_json_process(
            command=command,
            payload={},
            timeout_seconds=5,
            max_output_bytes=1024,
        )

        with self.assertRaises(ProviderProcessError):
            parse_json_stdout(result)

    def test_timeout_is_reported(self):
        command = self._python_command(
            "import time; time.sleep(2)"
        )

        result = execute_json_process(
            command=command,
            payload={},
            timeout_seconds=1,
            max_output_bytes=1024,
        )

        self.assertTrue(result.timed_out)

        with self.assertRaises(ProviderProcessError):
            parse_json_stdout(result)

    def test_empty_command_is_rejected(self):
        with self.assertRaises(ValueError):
            execute_json_process(
                command=(),
                payload={},
                timeout_seconds=5,
                max_output_bytes=1024,
            )

    def test_invalid_output_limit_is_rejected(self):
        command = self._python_command(
            "print('{}')"
        )

        with self.assertRaises(ValueError):
            execute_json_process(
                command=command,
                payload={},
                timeout_seconds=5,
                max_output_bytes=0,
            )

    def test_stdout_output_limit_is_enforced(self):
        command = self._python_command(
            "print('x' * 5000)"
        )

        with self.assertRaises(ProviderProcessError):
            execute_json_process(
                command=command,
                payload={},
                timeout_seconds=5,
                max_output_bytes=1024,
            )

    def test_stderr_output_limit_is_enforced(self):
        command = self._python_command(
            "import sys; sys.stderr.write('x' * 5000)"
        )

        with self.assertRaises(ProviderProcessError):
            execute_json_process(
                command=command,
                payload={},
                timeout_seconds=5,
                max_output_bytes=1024,
            )

    def test_payload_is_sent_as_json(self):
        command = self._python_command(
            "import json,sys; "
            "value=json.load(sys.stdin); "
            "print(json.dumps(value))"
        )

        result = execute_json_process(
            command=command,
            payload={"event_id": "evt-42"},
            timeout_seconds=5,
            max_output_bytes=1024,
        )

        self.assertEqual(result.return_code, 0)

        payload = parse_json_stdout(result)

        self.assertEqual(
            payload["event_id"],
            "evt-42",
        )


if __name__ == "__main__":
    unittest.main()