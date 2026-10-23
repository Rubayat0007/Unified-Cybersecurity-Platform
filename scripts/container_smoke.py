"""Verify the container image's contents without a container runtime.

Docker is not installed in this environment, so the image cannot be built.
This script emulates the parts that a build would prove:

- the COPY set in the Dockerfile is sufficient to import and run the app;
- requirements.txt installs cleanly into a fresh environment;
- the production startup path works (token required, health public);
- the same command the image runs (uvicorn api.app:app) serves correctly.

What it cannot prove: the base image, layer caching, file ownership, and the
healthcheck instruction itself. Those remain unverified until a real build.
"""

from __future__ import annotations

import json
import os
import shutil
import subprocess
import sys
import tempfile
import time
import urllib.error
import urllib.request
from pathlib import Path

REPO = Path(__file__).resolve().parents[1]
PORT = 8096
COPY_TARGETS = ("api", "core", "adapters", "tools", "dashboard")


def call(path, headers=None):
    request = urllib.request.Request("http://127.0.0.1:%d%s" % (PORT, path), headers=headers or {})
    try:
        with urllib.request.urlopen(request, timeout=5) as response:
            return response.status, json.loads(response.read() or b"{}")
    except urllib.error.HTTPError as exc:
        return exc.code, {}


def post_assess(headers=None):
    body = b"{}"
    request = urllib.request.Request(
        "http://127.0.0.1:%d/v1/assess" % PORT,
        data=body,
        headers={"Content-Type": "application/json", **(headers or {})},
        method="POST",
    )
    try:
        with urllib.request.urlopen(request, timeout=10) as response:
            return response.status
    except urllib.error.HTTPError as exc:
        return exc.code


def main() -> int:
    workspace = Path(tempfile.mkdtemp(prefix="ucp_image_", dir=os.environ.get("TEMP")))
    failures = []

    def check(label, condition, detail=""):
        print(("PASS" if condition else "FAIL") + ": " + label + ("" if condition else "  [%s]" % detail))
        if not condition:
            failures.append(label)

    try:
        for target in COPY_TARGETS:
            shutil.copytree(REPO / target, workspace / target)
        shutil.copy2(REPO / "requirements.txt", workspace / "requirements.txt")

        check("COPY set omits tests and results",
              not (workspace / "tests").exists() and not (workspace / "results").exists())

        venv = workspace / ".venv"
        subprocess.run([sys.executable, "-m", "venv", str(venv)], check=True,
                       stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)

        python = venv / "Scripts" / "python.exe"
        subprocess.run(
            [str(python), "-m", "pip", "install", "--quiet", "--no-input",
             "-r", str(workspace / "requirements.txt")],
            check=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
        )
        check("requirements install into a clean environment", True)

        env = {
            **os.environ,
            "UCP_ENVIRONMENT": "production",
            "UCP_API_TOKEN": "image-smoke-token",
            "PYTHONPATH": str(workspace),
            "TEMP": os.environ.get("TEMP", ""),
        }
        env.pop("UCP_PHISHVISION_ROOT", None)
        env.pop("UCP_PHISHVISION_PYTHON", None)

        process = subprocess.Popen(
            [str(python), "-m", "uvicorn", "api.app:app", "--host", "127.0.0.1", "--port", str(PORT)],
            cwd=workspace, env=env, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
        )

        try:
            up = False
            for _ in range(60):
                time.sleep(0.5)
                if process.poll() is not None:
                    break
                try:
                    if call("/health")[0] == 200:
                        up = True
                        break
                except Exception:
                    pass

            check("production service starts with only the copied files", up)

            if not up:
                diagnostic = subprocess.run(
                    [str(python), "-c", "import api.app"],
                    cwd=workspace, env=env, capture_output=True, text=True, timeout=60,
                )
                print("  import diagnostic:", (diagnostic.stderr or "").strip().splitlines()[-3:])

            if up:
                check("/health is public", call("/health")[0] == 200)
                check("/v1/assess rejects missing token", post_assess() == 401)
                check("/v1/assess accepts bearer token",
                      post_assess({"Authorization": "Bearer image-smoke-token"}) == 200)
        finally:
            process.terminate()
            try:
                process.wait(timeout=15)
            except subprocess.TimeoutExpired:
                process.kill()

        print("\nRESULT: " + ("PASS" if not failures else "FAIL (%s)" % ", ".join(failures)))
        print("NOTE: base image, layer caching and HEALTHCHECK remain unverified.")
        return 0 if not failures else 1
    finally:
        shutil.rmtree(workspace, ignore_errors=True)


if __name__ == "__main__":
    raise SystemExit(main())
