"""Live smoke test: start the API, exercise the real PhishVision worker.

This is the only check that runs the whole chain: uvicorn -> /v1/assess/image
-> worker subprocess -> OCR + CNN -> adapter -> correlation -> decision.

It needs the PhishVision runtime (torch, EasyOCR, a provisioned checkpoint),
so it is a script rather than a unit test. Exit codes: 0 pass, 1 failure,
2 prerequisites missing.
"""

from __future__ import annotations

import io
import json
import os
import subprocess
import sys
import time
import urllib.error
import urllib.request
from pathlib import Path

REPO = Path(__file__).resolve().parents[1]
PORT = int(os.environ.get("UCP_SMOKE_PORT", "8099"))
BASE = f"http://127.0.0.1:{PORT}"


def prerequisites() -> tuple[bool, str]:
    root = Path(os.environ.get("UCP_PHISHVISION_ROOT", r"D:\Projects\PhishVision-AI"))

    if not (root / "src" / "security" / "analyzer.py").is_file():
        return False, f"PhishVision root not usable: {root}"

    model = root / "models" / "phishvision_cnn_v2.pth"
    if not model.is_file():
        return False, f"checkpoint not provisioned: {model}"

    for module in ("torch", "easyocr", "PIL"):
        try:
            __import__(module)
        except ImportError:
            return False, f"missing module: {module}"

    os.environ.setdefault("UCP_PHISHVISION_PYTHON", sys.executable)
    os.environ.setdefault("UCP_PHISHVISION_ROOT", str(root))
    return True, ""


def call(method: str, path: str, body: bytes | None = None, content_type=None):
    request = urllib.request.Request(BASE + path, data=body, method=method)
    if content_type:
        request.add_header("Content-Type", content_type)

    try:
        with urllib.request.urlopen(request, timeout=180) as response:
            return response.status, json.loads(response.read())
    except urllib.error.HTTPError as exc:
        return exc.code, json.loads(exc.read() or b"{}")


def wait_for_server(process, timeout=60.0) -> bool:
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        if process.poll() is not None:
            return False
        try:
            status, _ = call("GET", "/health")
            if status == 200:
                return True
        except (urllib.error.URLError, ConnectionError, OSError):
            pass
        time.sleep(0.5)
    return False


def screenshot() -> bytes:
    from PIL import Image, ImageDraw, ImageFont

    font = ImageFont.load_default(size=46)
    image = Image.new("RGB", (1200, 520), "white")
    draw = ImageDraw.Draw(image)
    for index, line in enumerate(
        ["SECURITY ALERT", "Verify your account and enter your password"]
    ):
        draw.text((50, 40 + index * 100), line, fill="black", font=font)

    buffer = io.BytesIO()
    image.save(buffer, format="PNG")
    return buffer.getvalue()


def main() -> int:
    ok, reason = prerequisites()
    if not ok:
        print(f"SKIP: {reason}", file=sys.stderr)
        return 2

    process = subprocess.Popen(
        [sys.executable, "-m", "uvicorn", "api.app:app",
         "--host", "127.0.0.1", "--port", str(PORT), "--log-level", "warning"],
        cwd=REPO,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
    )

    failures = []

    def check(label, condition, detail=""):
        print(f"{'PASS' if condition else 'FAIL'}: {label}" + (f"  [{detail}]" if not condition else ""))
        if not condition:
            failures.append(label)

    try:
        if not wait_for_server(process):
            print("FAIL: server did not become healthy", file=sys.stderr)
            return 1

        status, health = call("GET", "/health")
        check("/health returns ok", status == 200 and health.get("status") == "ok", health)

        status, ready = call("GET", "/ready")
        check("/ready reports both components", status == 200 and set(ready["components"]) == {"ai_nids", "phishvision"}, ready)

        nids = json.loads((REPO / "fixtures" / "ai_nids" / "high_attack.json").read_text(encoding="utf-8"))
        phish = json.loads((REPO / "fixtures" / "phishvision" / "high_phishing.json").read_text(encoding="utf-8"))
        body = json.dumps({"event_id": "smoke-fixture", "ai_nids_result": nids, "phishvision_result": phish}).encode()

        status, payload = call("POST", "/v1/assess", body, "application/json")
        check("/v1/assess ingests both sources",
              status == 200 and payload["assessment"]["component_status"] == {"ai_nids": "available", "phishvision": "available"},
              payload)
        check("fixture assessment is high risk with human review",
              payload["assessment"]["overall_severity"] == "high" and payload["decision"]["requires_human_review"] is True,
              payload["decision"])

        status, payload = call(
            "POST",
            "/v1/assess/image?event_id=smoke-image&url=http%3A%2F%2F192.168.1.10%2Flogin%2Fverify",
            screenshot(),
            "image/png",
        )
        check("/v1/assess/image returns 200", status == 200, payload)
        if status == 200:
            signals = payload["assessment"]["signals"]
            types = {(s["source"], s["signal_type"]) for s in signals}
            check("worker produced three PhishVision signals",
                  {("phishvision", "text_threat"), ("phishvision", "url_threat"), ("phishvision", "visual_threat")} <= types,
                  types)
            visual = next(s for s in signals if s["signal_type"] == "visual_threat")
            check("visual signal carries a CNN probability",
                  0.0 <= visual["raw_score"] <= 1.0, visual["raw_score"])
            check("missing AI-NIDS source is reported, not assumed benign",
                  payload["assessment"]["component_status"]["ai_nids"] == "unavailable",
                  payload["assessment"]["component_status"])
            check("assessment still reaches a decision",
                  payload["decision"]["action"] in {"allow", "monitor", "warn", "investigate"},
                  payload["decision"])

        status, payload = call("POST", "/v1/assess/image", b"not-an-image", "image/png")
        check("invalid image bytes are a client error", status == 422, (status, payload))

    finally:
        process.terminate()
        try:
            process.wait(timeout=20)
        except subprocess.TimeoutExpired:
            process.kill()

    print(f"\nRESULT: {'PASS' if not failures else 'FAIL (' + ', '.join(failures) + ')'}")
    return 0 if not failures else 1


if __name__ == "__main__":
    raise SystemExit(main())
