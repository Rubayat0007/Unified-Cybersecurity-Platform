"""Cross-domain demonstration: one decision from network and phishing evidence.

Real data on both sides:
- AI-NIDS result from packets captured on loopback (benign by construction);
- PhishVision result from the production CNN and OCR on a generated screenshot.

Two scenarios:
1. captured network result (LOW) + phishing screenshot -> high severity, no
   cross-source corroboration;
2. the checked-in AI-NIDS high-attack fixture + phishing screenshot ->
   corroboration detected.

Scenario 2 uses a fixture because no labelled attack traffic exists. That is
stated in the output; it is not presented as a live attack detection.
"""

import json
import os
import subprocess
import sys
from pathlib import Path

REPO = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(REPO))

from api.service import run_assessment  # noqa: E402

AI_NIDS = Path(os.environ.get("UCP_AINIDS_ROOT", r"D:\Projects\AI-NIDS"))
PHISHVISION = Path(os.environ.get("UCP_PHISHVISION_ROOT", r"D:\Projects\PhishVision-AI"))


def run_helper(repo: Path, script: str) -> dict:
    result = subprocess.run(
        [sys.executable, str(repo / "scripts" / script)],
        cwd=repo, capture_output=True, text=True, timeout=600,
    )
    if result.returncode != 0:
        raise SystemExit(f"{script} failed: {result.stderr[-800:]}")
    return json.loads(result.stdout.strip().splitlines()[-1])


def summarise(label: str, outcome) -> dict:
    assessment = outcome.assessment
    return {
        "scenario": label,
        "severity": assessment.overall_severity.value,
        "primary_threat": assessment.primary_threat,
        "component_status": {k: v.value for k, v in assessment.component_status.items()},
        "corroboration": assessment.metadata.get("cross_source_corroboration"),
        "action": outcome.decision.action.value,
        "human_review": outcome.decision.requires_human_review,
    }


def main() -> int:
    print("capturing network traffic and analysing a screenshot...")
    live_network = run_helper(AI_NIDS, "demo_result.py")
    phishing = run_helper(PHISHVISION, "demo_result.py")

    print(f"network: prediction={live_network['prediction']} severity={live_network['severity']} "
          f"attack_p={live_network['attack_probability']:.4f} flows={live_network['flow_count']} "
          f"({live_network['source']})")
    print(f"phishing: verdict={phishing['security_assessment']['verdict']} "
          f"p(phishing)={phishing['cnn_analysis']['phishing_probability']:.4f}")

    fixture = json.loads((REPO / "fixtures" / "ai_nids" / "high_attack.json").read_text(encoding="utf-8"))

    scenarios = [
        summarise(
            "captured traffic + phishing screenshot",
            run_assessment(ai_nids_result=live_network, phishvision_result=phishing),
        ),
        summarise(
            "attack fixture + phishing screenshot (fixture, not live)",
            run_assessment(ai_nids_result=fixture, phishvision_result=phishing),
        ),
    ]

    print(json.dumps(scenarios, indent=2))

    failures = []
    if scenarios[0]["corroboration"] is not False:
        failures.append("captured benign traffic must not corroborate phishing")
    if scenarios[1]["corroboration"] is not True:
        failures.append("two threat sources must corroborate")
    if scenarios[1]["severity"] not in {"high", "critical"}:
        failures.append("two threat sources must produce high severity")

    for failure in failures:
        print("FAIL:", failure, file=sys.stderr)

    print("RESULT:", "PASS" if not failures else "FAIL")
    return 0 if not failures else 1


if __name__ == "__main__":
    raise SystemExit(main())
