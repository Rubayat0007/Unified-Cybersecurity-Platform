# Additional rules-policy edge-case scenarios

## Purpose

This additive fixture extends `policy_scenarios.json` with four synthetic policy-contract scenarios covering timeout and not-applicable statuses and standalone suspicious severity. It exercises the existing `correlate()` and `decide()` implementations without changing production rules, detector adapters, or model artifacts.

## Added cases

- `timeout-signal-excluded-from-severity`: a timed-out critical signal must not override an available low signal.
- `not-applicable-signal-excluded-from-corroboration`: a not-applicable high-severity signal must not raise the assessment or establish cross-source corroboration.
- `suspicious-standalone-warns`: one available suspicious phishing signal should produce a warning under the current policy contract.
- `timeout-and-not-applicable-require-review`: when there are no available signals, the overall severity remains unknown and the action requires human review.

## Run

From the repository root, evaluate the four edge cases with a new report destination:

```powershell
python tools/evaluate_policy_scenarios.py --input fixtures/evaluation/policy_scenarios_edge_cases.json --output-dir reports/evaluation/policy-scenario-edge-cases-v1
```

Run their unit tests with:

```powershell
python -m unittest discover -s tests\unit -p "test_policy_scenario_edge_cases.py" -v
```

The report's pass rate measures agreement with the declared synthetic policy contract. It is not real-world accuracy, detector performance, or evidence that multi-detector fusion improves detection.
