# Rules-policy scenario evaluation

## Purpose and scope

This evaluation exercises the unified platform's existing `correlate()` and `decide()` functions using explicit synthetic `SecuritySignal` inputs. The cases are policy-contract scenarios: each declares what the current policy is expected to produce for a constructed set of signals.

The report's pass rate measures agreement between implementation and these declared contract expectations. It is **not** detector accuracy, a security effectiveness estimate, or evidence that combining AI-NIDS and PhishVision improves detection in real incidents.

## Existing policy behavior under test

- Only signals with status `available` contribute to overall severity, identified threats, primary threat selection, and cross-source threat corroboration.
- Overall severity is the highest severity among available signals.
- A threat severity is one of `suspicious`, `medium`, `high`, or `critical`.
- Recommended action follows `core/policies/default_policy.py`: critical/high → investigate; suspicious/medium → warn; low → monitor; minimal → allow; unknown/no usable severity → investigate.
- Cross-source corroboration requires threat-severity signals from at least two distinct detector sources. Multiple PhishVision components do not count as two sources.
- `decide()` preserves the assessment's recommended action and requires human review for unknown severity or when the action is investigate/block.

## Included scenarios

The fixture includes eight deterministic cases: a high AI-NIDS signal with PhishVision unavailable; high risk corroborated across two sources; lower-severity evidence alongside medium risk; both sources low; minimal severity; no usable signals; multiple PhishVision components from one source; and critical severity alongside medium severity.

These cases are synthetic and focus on implementation-contract behavior. They do not use genuine detector outputs or ground-truth security events.

## Run it

From the repository root:

```powershell
python tools/evaluate_policy_scenarios.py
```

To write JSON and CSV reports, choose a new output directory (the CLI will not overwrite an existing report file):

```powershell
python tools/evaluate_policy_scenarios.py --output-dir reports/evaluation/policy-scenarios-v1
```

The JSON summary includes the scenario-file SHA-256, counts, pass rate and per-case expected/actual values. The CSV provides one row per case. Exit code is `0` when all cases pass, `1` if any case fails, and `2` for an input or report-writing error.

## Limitations and next evidence needed

- Scenario outcomes are declared from the current policy; they are not independently labeled real events.
- Pass rate is not precision, recall, ROC AUC, or end-to-end detector accuracy.
- The current rules select the maximum available severity. Corroboration adds context but does not independently alter the action.
- A future learned-fusion evaluation requires paired AI-NIDS and PhishVision outputs for the same appropriately labeled underlying events, suitable split provenance, and separation of training/validation/test data.
- This harness does not change detector models, thresholds, adapters, correlation policy, or operational decision behavior.
