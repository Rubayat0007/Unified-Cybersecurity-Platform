# AI-NIDS Feature-Parity Feasibility Audit

## Scope and safeguards

This document records a read-only feasibility audit of the original AI-NIDS repository before any live-inference integration into the unified cybersecurity platform. The original detector source, frozen model, model thresholds, and production behavior were not modified as part of this audit.

The audit distinguishes schema compatibility and unit-test results from independent equivalence with the CICIDS2017 training feature pipeline. Passing unit tests alone does not establish feature parity.

## Findings

### 1. Model input schema

The training script, evaluation script, canonical feature schema, and model-input adapter use the same 20 feature names in the same order. The adapter rejects missing or unexpected fields, Boolean values, non-numeric values, and non-finite values.

This confirms structural alignment. It does not establish that live packet-derived values have the same definitions, units, or distributions as the training features.

### 2. Training feature provenance

The inspected `src/prepare_cicids2017.py` maps model features to CICIDS2017 columns, including `Flow Duration`, `Fwd Packet Length Mean`, `Bwd Packet Length Mean`, `Average Packet Size`, `Active Mean`, `Idle Mean`, `Fwd IAT Mean`, and `Bwd IAT Mean`.

It derives:
- `flow_bytes` from total forward and backward packet lengths.
- `flow_packets` from forward and backward packet counts.
- `header_length` from forward and backward header-length columns.

These mappings provide the reference definitions that a live extractor must reproduce.

### 3. Legacy predictor is not feature-compatible

The inspected `src/predict.py` aggregates captured packets rather than extracting independent bidirectional flows. Several calculations conflict with the training feature definitions:

- `flow_duration` uses capture duration in seconds instead of per-flow duration in the CICIDS2017 feature units.
- `fwd_packet_length` and `bwd_packet_length` contain directional byte sums rather than directional packet-length means.
- `fwd_iat_mean` is calculated across all captured packet timestamps rather than forward-direction timestamps within a flow.
- `bwd_iat_mean` remains zero.
- `header_length` is approximated as 20 bytes per captured packet.
- `active_time` is set to capture duration and `idle_time` to zero.

The legacy extractor must not be used as a fallback for live inference.

### 4. Newer flow-based inference path

The repository contains `src/features/flow.py`, `src/features/model_input.py`, `src/inference.py`, and `src/detection.py`. This path groups packets into bidirectional flows, creates records matching the canonical feature schema, validates model inputs, and runs the frozen model.

However, full equivalence with the training feature-generation pipeline has not been demonstrated. Remaining questions include:

- Exact parity of packet-length and byte-count definitions.
- Header-length accounting.
- Average packet size, including the implemented first-packet adjustment.
- Active/idle timing semantics.
- Flow direction, timeout behavior, incomplete flows, and single-packet flows.
- Effects of finite capture windows on flow completeness.

These items require comparison against an independent CICFlowMeter-compatible reference, not only tests of the local implementation against predefined expectations.

### 5. Application wiring and safeguards

The inspected `src/main.py` only prints a startup message.

The dashboard imports `capture_network_traffic` from `src.capture`. Its detection worker captures traffic for eight seconds and then deliberately raises a runtime error stating that live inference is disabled because feature compatibility has not been verified.

The standalone `src/predict.py` also sets `LIVE_INFERENCE_ENABLED = False` and raises an error when live prediction is requested while the flag remains false. A separate `src/detection.py` inference path exists, but no dashboard call to that path was found in the inspected code.

Live inference must remain disabled until compatibility has been demonstrated and the intended application call path has been explicitly reviewed.

### 6. Test evidence

The following focused tests passed in the original AI-NIDS repository:

- `tests/test_cicids_feature_provenance.py`
- `tests/test_flow_features.py`
- `tests/test_flow_semantics.py`
- `tests/test_feature_pipeline.py`
- `tests/test_inference.py`

Result: **18 passed in 10.00 seconds**.

These tests cover provenance mappings, schema order, expected feature values for test packets, model-input validation, and inference behavior. They do not constitute an independent comparison of the live extractor against the training feature generator.

A repository search found no `.pcap`, `.pcapng`, or `.cap` files in the searched AI-NIDS tree. No packet-replay parity evaluation has therefore been established from an existing repository capture.

## Readiness assessment

**Status: Not ready for live-inference integration.**

Schema alignment and focused unit tests are confirmed. The legacy extractor has material feature-definition mismatches. The newer flow-based path is a stronger integration candidate, but independent feature parity remains unverified and the dashboard currently blocks inference.

No live detection accuracy, production compatibility, or fusion effectiveness claim should be inferred from the passing unit tests.

## Required evidence before reconsidering live inference

1. Obtain a suitable, lawfully usable packet-capture fixture with documented provenance and flow expectations.
2. Process the same traffic through an independent CICFlowMeter-compatible reference and the candidate extractor.
3. Compare all 20 features, including units, directionality, header accounting, timing, timeouts, and incomplete-flow behavior.
4. Document numerical tolerances, mismatches, and unsupported cases.
5. Add reproducible parity tests and review their results before deciding whether integration is justified.
6. Preserve the frozen model, model thresholds, and original detector repository unless a separate, explicitly authorized change is approved.

## Integration boundary

Any future integration work should be implemented and validated in the unified cybersecurity platform where practicable. Do not enable live inference, retrain the frozen model, alter model thresholds, or change the original detector's production behavior as part of this audit.
