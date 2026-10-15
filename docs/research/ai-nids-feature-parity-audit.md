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

A repository search found no `.pcap`, `.pcapng`, or `.cap` files in the searched AI-NIDS tree. A synthetic packet-replay parity evaluation was subsequently performed against a temporary CICFlowMeter checkout; results and limitations are documented below. This does not establish parity with the exact feature-generator version used to create the CICIDS2017 training features.

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

## Synthetic packet-replay parity experiments (2026-10-14)

### Setup and provenance

A temporary checkout of the upstream `ahlashkari/CICFlowMeter` repository at commit `98a5ebad0df579cc8b43eedd3421b3ae87699901` was built and run against synthetic offline IPv4/TCP PCAPs. Compilation required using the checkout's bundled Windows JNetPcap JAR in place of the unavailable Maven dependency. Running the reference also required adding the existing Npcap directory to the current PowerShell session's `PATH`. These adjustments were confined to the temporary reference environment.

The checkout is a candidate reference implementation. The exact CICFlowMeter version and configuration used to produce the frozen model's CICIDS2017 training features have not been established.

### Experiment results

Two four-packet bidirectional TCP flows were replayed through the reference and candidate implementations. Candidate results used runtime-only experimental adjustments; the original `src/features/flow.py` file was not changed.

- **Short flow:** packet timestamps at 0, 1, 3, and 6 milliseconds. The initial strict comparison reported seven feature mismatches. Subtracting the earliest timestamp before converting to floating point eliminated the small discrepancies in duration, rates, and directional IAT means. Matching the reference's transport-header-only accounting eliminated the header-length mismatch. `active_time` remained different: the reference reported 0, while the candidate reported 6,000 microseconds.
- **Idle-gap flow:** packet timestamps at 0, 1 millisecond, 6 seconds, and 6.001 seconds. With both runtime-only adjustments, all 20 features matched the reference within the harness's default absolute and relative tolerances of `1e-6`. The reference reported an active mean of 1,000 microseconds and an idle mean of 5,999,000 microseconds.

### Diagnosed differences

**Timestamp precision:** the candidate converts large Unix-epoch timestamps to floating-point values before subtraction. For the first synthetic flow, this produced a computed duration of approximately 6,000.04196 microseconds instead of 6,000 microseconds. Subtracting a Decimal timestamp origin before conversion eliminated the observed timing mismatches in these experiments. This was tested only as a runtime patch and has not been applied to the candidate source.

**Header length:** the candidate's `_packet_header_length` includes the IP header plus the TCP/UDP header. For these TCP fixtures, the inspected reference packet reader stores the TCP header length in `headerBytes`. UDP header accounting was not exercised, and one UDP parsing branch in `PacketReader.java` appears to use the TCP header getter; that path requires separate verification. For the four-packet fixtures, the candidate's total was 160 bytes versus 80 bytes from the reference. A runtime-only transport-header adjustment made this feature match in both fixtures. Whether this is the correct definition for the exact training-data generator must still be verified.

**Active/idle timing:** the reference evaluates active/idle timing as packets arrive. When a gap exceeds the activity timeout, it records the preceding active period and the idle interval, but it does not finalize the last active interval when dumping the tested current flow. Consequently, the short-flow fixture has reference active and idle means of zero, while the candidate calculates the final active interval. The idle-gap fixture records a long idle period and matches the candidate's calculated values. The short-flow discrepancy is therefore observed reference behavior, not evidence that the candidate should automatically be changed to imitate it.

### Assessment and next steps

These experiments isolate specific numerical and semantic differences, but do not prove equivalence with the CICIDS2017 training pipeline. The all-20-feature pass applies only to the tested idle-gap fixture and the stated runtime-only adjustments. The short-flow test still fails one feature.

Before modifying the persistent candidate extractor or reconsidering live inference:

1. Establish the provenance and configuration of the feature generator used for training.
2. Expand independent replay comparisons to representative flows, including short flows, idle gaps, single-packet and incomplete flows, and both TCP and UDP.
3. Decide the correct training-compatible definitions for timestamp handling, header length, and active/idle finalization from verified provenance and broader evidence.
4. Rerun the strict parity suite after any separately reviewed candidate-side change.

The original detector, frozen model, model thresholds, and live-inference gate remain unchanged. The temporary experiments do not establish detection accuracy or production readiness.

## Packaged CICFlowMeter V3.0 cross-check (2026-10-14)

### Setup and scope

A packaged CICFlowMeter 3.0 JAR from the temporary
`iPAS/TCPDUMP_and_CICFlowMeter` reference checkout was run against the
same two synthetic four-packet bidirectional TCP PCAP fixtures used in
the earlier replay experiments. The packaged reference and its JAR were
not modified.

This package is an additional comparator, not a verified reproduction
of the exact CICFlowMeter version and configuration used to generate the
frozen model's CICIDS2017 training features.

### Packet-level verification

Scapy inspection confirmed the TCP flags in both input captures:

- **Short flow:** packet flags `S`, `SA`, `PA`, `PA`; expected aggregate
  counts are SYN = 2, ACK = 3, PSH = 2.
- **Idle-gap flow:** packet flags `S`, `SA`, `A`, `PA`; expected aggregate
  counts are SYN = 2, ACK = 3, PSH = 1.

Both captures contain four TCP packets and were successfully processed
by the packaged V3.0 program.

### Feature comparison results

The canonicalized V3.0 output was compared against the earlier
upstream-based canonical reference with the existing feature-parity
harness.

For each fixture, one matching flow was found and all 20 model features
were compared. Exactly two features mismatched:

- `syn_count`: upstream-based reference = 2; V3.0 candidate = 0.
- `ack_count`: upstream-based reference = 3; V3.0 candidate = 0.

The other 18 model features matched within the harness's default
absolute and relative tolerances of `1e-6`. No flows were missing from
either side of these comparisons.

The V3.0 CSV also reported SYN Flag Cnt = 0, ACK Flag Cnt = 0, and
PSH Flag Cnt = 1 for both fixtures. Those values do not agree with the
verified packet-level aggregate counts.

### Bytecode findings and limitations

Inspection of the packaged V3.0 bytecode found:

- `PacketReader` obtains SYN, ACK, and PSH flags from the JNetPcap TCP
  accessors and passes the results to the corresponding
  `BasicPacketInfo` setters in the inspected parsing paths.
- `BasicPacketInfo` flag accessors return the stored Boolean fields.
- `BasicFlow.firstPacket()` invokes `checkFlags()`, which increments
  the flag counters based on the packet's flags.
- The inspected `BasicFlow.addPacket()` implementation does not invoke
  `checkFlags()` on the subsequent-packet path.
- Flag serialization iterates over `flagCounts.keySet()` and appends
  values from that map rather than explicitly selecting each counter in
  the fixed CSV-header order.

These observations are consistent with a flag-aggregation defect and
a possible CSV header/value ordering defect. The bytecode review and
observed outputs identify strong leads, but the precise contribution
of each issue has not been confirmed through instrumentation and a
corrected, rerun reference implementation. The package must not be
assumed to provide trustworthy SYN/ACK counts.

### Assessment

Packaged CICFlowMeter V3.0 is suitable only as a supplementary
synthetic cross-check for the tested cases. It is not an authoritative
reference for `syn_count` or `ack_count`, and the 18-of-20 matches on
these two fixtures do not establish parity with the training feature
generator.

The earlier upstream-based reference also has unverified training-data
provenance. The results therefore do not establish full feature parity
or production readiness.

The original AI-NIDS detector, frozen model, model thresholds, and
live-inference gate remain unchanged. Live inference must remain
disabled pending verified feature-generator provenance and broader,
reproducible parity testing.

## Phase 5: training-feature provenance review (2026-10-14)

### Published dataset provenance

The official Canadian Institute for Cybersecurity CICIDS2017 page states
that the dataset includes flow-analysis CSVs generated using CICFlowMeter
and more than 80 extracted network-flow features. The current page does
not identify the precise CICFlowMeter version used for this local archive.

Source: https://www.unb.ca/cic/datasets/ids-2017.html

A researcher-maintained dataset listing explicitly attributes the
CICIDS2017 flow-analysis CSVs to CICFlowmeter-V3.0. This supports V3.0
as the published version attribution, but does not identify the exact
source commit, binary build, runtime configuration, or timeout settings
used to create the local archive.

Source: https://www.cs.unb.ca/~alashkar/Data-sets.asp

A separate historical upstream commit inspected during the audit,
`844e3fa327f567a063108febbd59430f222f7e53` (2018-06-04), declares
`version = '4.0'` and `description = CICFlowMeterV4` in its committed
`build.gradle`. That commit is not evidence that V4.0 generated the
CICIDS2017 training features and must not be treated as the exact
training reference.

### Local archive integrity

The local `MachineLearningCSV.zip` was 235,102,953 bytes and contained
the eight expected daily CSV files, with archive-entry timestamps dated
2018-06-07.

SHA-256 hashes were calculated for each CSV entry read directly from
the ZIP archive and compared with the corresponding extracted CSV file.
All eight extracted files matched their archive entries exactly.

This confirms that the extracted files equal the local ZIP contents.
It does not independently authenticate the origin of the ZIP archive,
because no independently verified publisher checksum or equivalent
chain-of-custody record was established.

### Source-column mapping and duplicate header

The inspected source CSV header contains two columns named
`Fwd Header Length`. Pandas exposes the second as
`Fwd Header Length.1`. The preparation script selects
`Fwd Header Length` through `SOURCE_COLUMNS` and derives
`header_length` from the selected forward-header column and
`Bwd Header Length`.

A full read-only comparison of the two forward-header columns across
all eight CSVs covered 2,830,743 rows and found zero differing rows.
For this local archive, the duplicate header therefore introduces no
observed value difference in the derived forward-header input.

The preparation script also derives:
- `flow_bytes` as total forward plus total backward packet lengths.
- `flow_packets` as total forward plus total backward packet counts.
- `header_length` as forward plus backward header lengths.

It maps directional packet-length means, rates, flag counts,
`Average Packet Size`, `Active Mean`, `Idle Mean`, `Down/Up Ratio`,
and forward/backward IAT means from the corresponding CSV columns.
These mappings establish the local transformation logic, but do not
independently establish that a live extractor will reproduce the
historical generator's exact definitions and runtime behavior.

### Processed-row reconciliation

The eight raw CSVs contain 2,830,743 data rows in total. A read-only,
chunked replay of the preparation script's numeric conversion,
missing/non-finite-value removal, and nonnegative-value filters retained
2,827,761 rows.

The existing `data/processed/cicids2017_binary.csv` contains
2,020,632 data rows and 21 columns (20 model features plus `label`).
The tracked evaluation metrics also report 2,020,632 dataset rows.

The checked-in preparation entry point concatenates the per-file results
and then calls `combined.drop_duplicates()` before writing the processed
CSV. The 807,129-row difference between the filtered row count and the
saved processed dataset is consistent with that global deduplication
stage. The read-only filter replay did not independently execute a full
global duplicate-count calculation, so 807,129 is a reconciliation
difference, not a separately measured count of duplicates removed.

### Training artifact and dependency evidence

The preparation script, training script, and tracked evaluation metrics
have only the initial source commit `5d8ca4b` in their inspected Git
history. The processed CSV and frozen model are ignored by Git; the
metrics file is tracked. No tracked manifest or training log was found
that binds the exact processed CSV content, training invocation, full
dependency environment, and frozen model bytes into one reproducible
training record.

The existing frozen model and its backup have identical SHA-256 hashes:
`1992228DFDC81529D8F87028252688AB39BC5AEB66A7AA2C5A38D164C831B3F2`.
A read-only byte inspection of the serialized model found the
`_sklearn_version` marker `1.9.1`, matching the scikit-learn version
listed in both inspected dependency manifests.

The initial `requirements.txt` in `5d8ca4b` specified NumPy 2.5.3,
SciPy 1.18.1, and contourpy 1.4.0. The later dependency update
`782e0fd` (authored 2026-09-17 01:25:09 +0800; committed
2026-09-17 01:27:45 +0800) specifies NumPy 2.2.6, SciPy 1.15.3,
and contourpy 1.3.3. Both manifests specify pandas 3.0.5,
scikit-learn 1.9.1, and joblib 1.6.0.

The local model's filesystem timestamp precedes the dependency-update
commit timestamp. This is temporal context, not proof of the packages
actually loaded during training. Filesystem timestamps and a serialized
scikit-learn marker do not establish the complete historical environment
or which exact input file was used in the training invocation.

### Provenance assessment and safety boundary

**Status: partially established; exact training feature-generator
provenance remains unverified.**

The available publisher/researcher documentation supports CICFlowMeter
V3.0 as the published CICIDS2017 version attribution. The local archive's
extracted contents, duplicate header values, preparation mappings,
processed row count, saved metric row count, and frozen-model hash have
been checked as described above.

The exact generator build and configuration used for the local archive,
as well as the exact processed-dataset bytes used in the historical
training run, have not been independently established. The synthetic
V3.0 comparisons remain supplementary and are not proof of full feature
parity.

Do not retrain or replace the frozen model, change model thresholds,
modify the original detector, or enable live inference as a result of
these findings. Live inference remains disabled pending stronger
provenance evidence and broader reproducible parity validation.

### Current-state artifact fingerprint baseline (2026-10-14)

A read-only SHA-256 fingerprint baseline was captured for the local
AI-NIDS artifacts. The original AI-NIDS repository was clean at
revision `2d02907` (`main` aligned with `origin/main`) during the
surrounding provenance review.

| Artifact | Size (bytes) | SHA-256 |
| --- | ---: | --- |
| `data/raw/MachineLearningCVE/MachineLearningCSV.zip` | 235102953 | `C3F26274B36C837CCF28FFD2DBF4582941C30B3EE70A635C6E5B2F87C4727928` |
| `data/processed/cicids2017_binary.csv` | 241981132 | `14B517C997478428C14512CC94312C23017BD6D8F96048BD168619C89B7B3737` |
| `src/models/nids_random_forest_cicids2017.pkl` | 139873785 | `1992228DFDC81529D8F87028252688AB39BC5AEB66A7AA2C5A38D164C831B3F2` |
| `results/cicids2017_metrics.txt` | 647 | `986A54DB381FA2F90B106ED4E04A9EA2FABE172C4B0FC1B96615EDB9424C8E80` |
| `src/prepare_cicids2017.py` | 5265 | `F13E202EE7A20636D2E432A90E31E2FB9387D6A5B34C3F181586EDAC87BDC5DB` |
| `src/train_cicids2017.py` | 5006 | `F1BC7418A602F9D68E3604AAA6A795E3BC0E0B15E396E8C7F25929A930DA31F4` |
| `requirements.txt` | 356 | `69C410082A099FDD14CFD3E503B8B9008155C91CF429E5B6192A0B1644804D20` |

The separately stored backup model was also verified to have the same
size and SHA-256 hash as the active model.

This table identifies the local artifact contents observed during this
review. It does not independently authenticate the archive's publisher,
prove that the processed CSV with this hash was used in the historical
training invocation, or establish the exact CICFlowMeter build and
configuration used to generate the training features.

No AI-NIDS artifact was modified or retrained to create this baseline.
The model was not deserialized; its bytes were read only for hashing and
inspection. These hashes should be compared against future copies before
assuming those copies represent the same artifact versions.
