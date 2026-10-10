# Paired-event evaluation protocol for detector fusion

## Purpose

This protocol defines the evidence required before training or evaluating a learned fusion model that consumes AI-NIDS and PhishVision outputs. It is a data-contract and leakage-control proposal, not evidence that fusion currently improves detection.

## Current readiness

The current AI-NIDS CICIDS2017 flow dataset and PhishVision screenshot dataset are independently collected task datasets. No verified shared-event mapping has been established between them. **Do not randomly pair rows or screenshots and flows to populate this manifest.** Until legitimately paired, adjudicated records exist, the manifest should remain unpopulated and learned fusion should remain deferred.

The existing synthetic policy scenarios measure conformity with declared rules, not detector performance or fusion effectiveness.

## Required manifest contract

Use `fixtures/evaluation/paired_event_manifest.schema.json` and validate candidate manifests with `tools/validate_paired_manifest.py`.

Each event requires:

- A unique `event_id`, and a `group_id` representing the incident, campaign, or session needed for leakage-resistant splitting.
- A split of `train`, `validation`, or `test`; a group may occur in only one split.
- A timezone-aware event timestamp.
- A `pairing_basis` method and reference explaining how the source records were linked. The validator checks that this explanation is present, but cannot prove its truth.
- An event-level `security_incident` label, incident type, and named adjudication source. This is the target for evaluating fusion; it is not interchangeable with either detector's task-specific label.
- Both an AI-NIDS and a PhishVision source record, each with record ID, input SHA-256, model SHA-256, binary task label, saved prediction, continuous score in `[0,1]`, and score semantics. A decision threshold and prediction timestamp should be recorded when applicable.

The continuous scores must retain their source-specific meanings. For example, an AI-NIDS attack probability and a PhishVision phishing probability are not automatically probabilities of the same event-level target; learning or calibration must use explicitly defined labels and training-only fitting.

## Split and evaluation rules

1. Establish the event linkage and event-level label before looking at model errors.
2. Deduplicate source record IDs and preserve input/model hashes and model/preprocessing versions.
3. Split by incident/campaign/session `group_id`, not randomly by individual row. A group must not leak across training, validation, and test partitions.
4. Reserve the test partition until model, features, calibration, and thresholds have been fixed using training/validation data.
5. Report individual detector metrics separately from fused-model metrics. Include confusion matrix, per-class precision/recall/F1, specificity, balanced accuracy, ROC AUC where continuous scores are available, and sample/class counts.
6. Compare fusion against both source baselines on exactly the same held-out events; report confidence intervals and subgroup/error analysis where sample size permits.
7. Record excluded and missing-source events explicitly in a separate analysis. Do not silently impute missing detector scores or turn policy-contract fixtures into empirical dataset rows.

## Validation command

```powershell
python tools/validate_paired_manifest.py path\to\paired_manifest.json --json-output reports\evaluation\paired-manifest-validation.json
```

Exit status `0` means the manifest passed structural and split-hygiene validation. It does not verify that pairing references are authentic, labels are correct, model hashes belong to the stated models, or scores were generated without leakage. Those checks require independent provenance and review.

## Limitations

The existing saved AI-NIDS 2,000-row prediction file has only hard labels and no per-record probability score. The PhishVision probability file concerns screenshot classification and has not been paired with the AI-NIDS flow records. These sources therefore do not, by themselves, provide an eligible paired dataset for learned fusion.

## Validator/schema consistency hardening

The Python validator rejects unknown properties throughout the manifest, matching the schema's `additionalProperties: false` clauses. Fields ending in `_utc` require RFC3339-shaped date-times with a zero UTC offset (`Z` or `+00:00`); space-separated timestamps, compact offsets, offsets including seconds, and nonzero offsets are rejected. Hashes must be exactly 64 hexadecimal characters in both validators. Required non-empty strings also reject whitespace-only values in both the Python validator and schema. These checks remain structural: hashes, event linkage, and adjudication still require independent evidence.
