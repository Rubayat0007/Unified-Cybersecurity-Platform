# Programme closeout — 2026-10-25

Three repositories closed at `v1.0.0-research-preview`. This document records
what was built, what was measured, what failed, and what the next owner must do
first. It is the authoritative handover.

## Repositories

| Repo | Purpose | Closed at |
|---|---|---|
| `PhishVision-AI` | screenshot phishing detector + evaluation harness | `v1.0.0-research-preview` |
| `Unified-Cybersecurity-Platform` | correlation API with reliability-gated decisions | `v1.0.0-research-preview` |
| `AI-NIDS` | network intrusion detector, frozen CICIDS model | `v1.0.0-research-preview` |

## What is genuinely complete

- **Model integrity**: every load verifies a digest; a registry records which of
  seven distinct artifacts is production (`1403582C…`).
- **Leakage control**: the 555-image set contained 735 cross-split near-duplicate
  pairs; that inflation was found, quantified (F1 0.722 → 0.608), and corrected in
  the published claims.
- **Data pipeline for v3**: capture with interstitial, blank, duplicate and
  cluster+domain+brand guards; cluster-level splitting; OCR label triage;
  manifest validation; `source_url` carried end to end.
- **Evaluation discipline**: pre-registered hypotheses, single sealed evaluation,
  Wilson intervals, and failed hypotheses reported as prominently as passed ones.
- **Platform controls**: bearer auth, rate limiting, payload caps, hash-chained
  fail-closed audit, structured logs without content, truthful readiness, threat
  model, claims-to-ledger check enforced in CI.
- **Reliability gate**: a benign verdict requires measured sensitivity and FPR
  bounds; both detectors fail it, so the platform escalates `ALLOW` by design.

## What was measured, and rejected

| Hypothesis | Verdict | Evidence |
|---|---|---|
| P-1 threshold risk ≥ 25/100 | rejected: recall 0.60 → 0.20 | `pilot-rule-check.md` |
| 4.2 frozen-backbone linear probe | no evidence: AUC 0.50 vs 0.56 | `linear-probe.md` |
| Fusion calibration | no gain: equals CNN-only; text weight negative | `fusion-calibration.md` |
| P-3 URL component | direction confirmed, magnitude small (+3.75 phishing, +0.00 legit) | `url-component.md` |
| P-4 URL + threshold 20 | rejected: detection 0.526, FPR 0.333 at n=31 | `p4-sealed.md` |
| 7.2 adversarial evasion | evasion failed; false-alarm fragility instead | `adversarial-probe.md` |

## The measured state of the detector

- False-positive rate: **0.33** (0.14–0.61) on 12 legitimate test images.
- Detection: **0.53–0.64** depending on operating point.
- Component AUCs (leakage-free): text 0.638, CNN 0.657, combined 0.694.
- Reliability profile: sensitivity 0.706 (lower 0.538), FPR 0.429 (upper 0.567) —
  **fails** the platform's benign gate on FPR.

**Conclusion: not fit to certify benign pages.** Four independent fixes were
tested on unseen data and none moved the benign-side failure.

## What blocks further progress

Labelled data, and nothing else:

1. 36 % of phishing captures show no credential vocabulary or domain token in OCR
   (`pilot-triage.md`); labels are feed-derived, not reviewed.
2. Test split is 19 phishing / 12 legitimate; a usable profile needs ~50/class.
3. A PhishTank key is now used in practice; feeds that rehash the same URLs add
   nothing (OpenPhish exhausted, URLhaus 410).

## First actions for the next owner

1. Review or drop the OCR-flagged 36 % of phishing captures.
2. Capture ~150 verified PhishTank URLs (the tool now records `source_url`).
3. Grow the legitimate class to ~50/class, favouring real login, webmail and SSO
   pages — the hard negatives the model currently gets wrong.
4. Run `scripts/refresh_pilot.py`, then `p4_sealed.py` once; publish a profile only
   if FPR ≤ 0.15 and detection ≥ 0.70.

## Honest note on method

The most valuable outputs of this programme are the negative results and the
corrected numbers. The most dangerous one would have been a pipeline that produced
a flattering metric; the guards, pre-registration, and ledger exist to make that
outcome visible when it happens.
