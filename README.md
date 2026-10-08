\# Unified Cybersecurity Platform



A security orchestration platform that integrates heterogeneous cybersecurity signals from \*\*AI-NIDS\*\* and \*\*PhishVision-AI\*\* into a normalized, correlated, explainable security assessment and operational decision.



The project is intentionally separate from both detection systems. It provides the integration and orchestration layer rather than modifying the underlying ML projects.



\## Architecture



```text

&#x20;                   ┌───────────────────────┐

&#x20;                   │   AI-NIDS Result      │

&#x20;                   │ Network intrusion     │

&#x20;                   └──────────┬────────────┘

&#x20;                              │

&#x20;                              ▼

&#x20;                   ┌───────────────────────┐

&#x20;                   │   AI-NIDS Adapter     │

&#x20;                   └──────────┬────────────┘

&#x20;                              │

&#x20;                              │ SecuritySignal

&#x20;                              │

&#x20;                              ▼

┌───────────────────────┐    ┌───────────────────────┐

│ PhishVision-AI Result │───▶│ PhishVision Adapter   │

│ Text / URL / CNN      │    └──────────┬────────────┘

└───────────────────────┘               │

&#x20;                                      │ SecuritySignal

&#x20;                                      ▼

&#x20;                             ┌───────────────────────┐

&#x20;                             │ Correlation Engine    │

&#x20;                             │                       │

&#x20;                             │ - severity            │

&#x20;                             │ - threats             │

&#x20;                             │ - primary threat      │

&#x20;                             │ - evidence             │

&#x20;                             │ - component status    │

&#x20;                             │ - corroboration       │

&#x20;                             └──────────┬────────────┘

&#x20;                                        │

&#x20;                                        ▼

&#x20;                             ┌───────────────────────┐

&#x20;                             │ Decision Layer        │

&#x20;                             │                       │

&#x20;                             │ - action              │

&#x20;                             │ - human review        │

&#x20;                             │ - operational reason  │

&#x20;                             └──────────┬────────────┘

&#x20;                                        │

&#x20;                                        ▼

&#x20;                             ┌───────────────────────┐

&#x20;                             │ Unified Assessment    │

&#x20;                             └───────────────────────┘

```



\## Why a separate integration project?



AI-NIDS and PhishVision-AI solve different security problems and expose different kinds of model output.



AI-NIDS focuses on network intrusion detection and can produce values such as:



\- attack probability

\- prediction

\- confidence

\- severity

\- flow and packet metadata



PhishVision-AI produces phishing-related signals from:



\- text analysis

\- URL analysis

\- visual CNN analysis

\- its existing composite heuristic risk score



These outputs are not directly interchangeable. The unified platform therefore introduces a neutral signal contract and keeps source-specific semantics inside adapters.



\## Core design



\### SecuritySignal



`SecuritySignal` is the normalized domain object used by the integration layer.



It preserves:



\- source

\- signal type

\- availability status

\- raw score

\- raw score semantics

\- normalized score

\- confidence

\- severity

\- evidence

\- metadata

\- timestamp



Scores are not automatically treated as probabilities. Their semantics are explicitly recorded.



\### Adapters



Adapters translate existing subsystem results into the neutral contract.



The adapters currently operate on already-produced results and do \*\*not\*\* import or execute the ML implementations from the two source repositories.



This keeps the projects decoupled and makes the integration layer independently testable.



\### Correlation



The correlation engine aggregates available signals according to an explicit default policy.



The current policy:



```text

UNKNOWN   = 0

MINIMAL   = 1

LOW       = 2

SUSPICIOUS= 3

MEDIUM    = 4

HIGH      = 5

CRITICAL  = 6

```



The overall severity is the highest severity among available signals.



Threats are derived from signals at `SUSPICIOUS` severity or above.



Cross-source corroboration is recorded when threatening signals are present from at least two distinct sources.



Unavailable components are not interpreted as benign.



\### Decision layer



The decision layer translates the correlated assessment into an operational decision.



Current behavior:



| Severity | Default action |

|---|---|

| CRITICAL | INVESTIGATE |

| HIGH | INVESTIGATE |

| SUSPICIOUS | WARN |

| MEDIUM | WARN |

| LOW | MONITOR |

| MINIMAL | ALLOW |

| UNKNOWN | INVESTIGATE |



High-risk and unknown assessments are treated conservatively and can require human review.



The decision layer does not silently replace the correlation policy. It adds operational context such as the decision reason and whether human review is required.



\## Missing and failed signals



The platform explicitly distinguishes between:



```text

AVAILABLE

UNAVAILABLE

ERROR

TIMEOUT

NOT\_APPLICABLE

```



A missing component is not automatically considered safe.



Examples:



```text

AI-NIDS unavailable

PhishVision CNN unavailable

URL not applicable

Adapter validation error

```



These conditions remain visible in the resulting assessment.



\## Explainability



The unified result preserves the information needed to explain why a decision was reached.



A future operator-facing representation can expose:



```text

Overall severity: HIGH



Primary threat:

network\_intrusion



Corroboration:

AI-NIDS + PhishVision



Signals:

\- network intrusion

\- text threat

\- URL threat

\- visual threat



Evidence:

\- source-specific security findings



Recommendation:

INVESTIGATE



Human review:

REQUIRED

```



The architecture intentionally keeps component signals and evidence separate from the overall decision instead of collapsing everything into one opaque score.



\## Current integration status



The current implementation is intentionally \*\*offline and fixture-based\*\*.



It demonstrates the complete flow:



```text

fixture result

&#x20;   ↓

adapter

&#x20;   ↓

SecuritySignal

&#x20;   ↓

correlation

&#x20;   ↓

SecurityAssessment

&#x20;   ↓

operational decision

```



The project does not currently enable live network capture or directly execute either source application's production inference path.



This is deliberate. Live integration should only be introduced after validating the semantic compatibility between live inputs and the source models.



\## Testing



The current test suite covers:



\- security signal contracts

\- score and confidence validation

\- AI-NIDS adaptation

\- PhishVision adaptation

\- missing component behavior

\- correlation policy

\- cross-source corroboration

\- operational decisions

\- orchestration failures

\- fixture-based end-to-end integration

\- API service serialization



Current validation baseline:



```text

38 tests passed

```



Compilation validation:



```text

python -m compileall .\\api .\\core .\\adapters .\\tests

```



Whitespace validation:



```text

git diff --check

```



\## Repository structure



```text

.

├── adapters/

│   ├── ai\_nids/

│   └── phishvision/

├── api/

├── core/

│   ├── correlation/

│   ├── decision/

│   ├── evidence/

│   ├── models/

│   ├── orchestration/

│   └── policies/

├── dashboard/

├── fixtures/

│   ├── ai\_nids/

│   └── phishvision/

├── tests/

│   ├── integration/

│   ├── unit/

│   └── fixtures/

├── .gitignore

└── README.md

```



\## Source projects



The unified platform is designed to integrate two independent projects:



\- \*\*AI-NIDS\*\* — network intrusion detection

\- \*\*PhishVision-AI\*\* — phishing and visual threat detection



The source repositories remain independent. The unified platform should not modify their production behavior merely to simplify integration.



\## Security considerations



The architecture is designed to support explicit handling of:



\- malformed source results

\- invalid scores

\- missing models

\- inference failures

\- unavailable components

\- duplicate evidence

\- untrusted input

\- oversized or expensive processing workloads

\- unsafe serialization

\- sensitive logging concerns



Security controls should remain deterministic, testable, and explainable.



\## Roadmap



The next development stages are:



1\. Expose the existing service boundary through a small HTTP API.

2\. Add API-level validation and integration tests.

3\. Add structured response schemas.

4\. Build an operator-facing dashboard.

5\. Introduce controlled live adapters only after source-domain compatibility is validated.

6\. Add broader evaluation scenarios for partial availability, conflicting signals, and failure handling.



The project should continue to prioritize correctness, reproducibility, maintainability, explainability, and defensible security behavior over simply adding more ML components.

