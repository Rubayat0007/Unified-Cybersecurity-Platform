# API contract

What this service guarantees, and what it deliberately does not. Code is
the source of truth; this document records the promises the tests pin.

## Endpoints

| Method | Path | Purpose |
|---|---|---|
| `GET` | `/health` | process liveness; returns environment |
| `GET` | `/ready` | component state honestly: `ingestion_only` for AI-NIDS; `not_started` / `started` / `disabled` for the lazy PhishVision worker |
| `POST` | `/v1/assess` | assess already-produced detector results (JSON body) |
| `POST` | `/v1/assess/image` | run PhishVision on raw image bytes, then assess |
| `GET` | `/dashboard` | static operator dashboard |
| `GET` | `/docs`, `/openapi.json` | FastAPI-generated docs |

Binds to loopback for local use. There is no authentication, authorization,
rate limiting, or TLS: do not expose it to an untrusted network.

## Response shape

Every successful assessment returns the same three-part envelope:

```json
{
  "assessment": { "overall_severity": "...", "signals": [], "evidence": [],
                  "component_status": {}, "recommended_action": "..." },
  "decision":   { "severity": "...", "action": "...", "reason": "...",
                  "requires_human_review": true },
  "audit":      { "event_id": "...", "processed_at": "...", "source_statuses": {},
                  "overall_severity": "...", "recommended_action": "...",
                  "human_review_required": true }
}
```

Contract guarantees:

- `assessment.component_status` reports the worst status per source
  (`error` > `timeout` > `available` > `unavailable` > `not_applicable`).
- A missing source produces `unavailable` signals; a failed adapter produces
  `error` signals. Neither is treated as benign.
- When no usable severity exists, `overall_severity` is `unknown` and the
  decision is `investigate` with `requires_human_review: true`.
- `decision.action` is an assessment output. Nothing is blocked or enforced.
- `audit.event_id` echoes the caller's `event_id` or a generated UUID.

## `/v1/assess` request

```json
{ "event_id": "optional, <=128 chars",
  "ai_nids_result": { "prediction": 0|1, "confidence": 0..1,
                      "attack_probability": 0..1, "severity": "LOW|MEDIUM|HIGH|SUSPICIOUS",
                      "packet_count": 0, "duration": 0.0, "flows": [] },
  "phishvision_result": { "text_analysis": {...}, "url_analysis": {...}|null,
                          "cnn_analysis": {...}, "risk": {...},
                          "security_assessment": { "evidence": [] } } }
```

Both source objects are optional and independent. Required AI-NIDS fields are
`prediction`, `confidence`, `attack_probability`, `severity`; anything else is
metadata. Extra top-level fields are rejected (`extra="forbid"`).

## `/v1/assess/image` request

- Body: raw image bytes, `Content-Type` one of `image/jpeg`, `image/png`,
  `image/webp`. No multipart.
- Optional query: `url` (≤2048 chars), `event_id` (≤128 chars).
- PhishVision runs out-of-process through a persistent worker.

## Failure semantics

| Status | Condition |
|---|---|
| `413` | body exceeds the configured limit (1 MiB general, 10 MiB image) |
| `415` | unsupported image media type |
| `422` | empty/invalid image, invalid query params, or payload too deep/large |

Provider failure (worker crash, timeout, malformed output) is **not** a 5xx:
it becomes `error` signals for every PhishVision component, and the response
is a `200` with a fail-safe decision. Malformed *client* input is a 4xx.

## Payload limits

`MAX_DEPTH 8`, `MAX_TOTAL_NODES 2048`, `MAX_COLLECTION_ITEMS 128`,
`MAX_STRING_LENGTH 4096`. A realistic AI-NIDS aggregate with many `flows`
exceeds the node budget (roughly 70 flows), so send the aggregate without
`flows` when posting from real captures.

## Not guaranteed

- Cross-detector score comparability. `raw_score_semantics` names what each
  score means; the platform never treats them as one probability.
- That a `warn`/`monitor` recommendation is a calibrated risk level; the
  composite PhishVision score is a documented heuristic.
- Persistence: no database, no result store; `audit` is data, not a ledger.
