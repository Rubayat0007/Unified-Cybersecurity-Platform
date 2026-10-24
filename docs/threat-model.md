# Threat model (STRIDE, per trust boundary)

Scope: the Unified-Cybersecurity-Platform as it exists today. Every mitigation
named here is implemented and tested unless marked otherwise. This document
exists to decide what to build next, not to claim the system is secure.

Assets: assessment results, audit chain integrity, the PhishVision worker
process, the API token, and the host.

## Boundary 1 — client to API (HTTP)

| Threat | Mitigation | Residual |
|---|---|---|
| Spoofing | Bearer token, `hmac.compare_digest`, production refuses to start without one | shared secret, no per-user identity; token in a header can leak through a proxy log |
| Tampering | Pydantic models with `extra="forbid"`; payload depth/size guards | body is trusted once parsed |
| Repudiation | JSON request log with `request_id`; audit chain records the assessment | logs are not signed and are host-local |
| Information disclosure | error bodies are generic; logs exclude query, headers and body (tested) | response includes evidence text by design |
| Denial of service | 1 MiB / 10 MiB body caps, depth 8, 2048 nodes, 128 items, 4096 chars, per-client token bucket | single worker; no global concurrency limit; rate state is per process |
| Elevation of privilege | only two POST routes; no shell, no path input | compromise of the token is full API access |

## Boundary 2 — API to PhishVision worker (subprocess)

| Threat | Mitigation | Residual |
|---|---|---|
| Spoofing | worker is our own script, launched with a configured interpreter and cwd | `UCP_PHISHVISION_PYTHON` is operator-controlled; a hostile interpreter is game over |
| Tampering | JSON-lines protocol; bounded output; response validated as a mapping | worker runs with the same OS privileges as the API |
| Information disclosure | worker stderr captured as a bounded tail; not returned to clients | stderr may contain local paths in logs |
| Denial of service | startup/request timeouts, output byte cap, restart on protocol violation | a worker that hangs consumes a request slot until timeout |
| Elevation | model digest verified before `torch.load(weights_only=True)` | no sandbox (no seccomp/container limits): 6.5 is not done |

**This is the weakest boundary in the system.** The worker executes Python from
a mounted runtime directory and is not resource-isolated beyond timeouts.

## Boundary 3 — API to disk (audit chain)

| Threat | Mitigation | Residual |
|---|---|---|
| Tampering | hash chain with `prev_hash`; `verify()` locates the first bad row | anyone with write access to the file can rewrite the whole chain; no external anchor |
| Repudiation | every successful assessment is appended before the response (fail closed, 503) | records are only as good as the clock |
| Information disclosure | payload holds ids, severities, digests — no evidence text or images | file permissions are the operator's responsibility |
| Denial of service | SQLite write failure → 503 | full disk makes the API unavailable by design |

## Boundary 4 — operator to configuration (environment)

| Threat | Mitigation | Residual |
|---|---|---|
| Spoofing / privilege | production requires a token; readiness reports state | environment variables are visible to anything that can read `/proc` or the container spec |
| Misconfiguration | invalid values fail fast (`UCP_RATE_LIMIT_*`, `UCP_RELIABILITY_FLOOR`) | `UCP_AUDIT_DB` unset silently disables persistence |
| Secret exposure | no secrets in code; `.env` ignored | token rotation not implemented; one static secret |

## Boundary 5 — CI to artifacts

| Threat | Mitigation | Residual |
|---|---|---|
| Supply chain | pinned CI Python, installs from `requirements.txt` | no hash pinning, no SBOM, no `pip-audit` yet (6.8) |
| Artifact substitution | model digest checked at load; recorded in ledger/profile | dataset had no manifest until v3 tooling |
| Unverified claims | claims-to-ledger checker; verification commands recorded | checker is not yet in CI |

## Explicitly out of scope today

- TLS termination (intended for a reverse proxy; the app speaks HTTP).
- Multi-tenant identity, quotas per user, SSO.
- Model poisoning and adversarial training defence (Phase 4/7).
- Physical and endpoint security of the capture machines.
- Automatic response/blocking: the platform only recommends.

## Prioritised gaps

1. **Worker sandboxing (6.5)** — the only boundary where a compromised component
   has full process privileges. Timeouts are not isolation.
2. **Audit external anchoring (6.1c)** — the chain detects edits only if an
   attacker does not have write access to the whole file.
3. **Multi-worker rate limiting (6.4)** — per-process state is a documented limit,
   not a bug, but it is a false sense of protection at scale.
4. **Supply chain (6.8)** — no SBOM, no vulnerability scan, no signed release.

## Rules this document imposes

- Do not describe the platform as "secure"; describe it as "hardened to the
  extent listed, with these residual risks".
- Any new boundary or capability adds a row here before it ships.
