# Security policy

## What this service is

A local, development-grade assessment API that correlates two detector results
into one explainable decision. It binds loopback by default, recommends actions
rather than taking them, and has no multi-user identity model.

Read `docs/threat-model.md` before deploying it anywhere other than a workstation.
It lists, per trust boundary, what is mitigated and what is residual.

## Supported use

- Local analysis on a workstation you control.
- Pre-release checks through `scripts/smoke_live.py` and the CI workflow.
- Research use as described in the repository README.

## Not supported

- Exposure to the public internet.
- Multi-tenant operation, per-user authorisation, or SSO.
- Any use where a wrong decision causes automatic harm: the platform does not
  block traffic or modify external systems, and must not be wired to do so.

## Controls in place

| Control | Where | Test |
|---|---|---|
| Bearer token, constant-time compare, production requires it | `api/auth.py` | `tests/unit/test_auth.py` |
| Per-client rate limiting with `Retry-After` | `api/auth.py` | same |
| Request size, depth, and content-type limits | `api/middleware.py`, `api/app.py` | integration suite |
| No request content in logs | `api/observability.py` | `tests/unit/test_observability.py` |
| Hash-chained audit, fail closed (503) | `api/audit_sink.py`, `core/audit/store.py` | `tests/unit/test_audit_store.py`, `test_audit_sink.py` |
| Model digest verified before load | PhishVision `src/models/integrity.py` | PhishVision `tests/test_model_integrity.py` |
| Claims tied to evidence rows | `docs/ledger.md`, README tables | `D:\Projects\check_claims.py` |

## Reporting a vulnerability

This is a personal research project without a bug bounty or an on-call rotation.
Open a private report through the repository's security advisory feature, or
contact the maintainer directly. Include: affected commit/tag, the boundary
involved (see the threat model), a minimal reproduction, and what an attacker
gains.

Please do not open a public issue for an unpatched vulnerability, and do not
test against systems you do not own.

## Known limitations, stated plainly

- One static token; no rotation, no per-client identity.
- Rate limiting is per process; multiple workers multiply the effective limit.
- The audit chain detects edits only without full file access.
- The PhishVision worker is not sandboxed beyond timeouts and output caps.
- No SBOM, vulnerability scan, or signed release yet.
- No TLS: terminate at a reverse proxy.

## Disclosure of AI/ML limitations

The detectors' measured reliability is published in `docs/profiles/`. Both
currently fail the platform's own benign-verdict gate, which is why `ALLOW` is
escalated. That is intentional behaviour, not a defect to be worked around.
