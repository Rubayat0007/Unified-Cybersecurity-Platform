# Evidence ledger — Unified-Cybersecurity-Platform

Append-only. A capability claim must name a row here.

| ID | commit | date | command | scope | result | status |
|---|---|---|---|---|---|---|
| R-UCP-tests-01 | 7d66c7c | 2026-10-24 | `unittest discover` unit + integration | — | 196 unit OK, 35 integration OK, exit 0 | RECORDED |
| R-UCP-fixture-01 | 7d66c7c | 2026-10-24 | `unittest tests.unit.test_phishvision_recorded_fixture` | real analyzer output captured from PhishVision v2 | 7 tests: three signals, availability, probabilities, metadata, evidence attribution | RECORDED |
| R-UCP-auth-01 | 7d66c7c | 2026-10-24 | uvicorn + probes (`UCP_ENVIRONMENT=production`) | auth and rate limiting | unauth 401, bearer 200, /health 200, 13/40 burst requests 429 | RECORDED |
| R-UCP-smoke-01 | 7d66c7c | 2026-10-24 | `scripts/smoke_live.py` | full chain incl. real PhishVision worker | 10/10 checks pass | RECORDED |
| R-UCP-container-01 | 7d66c7c | 2026-10-24 | `scripts/container_smoke.py` | Dockerfile COPY set + clean env | 6/6 checks; found and fixed missing `dashboard/` copy | RECORDED |
| R-UCP-crossdomain-01 | 7d66c7c | 2026-10-24 | `scripts/cross_domain_demo.py` | captured traffic + real analyzer | benign capture + phishing: high, corroboration false; attack fixture + phishing: high, corroboration true, primary threat network_intrusion | RECORDED |
| R-UCP-image-01 | 7d66c7c | 2026-10-24 | — | container image | **not built**; base image, layer cache, HEALTHCHECK unverified | UNVERIFIED |

Notes:
- `R-UCP-image-01` is deliberately a negative row: the container contents are
  emulated and verified, the image itself is not.
- Rate-limit state is per process; multi-worker behaviour is unverified.
