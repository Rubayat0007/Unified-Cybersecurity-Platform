# Security and deployment

## Authentication

`POST /v1/assess` and `POST /v1/assess/image` require a bearer token when
`UCP_API_TOKEN` is set:

```
Authorization: Bearer <token>
```

- Missing or wrong token → `401`, with `WWW-Authenticate: Bearer`.
- Comparison uses `hmac.compare_digest` (constant time).
- Public paths: `/health`, `/ready`, `/dashboard*`, `/docs`, `/redoc`,
  `/openapi.json`.
- `development` / `test` run without auth when no token is configured, so
  local work and the test suite keep working.
- `UCP_ENVIRONMENT=production` **refuses to start** without `UCP_API_TOKEN`.

This is a shared-secret model, not user accounts. It answers "is this caller
allowed to talk to the service", not "who is this caller". Multi-tenant
identity, per-user quotas and audit trails are out of scope.

## Rate limiting

Enabled always in `production`, and in development only when configured:

| Variable | Default |
|---|---|
| `UCP_RATE_LIMIT_CAPACITY` | `30` |
| `UCP_RATE_LIMIT_REFILL_PER_SECOND` | `1.0` |

Per client address, token bucket. Exceeding it returns `429` with
`Retry-After`. Verified live: with capacity 30, 13 of 40 rapid requests were
rejected.

State is in-process; a multi-worker deployment limits per worker. Move to a
shared store before scaling horizontally.

## Transport

The service speaks plain HTTP and binds loopback in development. TLS
termination belongs to a reverse proxy or the platform ingress. Do not expose
the container directly to the internet without it.

## Container

`Dockerfile` builds a non-root image with a healthcheck on `/health`.

```powershell
docker build -t ucp:local .
docker run --rm -p 8000:8000 `
  -e UCP_ENVIRONMENT=production `
  -e UCP_API_TOKEN=change-me `
  ucp:local
```

Docker was not available on the machine where this was authored, so the image
was **not built or run**. The Dockerfile is reviewed by reading, and the
service itself is verified natively by `scripts/smoke_live.py`. Treat the
image as unverified until a build succeeds.

## PhishVision runtime

The image does not include PhishVision (torch, EasyOCR, checkpoint). Set
`UCP_PHISHVISION_ROOT` and `UCP_PHISHVISION_PYTHON` to a mounted runtime, or
run the image without the image endpoint accepting requests (the provider
fails safe: `error` signals, `200` response with an investigate decision).
