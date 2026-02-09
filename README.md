# provenact-control

Standalone SaaS/control-plane scaffold for Provenact.

Ecosystem map: `provenact/docs/ecosystem.md` in the substrate repository.
Verifier compatibility pin: `COMPATIBILITY.md`.

## Planning

- Product + implementation roadmap: `docs/site-plan.md`
- Architecture decisions (ADR): `docs/adr/`

## Scope

- API surface for control-plane concerns.
- Reuse of `provenact-verifier` for validation-heavy endpoints.
- No changes to Provenact runtime trust boundaries.
- Web console now lives in `provenact-control-web`:
  https://github.com/opertus-systems/provenact-control-web

## Backend (Rust API)

```bash
cargo run -p provenact-control --features web --bin provenact-control-api
```

Legacy compatibility alias remains available as `provenact-control-web`.

Default `cargo build`/`cargo test` uses the non-web core baseline. The HTTP API
is opt-in via the `web` feature.

Optional environment variables:

- `PROVENACT_CONTROL_BIND` (default: `127.0.0.1:8080`)
- `RUST_LOG` (default: `info`)
- `DATABASE_URL` (Postgres/Neon connection URL)
- `PROVENACT_API_AUTH_SECRET` (shared secret for web-to-api bearer bridge, at least 32 bytes)
- `PROVENACT_MAX_REQUESTS_PER_MINUTE` (default: `120`, per-user sliding-window
  limit on authenticated endpoints)

Auth replay and request-rate enforcement for authenticated endpoints is persisted
in Postgres tables (`bridge_token_replays`, `api_request_events`) to remain
effective in multi-instance deployments.

This repo is pinned to Rust `1.90.0` via `rust-toolchain.toml`.

On startup, if `DATABASE_URL` is set, the API connects to Postgres and applies SQL migrations from `migrations/`.

## Web Console

The standalone Next.js web console is maintained in:

- `https://github.com/opertus-systems/provenact-control-web`

This repository now contains only the Rust API/control-plane service.

## Run with Docker

Build and run with Docker Compose:

```bash
docker compose up --build
```

The service is exposed on `http://localhost:8080`.
Postgres is exposed on `localhost:5432`.

## Endpoints

- `GET /healthz`
- `POST /v1/verify/manifest`
- `POST /v1/verify/receipt`
- `POST /v1/hash/sha256`
- `GET /v1/packages` (requires bearer token bridge from web session)
- `POST /v1/packages` (requires bearer token bridge from web session)
- `GET /v1/packages/{package}/versions` (requires bearer token bridge from web session)
- `POST /v1/packages/{package}/versions` (requires bearer token bridge from web session)
- `POST /v1/packages/{package}/versions/{version}/deprecate` (requires bearer token bridge from web session)
- `GET /v1/contexts` (requires bearer token bridge from web session)
- `POST /v1/contexts` (requires bearer token bridge from web session)
- `GET /v1/contexts/{context_id}` (requires bearer token bridge from web session)
- `PATCH /v1/contexts/{context_id}` (requires bearer token bridge from web session)
- `GET /v1/contexts/{context_id}/logs` (requires bearer token bridge from web session)
- `POST /v1/contexts/{context_id}/logs` (requires bearer token bridge from web session)

## OpenAPI

- OpenAPI document: `openapi.yaml`
- Request examples:
  - `examples/hash-request.json`
  - `examples/verify-manifest-request.json`
  - `examples/verify-manifest-request-v1.json`
  - `examples/verify-receipt-request.json`
  - `examples/verify-receipt-request-v1.json`

Quick curl examples:

```bash
curl -s http://localhost:8080/healthz

curl -s -X POST http://localhost:8080/v1/hash/sha256 \
  -H 'content-type: application/json' \
  --data @examples/hash-request.json

curl -s -X POST http://localhost:8080/v1/verify/manifest \
  -H 'content-type: application/json' \
  --data @examples/verify-manifest-request.json

curl -s -X POST http://localhost:8080/v1/verify/manifest \
  -H 'content-type: application/json' \
  --data @examples/verify-manifest-request-v1.json

curl -s -X POST http://localhost:8080/v1/verify/receipt \
  -H 'content-type: application/json' \
  --data @examples/verify-receipt-request.json

curl -s -X POST http://localhost:8080/v1/verify/receipt \
  -H 'content-type: application/json' \
  --data @examples/verify-receipt-request-v1.json
```

Context/logs API examples (requires `PROVENACT_API_AUTH_SECRET`-signed bearer token):

```bash
curl -s -X POST http://localhost:8080/v1/contexts \
  -H "authorization: Bearer $PROVENACT_BRIDGE_TOKEN" \
  -H 'content-type: application/json' \
  --data '{"status":"running","region":"local-dev"}'

curl -s -X POST http://localhost:8080/v1/contexts/<context_id>/logs \
  -H "authorization: Bearer $PROVENACT_BRIDGE_TOKEN" \
  -H 'content-type: application/json' \
  --data '{"severity":"info","message":"context started"}'

curl -s "http://localhost:8080/v1/contexts/<context_id>/logs?severity=info&from=2026-02-06T00:00:00Z&to=2026-02-06T23:59:59Z" \
  -H "authorization: Bearer $PROVENACT_BRIDGE_TOKEN"
```
