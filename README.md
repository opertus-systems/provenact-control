# inactu-control

Standalone SaaS/control-plane scaffold for Inactu.

## Planning

- Product + implementation roadmap: `docs/site-plan.md`
- Architecture decisions (ADR): `docs/adr/`

## Scope

- API surface for control-plane concerns.
- Reuse of `inactu-verifier` for validation-heavy endpoints.
- No changes to Inactu runtime trust boundaries.
- Includes a Next.js frontend scaffold at `web`.

## Backend (Rust API)

```bash
cargo run -p inactu-control --features web --bin inactu-control-web
```

Default `cargo build`/`cargo test` uses the non-web core baseline. The HTTP API
is opt-in via the `web` feature.

Optional environment variables:

- `INACTU_CONTROL_BIND` (default: `127.0.0.1:8080`)
- `RUST_LOG` (default: `info`)
- `DATABASE_URL` (Postgres/Neon connection URL)
- `INACTU_API_AUTH_SECRET` (shared secret for web-to-api bearer bridge)

This repo is pinned to Rust `1.88.0` via `rust-toolchain.toml`.

On startup, if `DATABASE_URL` is set, the API connects to Postgres and applies SQL migrations from `migrations/`.

## Frontend (Next.js)

```bash
cd web
npm install
npm run dev
```

Set `NEXT_PUBLIC_INACTU_API_BASE_URL` in `web/.env.local`.
For auth flows, also set `NEXTAUTH_URL`, `NEXTAUTH_SECRET`, and `DATABASE_URL` in `web/.env.local`.

Vercel deployment: use `web` as the project root.

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

Context/logs API examples (requires `INACTU_API_AUTH_SECRET`-signed bearer token):

```bash
curl -s -X POST http://localhost:8080/v1/contexts \
  -H "authorization: Bearer $INACTU_BRIDGE_TOKEN" \
  -H 'content-type: application/json' \
  --data '{"status":"running","region":"local-dev"}'

curl -s -X POST http://localhost:8080/v1/contexts/<context_id>/logs \
  -H "authorization: Bearer $INACTU_BRIDGE_TOKEN" \
  -H 'content-type: application/json' \
  --data '{"severity":"info","message":"context started"}'

curl -s "http://localhost:8080/v1/contexts/<context_id>/logs?severity=info&from=2026-02-06T00:00:00Z&to=2026-02-06T23:59:59Z" \
  -H "authorization: Bearer $INACTU_BRIDGE_TOKEN"
```
