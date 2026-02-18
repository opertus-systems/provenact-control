# API Stability Policy (v0.1)

This document defines the externally stable API subset for Provenact control
plane Phase 0/0.1.

Canonical contract source: `openapi.yaml`.

## Stable Subset (v0.1)

Core verification/hash endpoints:
- `POST /v1/hash/sha256`
- `POST /v1/verify/manifest`
- `POST /v1/verify/receipt`

Optional package publishing endpoints:
- `GET /v1/packages`
- `POST /v1/packages`
- `GET /v1/packages/{package}/versions`
- `POST /v1/packages/{package}/versions`
- `POST /v1/packages/{package}/versions/{version}/deprecate`

Optional context lifecycle endpoints:
- `GET /v1/contexts`
- `POST /v1/contexts`
- `GET /v1/contexts/{context_id}`
- `PATCH /v1/contexts/{context_id}`
- `GET /v1/contexts/{context_id}/logs`
- `POST /v1/contexts/{context_id}/logs`

## Versioning Rules

- Major API version is path-based (`/v1`).
- Breaking changes require a new major path (`/v2`).
- Within `/v1`, additive fields/endpoints are allowed.
- Existing request/response fields in the stable subset must not be removed or
  have incompatible type changes.

## Deprecation Policy

- Deprecations are announced in `CHANGELOG.md` and reflected in `openapi.yaml`.
- Deprecated endpoints/fields remain available for at least two released
  versions after announcement.
- Removal only occurs at next major version path.

## Auth Assumptions

- Local/dev mode:
  - hash/verify endpoints may run without enterprise auth integration.
- Enterprise mode:
  - package/context lifecycle endpoints require bearer-bridge auth and server
    side replay/rate controls.

## Source of Truth and Mirroring

- `openapi.yaml` in this repository is authoritative.
- Web mirror (`provenact-control-web/public/openapi.yaml`) must match the
  pinned source commit under sync-manifest parity checks.
