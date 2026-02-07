# Inactu Control Site Plan

## Objective
Build `inactu-control` into a multi-tenant control plane where users can:
- Sign up and log in.
- Publish and update packages in a repository.
- Manage package visibility (private by default).
- View running cloud contexts and inspect logs.

This plan is scoped for single-user ownership first, with org support designed in but deferred.

## Product Scope

### MVP (Phase 1-3)
- Email/password auth with session management.
- User-owned package repository.
- Package publish + update flows (new version uploads).
- Package listing/search for the current user.
- Package settings (visibility, metadata, deprecate/archive).
- Cloud contexts dashboard (status, runtime metadata, last activity).
- Context log viewer with filtering and pagination.

### Later (Phase 4+)
- Organizations/teams and role-based access control.
- Shared package namespaces.
- Billing/quotas/usage alerts.
- Advanced observability (metrics, traces, alerts).

## Primary User Flows

### 1) Authentication
1. User signs up with email/password.
2. User verifies email.
3. User logs in and receives session/JWT.
4. User can reset password and revoke sessions.

### 2) Publish Package
1. User opens “Publish Package”.
2. User uploads package tarball/manifest.
3. System validates manifest and integrity.
4. User confirms version + visibility.
5. System stores artifact and writes package version record.

### 3) Update Existing Package
1. User opens package detail page.
2. User publishes a new semver version.
3. System enforces immutability for existing versions.
4. Package page shows version history and release metadata.

### 4) Manage Packages
1. User views package list.
2. User filters by visibility/status.
3. User updates metadata (description/tags/readme).
4. User can deprecate/unlist/archive packages.

### 5) Cloud Contexts + Logs
1. User opens “Contexts”.
2. User sees all running/recent contexts with status.
3. User opens a context to inspect details and logs.
4. User filters logs by time, severity, and query text.

## System Architecture

### Frontend (`inactu-control-web` repo)
- Next.js app-router UI.
- Auth pages: signup/login/reset/verify.
- App sections: Packages, Package Detail, Publish, Contexts, Context Detail.
- Session-aware API client (http-only cookie session preferred).

### Backend (`src/bin/inactu-control-web.rs` + modules)
- Rust API for auth, package registry, and context/log APIs.
- Reuse existing verifier endpoints in package publish pipeline.
- Introduce service modules:
  - `auth`
  - `packages`
  - `artifacts`
  - `contexts`
  - `logs`

### Storage
- PostgreSQL:
  - Users, sessions, packages, package_versions, contexts, log_index.
- Object storage (S3-compatible):
  - Package tarballs and immutable blobs.
- Optional queue/stream (later): async processing for ingestion/log fanout.

## Proposed Data Model (Initial)

### `users`
- `id` (uuid, pk)
- `email` (unique)
- `password_hash`
- `email_verified_at`
- `created_at`, `updated_at`

### `sessions`
- `id` (uuid, pk)
- `user_id` (fk -> users)
- `expires_at`
- `created_at`
- `revoked_at` (nullable)

### `packages`
- `id` (uuid, pk)
- `owner_id` (fk -> owners)
- `name`
- `visibility` (`private|public`)
- `description` (nullable)
- `created_at`, `updated_at`
- Unique: (`owner_id`, `name`)

### `package_versions`
- `id` (uuid, pk)
- `package_id` (fk -> packages)
- `version` (semver string)
- `artifact_digest` (sha256 prefixed)
- `manifest_json`
- `published_by_user_id`
- `published_at`
- `deprecated_at` (nullable)
- Unique: (`package_id`, `version`)

### `contexts`
- `id` (uuid, pk)
- `owner_id` (fk -> owners)
- `package_version_id` (fk -> package_versions, nullable)
- `status` (`starting|running|stopped|failed`)
- `region`
- `started_at`, `ended_at` (nullable)

### `context_logs`
- `id` (bigserial, pk)
- `context_id` (fk -> contexts)
- `ts`
- `severity`
- `message`
- `metadata_json` (nullable)
- Indexes: (`context_id`, `ts`), (`context_id`, `severity`)

## API Plan (Incremental)

### Auth
- `POST /v1/auth/signup`
- `POST /v1/auth/login`
- `POST /v1/auth/logout`
- `POST /v1/auth/password/forgot`
- `POST /v1/auth/password/reset`
- `GET /v1/auth/me`

### Packages
- `GET /v1/packages`
- `POST /v1/packages`
- `GET /v1/packages/{package}`
- `PATCH /v1/packages/{package}`
- `POST /v1/packages/{package}/versions`
- `GET /v1/packages/{package}/versions`
- `GET /v1/packages/{package}/versions/{version}`

### Contexts & Logs
- `GET /v1/contexts`
- `GET /v1/contexts/{context_id}`
- `GET /v1/contexts/{context_id}/logs`

## Security & Policy Baseline
- Passwords hashed with Argon2id.
- HttpOnly + Secure session cookies.
- CSRF protection for browser state-changing requests.
- Per-user authorization checks on all resource fetches.
- Package version immutability after publish.
- Rate limits on auth and publish endpoints.
- Audit events for login, publish, visibility change, deprecate/archive.

## Execution Plan

### Phase 1: Foundation (1-2 weeks)
- Add DB migrations + Postgres integration.
- Implement auth service and session middleware.
- Add protected `/v1/auth/me` and basic frontend auth pages in `inactu-control-web`.

Exit criteria:
- User can sign up, log in, and access an authenticated dashboard.

### Phase 2: Package Registry Core (2-3 weeks)
- Implement package and package_version schema + APIs.
- Add artifact upload path (pre-signed URL or direct API upload).
- Wire manifest validation using existing verifier modules.
- Build package list/detail/publish UI.

Exit criteria:
- Authenticated user can publish package versions and manage metadata.

### Phase 3: Contexts and Logs (1-2 weeks)
- Add contexts and logs schema + APIs.
- Build contexts list/detail pages and log stream/pagination UI.
- Add filters: severity, time range, search term.

Exit criteria:
- User can view active/recent contexts and inspect logs reliably.

### Phase 4: Org-Ready Refactor (1-2 weeks)
- Introduce `owners` abstraction (`user` now, `org` later).
- Add membership tables and RBAC scaffolding behind feature flag.
- Keep existing user-only UX unchanged while internal model expands.

Exit criteria:
- Data model supports org ownership without breaking user-owned packages.

## Key Risks & Mitigations
- Upload pipeline complexity: start with synchronous upload + validation, move to async later.
- Log volume growth: enforce retention + pagination, add log storage tiering later.
- Auth/security regressions: add integration tests for authz boundaries and session handling.
- Future org migration pain: introduce owner abstraction before broad adoption.

## Suggested Next Implementation Steps in This Repo
1. Add `docs/adr/` and write ADRs for auth mode, storage choice, and owner model.
2. Add database migration tooling (e.g., `sqlx`/`sea-orm` migrations) and first schema migration.
3. Extend `openapi.yaml` with auth and packages endpoints (start with `auth/me`, `packages list/create`).
4. Create `/app/packages` and `/app/contexts` routes behind auth checks in `inactu-control-web`.
