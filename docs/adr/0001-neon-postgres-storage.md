# ADR 0001: Use Neon Postgres for Control-Plane Storage

## Status
Accepted

## Context
`provenact-control` needs durable relational storage for users, sessions, package metadata, package versions, running contexts, and log indexing. The system also needs an easy managed option for production and a compatible local developer workflow.

## Decision
- Use PostgreSQL as the system of record.
- Use Neon-hosted Postgres in cloud environments.
- Use a standard `DATABASE_URL` connection string for all environments.
- Use SQL migrations checked into this repo under `migrations/`.
- Use `sqlx` in the Rust API for runtime DB access.

## Rationale
- Postgres is a strong fit for transactional multi-tenant metadata.
- Neon provides managed Postgres with serverless ergonomics and branching workflows.
- `DATABASE_URL` keeps deploy targets portable and avoids provider lock-in at the application layer.
- SQL migrations provide explicit and reviewable schema evolution.

## Consequences
- Runtime requires valid `DATABASE_URL` in environments where DB-backed features are enabled.
- TLS should be enabled in cloud URLs (Neon default behavior).
- Local development can use Docker Postgres with the same schema/migrations.

## Follow-up
- Add migration runner workflow to CI/CD.
- Add pool sizing and statement timeout settings per environment.
