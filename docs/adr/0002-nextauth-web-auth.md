# ADR 0002: Use NextAuth.js for Web Authentication

## Status
Accepted

## Context
The web app needs reliable signup/login/session handling with minimal custom auth plumbing and strong ecosystem support. Auth should integrate with Postgres so sessions and account state are durable.

## Decision
- Use NextAuth.js in the Next.js app for browser auth flows.
- Use Postgres-backed persistence (Neon in production) for auth state.
- Use secure cookie-based sessions for browser interactions.
- Keep the Rust API as resource server; web frontend calls API using authenticated session context.

## Rationale
- NextAuth gives battle-tested session handling, providers, CSRF controls, and callback hooks.
- Cookie sessions reduce token handling complexity in browser clients.
- Postgres-backed auth state supports revocation, auditability, and multi-device session management.

## Consequences
- Next.js app requires `NEXTAUTH_SECRET` and `NEXTAUTH_URL`.
- Shared authorization model must be defined between Next.js and Rust API (phase 1 integration task).
- Initial implementation should start with credentials/email flow; additional providers can be added later.

## Follow-up
- Implement `/api/auth/[...nextauth]` route and auth config in `inactu-control-web`.
- Define how Rust API authorizes requests originating from NextAuth sessions.
- Add integration tests for login/session lifecycle.
