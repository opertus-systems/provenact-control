# Security Policy

## Reporting

Report vulnerabilities privately to the maintainers before public disclosure.
Include:
- affected endpoint(s)
- reproduction steps
- impact assessment
- suggested remediation

## Scope

`inactu-control` is a control-plane/service layer. It must not weaken Inactu
substrate trust boundaries:
- no capability elevation beyond substrate policy
- no bypass of manifest/signature/receipt verification semantics
- no ambient authority assumptions

## Operational Baseline

- Run CI security checks on every push/PR.
- Keep dependencies updated and audit findings triaged.
- Treat auth/session/token handling as high-risk surfaces.
- Keep the default audited build non-web; run HTTP API only with explicit
  `web` feature enablement.
- Enforce bounded request rates and reject replayed bearer tokens (`jti`) on
  authenticated API paths.

## RustSec Exception (Documented)

`cargo audit` is configured via `.cargo/audit.toml` to ignore
`RUSTSEC-2023-0071` (`rsa` via `sqlx-mysql`) because:
- `inactu-control` uses PostgreSQL-only query/runtime paths.
- CI enforces that the runtime dependency graph excludes `sqlx-mysql`.
- No fixed upstream patch exists at time of writing.

This exception must be removed once upstream dependencies no longer pull the
advisory path.
