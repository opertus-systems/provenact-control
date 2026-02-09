# Contributing

## Scope Guardrails

`provenact-control` is a control-plane service. Changes must not weaken Provenact
substrate trust boundaries.

Allowed:
- control-plane APIs and metadata workflows
- verifier-backed validation paths
- deterministic, auditable service behavior

Not allowed:
- agent planning/orchestration logic
- ambient authority shortcuts
- bypasses for manifest/signature/policy verification

## Development Standards

- Keep changes small and reviewable.
- Add tests for behavior changes.
- Keep docs and OpenAPI examples aligned with code.
- Keep `COMPATIBILITY.md` aligned with `Cargo.toml` verifier pin changes.
- Run local gates before opening a PR:

```bash
cargo fmt --all --check
cargo clippy --all-targets --all-features -- -D warnings
cargo test --locked
cargo test --locked --features web --bin provenact-control-web
```

## Security Reporting

See `SECURITY.md` for coordinated vulnerability disclosure.

## Work item labeling

All work must have `area:*`, `type:*`, and `risk:*` labels so it is triaged and synced into the org project.
