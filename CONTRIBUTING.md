# Contributing

## Scope Guardrails

`inactu-control` is a control-plane service. Changes must not weaken Inactu
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
cargo test --locked --features web --bin inactu-control-web
```

## Security Reporting

See `SECURITY.md` for coordinated vulnerability disclosure.
