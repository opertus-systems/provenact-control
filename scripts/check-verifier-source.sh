#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
CARGO_TOML="$ROOT_DIR/Cargo.toml"
EXPECTED_REV="edcd94c"

if [[ -d "$ROOT_DIR/crates/provenact-verifier" ]]; then
  echo "error: local crate 'crates/provenact-verifier' must not exist; use shared provenact verifier dependency"
  exit 1
fi

if ! grep -Eq '^provenact-verifier\s*=\s*\{[^}]*git\s*=\s*"https://github.com/opertus-systems/provenact-cli.git"[^}]*package\s*=\s*"provenact-verifier"' "$CARGO_TOML"; then
  echo "error: Cargo.toml must declare provenact-verifier from the shared provenact-cli git source"
  exit 1
fi

if ! grep -Eq "^provenact-verifier\\s*=\\s*\\{[^}]*rev\\s*=\\s*\"$EXPECTED_REV\"" "$CARGO_TOML"; then
  echo "error: Cargo.toml must pin provenact-verifier rev to $EXPECTED_REV"
  exit 1
fi

if grep -Eq '^\[patch\."https://github.com/opertus-systems/provenact-cli.git"\]' "$CARGO_TOML"; then
  echo "error: Cargo.toml must not include local [patch] overrides for provenact-verifier in standalone mode"
  exit 1
fi

echo "ok: verifier source-of-truth checks passed (standalone mode)"
