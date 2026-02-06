#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
CARGO_TOML="$ROOT_DIR/Cargo.toml"

if [[ -d "$ROOT_DIR/crates/inactu-verifier" ]]; then
  echo "error: local crate 'crates/inactu-verifier' must not exist; use shared inactu verifier dependency"
  exit 1
fi

if ! grep -Eq '^inactu-verifier\s*=\s*\{[^}]*git\s*=\s*"https://github.com/opertus-systems/inactu.git"[^}]*package\s*=\s*"inactu-verifier"' "$CARGO_TOML"; then
  echo "error: Cargo.toml must declare inactu-verifier from the shared inactu git source"
  exit 1
fi

if grep -Eq '^\[patch\."https://github.com/opertus-systems/inactu.git"\]' "$CARGO_TOML"; then
  echo "error: Cargo.toml must not include local [patch] overrides for inactu-verifier in standalone mode"
  exit 1
fi

echo "ok: verifier source-of-truth checks passed (standalone mode)"
