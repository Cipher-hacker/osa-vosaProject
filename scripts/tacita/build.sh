#!/usr/bin/env bash
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT"
export CARGO_HOME="${CARGO_HOME:-$ROOT/.runtime/cargo}"
export CARGO_TARGET_DIR="$ROOT/target"
mkdir -p "$CARGO_HOME" "$ROOT/.runtime/tmp"
export TMPDIR="$ROOT/.runtime/tmp"
cargo build --release --locked -j "${JOBS:-32}"
cargo test --release --locked -j "${JOBS:-32}"
