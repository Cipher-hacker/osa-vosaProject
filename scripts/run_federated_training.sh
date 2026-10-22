#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
VENV="${FL_VENV:-$ROOT/.runtime/fl-venv}"
if [[ ! -x "$VENV/bin/python" ]]; then
  if python3 -c 'import torch' >/dev/null 2>&1; then
    cd "$ROOT"
    exec python3 -m federated_training.train "$@"
  fi
  echo "Missing $VENV. Run scripts/setup_federated_training.sh first or set FL_VENV." >&2
  exit 1
fi
cd "$ROOT"
exec "$VENV/bin/python" -m federated_training.train "$@"
