#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
VENV="${FL_VENV:-$ROOT/.runtime/fl-venv}"
python3 -m venv "$VENV"
"$VENV/bin/python" -m pip install --upgrade pip
"$VENV/bin/python" -m pip install -r "$ROOT/federated_training/requirements-base.txt"
if [[ -n "${PYTORCH_INDEX_URL:-}" ]]; then
  "$VENV/bin/python" -m pip install --index-url "$PYTORCH_INDEX_URL" torch torchvision
else
  "$VENV/bin/python" -m pip install torch torchvision
fi
"$VENV/bin/python" -c 'import torch, torchvision; print("torch", torch.__version__, "cuda", torch.cuda.is_available(), "torchvision", torchvision.__version__)'
