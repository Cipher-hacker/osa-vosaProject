#!/usr/bin/env bash
set -euo pipefail
ROOT="$(cd "$(dirname "$0")" && pwd)"
exec "${PYTHON_SOURCE:-python3}" "$ROOT/project.py" "$@"
