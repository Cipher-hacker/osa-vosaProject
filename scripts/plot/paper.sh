#!/usr/bin/env bash
set -euo pipefail
source "$(cd "$(dirname "$0")" && pwd)/env.sh"
"$PYTHON" "$PACKAGE_ROOT/scripts/plot.py" --run "${1:?Pass the completed runs/paper_* directory}"
