#!/usr/bin/env bash
set -euo pipefail
source "$(cd "$(dirname "$0")" && pwd)/env.sh"
cd "$PACKAGE_ROOT"
LOG="$PACKAGE_ROOT/logs/suite_$(date -u +%Y%m%dT%H%M%SZ).log"
exec > >(tee -a "$LOG") 2>&1
trap 'code=$?; echo "RUN_FAILED exit=$code line=$LINENO log=$LOG"; exit "$code"' ERR
"$PYTHON" -u scripts/suite.py run --plots "$@"
echo "Run complete; see the printed RESULTS and FIGURES paths."
