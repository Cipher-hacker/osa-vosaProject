#!/usr/bin/env bash
set -euo pipefail
TASK_ROOT="$(cd "$(dirname "$0")" && pwd)"
BASE="${1:-/root/autodl-tmp/OSA_Paper_Experiments_CPU_20261008}"
if (( $# > 0 )); then shift; fi
source "$BASE/scripts/env.sh"
export PYTHONDONTWRITEBYTECODE=1
mkdir -p "$TASK_ROOT/logs"
LOG="$TASK_ROOT/logs/computation_$(date -u +%Y%m%dT%H%M%SZ).log"
exec > >(tee -a "$LOG") 2>&1
trap 'code=$?; echo "COMPUTATION_FAILED exit=$code line=$LINENO log=$LOG"; exit "$code"' ERR
"$PYTHON" -u "$TASK_ROOT/runner.py" run --base "$BASE" "$@"
echo "RUN_PASS log=$LOG"
