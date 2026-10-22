#!/usr/bin/env bash
set -euo pipefail
TASK_ROOT="$(cd "$(dirname "$0")" && pwd)"
BASE="${1:-/root/autodl-tmp/OSA_Paper_Experiments_CPU_20261008}"
source "$BASE/scripts/env.sh"
export PYTHONDONTWRITEBYTECODE=1
if [[ -f "$TASK_ROOT/current.json" ]]; then
  "$PYTHON" "$TASK_ROOT/runner.py" status
else
  echo "No current formal run; inspect logs/prepare_*.log"
fi
ps -ww -eo pid,ppid,etime,time,pcpu,stat,args | grep -E '[O]SA_Computation_Retest_20261013|[r]ustc|[c]argo|[b]azel' || true
