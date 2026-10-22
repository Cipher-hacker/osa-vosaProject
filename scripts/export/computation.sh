#!/usr/bin/env bash
set -euo pipefail
TASK_ROOT="$(cd "$(dirname "$0")" && pwd)"
BASE="${1:-/root/autodl-tmp/OSA_Paper_Experiments_CPU_20261008}"
RUN="${2:-}"
source "$BASE/scripts/env.sh"
export PYTHONDONTWRITEBYTECODE=1
if [[ -z "$RUN" ]]; then
  RUN="$("$PYTHON" -c 'import json,sys; print(json.load(open(sys.argv[1]))["run"])' "$TASK_ROOT/current.json")"
fi
"$PYTHON" "$TASK_ROOT/runner.py" export --run "$RUN"
