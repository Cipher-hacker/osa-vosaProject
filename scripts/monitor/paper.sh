#!/usr/bin/env bash
set -euo pipefail
source "$(cd "$(dirname "$0")" && pwd)/env.sh"
RUN="${1:?Pass the runs/paper_* directory shown at experiment start}"
"$PYTHON" "$PACKAGE_ROOT/scripts/suite.py" status --run "$RUN"
echo 'Processes (CPU percentage can exceed 100 on multicore):'
ps -ww -eo pid,ppid,etime,time,pcpu,stat,args | grep -E '[s]uite.py run|[t]acita-ste-comparison bench|[b]ench_ud_vector|[/]bin/(osa|opa|willow|vosa)|[k]ahe_stage_fig7' || true
