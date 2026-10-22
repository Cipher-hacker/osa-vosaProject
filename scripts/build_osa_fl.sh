#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
export BAZEL_CACHE_ROOT="${BAZEL_CACHE_ROOT:-$ROOT/.runtime/bazel-cache}"
source "$ROOT/scripts/common.sh"

for executable in gcc g++ make; do
  command -v "$executable" >/dev/null || { echo "Missing build tool: $executable" >&2; exit 1; }
done

PROTO_ROOT="$ROOT/protocols"
if [[ ! -d "$PROTO_ROOT" && -d "$ROOT/source" ]]; then
  PROTO_ROOT="$ROOT/source"
fi

cd "$PROTO_ROOT/secure-aggregation-main"
run_bazel build "${BAZEL_FLAGS[@]}" --jobs="${BUILD_JOBS:-16}" \
  //willow/benches:osa_vosa_shell_kahe_real_fl_bridge
