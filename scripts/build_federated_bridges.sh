#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
source "$ROOT/scripts/common.sh"

PROTO_ROOT="$ROOT/protocols"
if [[ ! -d "$PROTO_ROOT" && -d "$ROOT/source" ]]; then
  PROTO_ROOT="$ROOT/source"
fi

pushd "$PROTO_ROOT/opa-secure-aggregation" >/dev/null
run_bazel build "${BAZEL_FLAGS[@]}" //opa:real_fl_bridge_optimized
popd >/dev/null

pushd "$PROTO_ROOT/secure-aggregation-main" >/dev/null
run_bazel build "${BAZEL_FLAGS[@]}" \
  //willow/benches:real_fl_bridge \
  //willow/benches:osa_vosa_shell_kahe_real_fl_bridge
popd >/dev/null

echo "Federated aggregation bridges built successfully."
