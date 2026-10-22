#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
source "$ROOT/scripts/common.sh"

PROTO_ROOT="$ROOT/protocols"
if [[ ! -d "$PROTO_ROOT" && -d "$ROOT/source" ]]; then
  PROTO_ROOT="$ROOT/source"
fi

python3 -m compileall -q "$ROOT/federated_training"
PYTHONPATH="$ROOT" python3 -m unittest \
  federated_training.tests.test_config_only

pushd "$PROTO_ROOT/opa-secure-aggregation" >/dev/null
run_bazel test "${BAZEL_FLAGS[@]}" //opa:opalwr_fl_params_test
run_bazel build "${BAZEL_FLAGS[@]}" //opa:real_fl_bridge_optimized
popd >/dev/null

pushd "$PROTO_ROOT/secure-aggregation-main" >/dev/null
run_bazel build "${BAZEL_FLAGS[@]}" \
  //willow/benches:real_fl_bridge \
  //willow/benches:osa_vosa_shell_kahe_real_fl_bridge
popd >/dev/null

python3 "$ROOT/scripts/smoke_federated_bridges.py"

if python3 -c 'import numpy, torch, torchvision' >/dev/null 2>&1; then
  PYTHONPATH="$ROOT" python3 -m unittest discover \
    -s "$ROOT/federated_training/tests" -p 'test_*.py'
else
  echo "python_unit_tests=skipped_missing_torch_or_torchvision"
fi

echo "federated_code_validation=pass"
