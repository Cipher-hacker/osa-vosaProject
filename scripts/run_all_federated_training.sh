#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"

bash "$ROOT/scripts/run_federated_training.sh" \
  --config "$ROOT/federated_training/configs/mnist_lenet5.json" \
  --protocol all \
  --data-root "$ROOT/datasets" \
  --output-root "$ROOT/results/federated_training" \
  --device "${FL_DEVICE:-auto}" \
  --download \
  "$@"
