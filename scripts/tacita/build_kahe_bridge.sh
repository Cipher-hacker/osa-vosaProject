#!/usr/bin/env bash
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
PROJECT="${1:?pass the existing OSA_VOSA_Project_Final directory}"
SECURE="$(cd "$PROJECT/source/secure-aggregation-main" && pwd)"
DEST="$SECURE/tacita_ste_bridge"
if [[ -e "$DEST" ]]; then
    cmp "$ROOT/bridge/BUILD" "$DEST/BUILD"
    cmp "$ROOT/bridge/kahe_stage.rs" "$DEST/kahe_stage.rs"
else
    mkdir "$DEST"
    cp "$ROOT/bridge/BUILD" "$ROOT/bridge/kahe_stage.rs" "$DEST/"
fi
cd "$SECURE"
bazel --output_user_root="${BAZEL_CACHE_ROOT:-$ROOT/.runtime/bazel-cache}" build -c opt --jobs="${JOBS:-32}" //tacita_ste_bridge:kahe_stage
mkdir -p "$ROOT/bin"
cp bazel-bin/tacita_ste_bridge/kahe_stage "$ROOT/bin/kahe_stage"
