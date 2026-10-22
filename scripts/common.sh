#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
RUNTIME_DIR="${RUNTIME_DIR:-$ROOT/.runtime}"
RESULTS_DIR="${RESULTS_DIR:-$ROOT/results/runs}"
BAZEL="${BAZEL:-$ROOT/third_party/bazel-8.1.1-linux-x86_64}"
DISTDIR="${DISTDIR:-$ROOT/third_party/bazel-distdir}"
BAZEL_CACHE_ROOT="${BAZEL_CACHE_ROOT:-${XDG_CACHE_HOME:-$HOME/.cache}/osa-vosa-rss31}"
BAZEL_USER_ROOT="${BAZEL_USER_ROOT:-$BAZEL_CACHE_ROOT/bazel-user-root}"
BAZEL_REPOSITORY_CACHE="${BAZEL_REPOSITORY_CACHE:-$BAZEL_CACHE_ROOT/repository-cache}"

chmod +x "$BAZEL"

mkdir -p "$RUNTIME_DIR" "$RESULTS_DIR" "$BAZEL_USER_ROOT" "$BAZEL_REPOSITORY_CACHE"

CFG="$ROOT/config/rust_mirror.cfg"
if [[ ! -f "$CFG" && -f "$ROOT/rust_mirror.cfg" ]]; then
  CFG="$ROOT/rust_mirror.cfg"
fi

BAZEL_FLAGS=(
  -c opt
  "--distdir=$DISTDIR"
  "--repository_cache=$BAZEL_REPOSITORY_CACHE"
  "--experimental_downloader_config=$CFG"
  --action_env=CC=gcc
  --action_env=CXX=g++
  --repo_env=CC=gcc
  --repo_env=CXX=g++
)

run_bazel() {
  "$BAZEL" "--output_user_root=$BAZEL_USER_ROOT" "$@"
}

timestamp() {
  date -u +%Y%m%dT%H%M%SZ
}

require_protocol_line() {
  local log_path="$1"
  shift
  local marker
  for marker in "$@"; do
    if ! grep -Fq "$marker" "$log_path"; then
      echo "ERROR: $log_path is missing required marker: $marker" >&2
      return 1
    fi
  done
}
