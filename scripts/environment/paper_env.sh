#!/usr/bin/env bash
# Source only from the package scripts; all paths remain on the package disk.
PACKAGE_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
export PACKAGE_ROOT
export RUNTIME_DIR="$PACKAGE_ROOT/.runtime"
export TMPDIR="$RUNTIME_DIR/tmp"
export PIP_CACHE_DIR="$RUNTIME_DIR/pip-cache"
export CARGO_HOME="$RUNTIME_DIR/cargo"
export RUSTUP_HOME="$RUNTIME_DIR/rustup"
export RUSTUP_TOOLCHAIN=1.87.0
export CARGO_TARGET_DIR="$PACKAGE_ROOT/tacita/target"
export BAZEL_CACHE_ROOT="$RUNTIME_DIR/bazel-cache"
export BAZEL_USER_ROOT="$BAZEL_CACHE_ROOT/user"
export BAZEL_REPOSITORY_CACHE="$BAZEL_CACHE_ROOT/repository"
export DISTDIR="$PACKAGE_ROOT/project/third_party/bazel-distdir"
export RESULTS_DIR="$PACKAGE_ROOT/runs"
export PATH="$CARGO_HOME/bin:$PATH"
export PYTHONUTF8=1
export PYTHONUNBUFFERED=1
export OMP_NUM_THREADS=1 MKL_NUM_THREADS=1 OPENBLAS_NUM_THREADS=1
unset PYTHONHOME
JOBS="${JOBS:-$(nproc)}"
if (( JOBS > 32 )); then JOBS=32; fi
export JOBS
mkdir -p "$TMPDIR" "$PIP_CACHE_DIR" "$BAZEL_USER_ROOT" "$BAZEL_REPOSITORY_CACHE" "$RESULTS_DIR" "$PACKAGE_ROOT/logs"
PYTHON="$RUNTIME_DIR/python/bin/python"
export PYTHON
