#!/usr/bin/env bash
set -euo pipefail
source "$(cd "$(dirname "$0")" && pwd)/env.sh"
LOG="$PACKAGE_ROOT/logs/setup_$(date -u +%Y%m%dT%H%M%SZ).log"
exec > >(tee -a "$LOG") 2>&1
trap 'code=$?; echo "SETUP_FAILED exit=$code line=$LINENO log=$LOG"; exit "$code"' ERR
[[ "$(uname -sm)" == "Linux x86_64" ]] || { echo "Requires Linux x86_64"; exit 1; }
if [[ "${1:-}" == "--install-system" ]]; then
    if [[ $(id -u) == 0 ]]; then SUDO=(); else SUDO=(sudo); fi
    "${SUDO[@]}" apt-get update
    "${SUDO[@]}" apt-get install -y build-essential clang lld pkg-config libgmp-dev libssl-dev \
        flex bison m4 autoconf automake libtool python3-dev python3-venv python3-pip \
        curl ca-certificates git unzip zip tmux
fi
for tool in gcc g++ clang ld ld.lld make pkg-config flex bison curl tar unzip; do
    command -v "$tool" >/dev/null || { echo "Missing $tool; use setup.sh --install-system on Ubuntu/Debian"; exit 1; }
done
SOURCE_PY="${PYTHON_SOURCE:-python3}"
"$SOURCE_PY" -c 'import sys,sysconfig,pathlib; assert sys.version_info[:2] == (3,10), "Use Python 3.10.x for pinned Charm"; assert pathlib.Path(sysconfig.get_paths()["include"],"Python.h").is_file(), "Python.h missing"'
"$SOURCE_PY" "$PACKAGE_ROOT/scripts/suite.py" verify-package
if [[ ! -x "$PYTHON" ]]; then "$SOURCE_PY" -m venv "$RUNTIME_DIR/python"; fi
"$PYTHON" -m pip install --disable-pip-version-check -r "$PACKAGE_ROOT/requirements.txt"
if [[ ! -x "$CARGO_HOME/bin/rustup" ]]; then
    curl --fail --location --retry 3 --connect-timeout 30 --max-time 300 \
        https://sh.rustup.rs -o "$TMPDIR/rustup-init.sh"
    bash "$TMPDIR/rustup-init.sh" -y --no-modify-path --profile minimal --default-toolchain 1.87.0
fi
rustup toolchain install 1.87.0 --profile minimal
cargo +1.87.0 --version
rustc +1.87.0 --version
echo "SETUP_PASS log=$LOG"
