#!/usr/bin/env bash
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
PROJECT="$(cd "${1:?pass the existing OSA_VOSA_Project_Final directory}" && pwd)"
SECURE="$(cd "$PROJECT/source/secure-aggregation-main" && pwd)"
if [[ -n "${BAZEL:-}" ]]; then
    BAZEL_BIN="$(command -v "$BAZEL" || true)"
elif [[ -f "$PROJECT/third_party/bazel-8.1.1-linux-x86_64" ]]; then
    BAZEL_BIN="$PROJECT/third_party/bazel-8.1.1-linux-x86_64"
    chmod +x "$BAZEL_BIN"
else
    BAZEL_BIN="$(command -v bazel || command -v bazelisk || true)"
fi
if [[ -z "$BAZEL_BIN" || ! -x "$BAZEL_BIN" ]]; then
    printf '%s\n' "Bazel not found. Expected $PROJECT/third_party/bazel-8.1.1-linux-x86_64 or an executable BAZEL/PATH entry." >&2
    exit 127
fi
printf 'Using Bazel: %s\n' "$BAZEL_BIN"
CACHE_ROOT="${BAZEL_CACHE_ROOT:-$ROOT/.runtime/bazel-cache}"
USER_ROOT="${BAZEL_USER_ROOT:-$CACHE_ROOT}"
REPOSITORY_CACHE="${BAZEL_REPOSITORY_CACHE:-$CACHE_ROOT/repository-cache}"
DISTDIR="${DISTDIR:-$PROJECT/third_party/bazel-distdir}"
mkdir -p "$USER_ROOT" "$REPOSITORY_CACHE"
# Rust links a PIE executable, so its C++ static dependencies must also use PIC.
BAZEL_FLAGS=(-c opt --force_pic "--jobs=${JOBS:-32}" "--repository_cache=$REPOSITORY_CACHE")
printf 'Native build mode: --force_pic\n'
# Reuse the original project's checksum-verified dependency archives.
if [[ -d "$DISTDIR" ]]; then
    BAZEL_FLAGS+=("--distdir=$DISTDIR")
    printf 'Dependency archives: %s\n' "$DISTDIR"
else
    printf 'Warning: dependency archive directory missing: %s; downloads may be required.\n' "$DISTDIR" >&2
fi
if [[ -f "$PROJECT/rust_mirror.cfg" ]]; then
    BAZEL_FLAGS+=("--experimental_downloader_config=$PROJECT/rust_mirror.cfg")
fi
printf 'Bazel output root: %s\nRepository cache: %s\n' "$USER_ROOT" "$REPOSITORY_CACHE"
DEST="$SECURE/tacita_ste_bridge_fig7_v2"
if [[ -d "$DEST" ]]; then
    if ! cmp -s "$ROOT/bridge/BUILD" "$DEST/BUILD" || ! cmp -s "$ROOT/bridge/kahe_stage.rs" "$DEST/kahe_stage.rs"; then
        BACKUP="$ROOT/backups/bridge_fig7_$(date -u +%Y%m%dT%H%M%S)_$$"
        mkdir -p "$BACKUP"
        cp -a "$DEST/." "$BACKUP/"
    fi
fi
mkdir -p "$DEST"
cp "$ROOT/bridge/BUILD" "$ROOT/bridge/kahe_stage.rs" "$DEST/"
cd "$SECURE"
"$BAZEL_BIN" "--output_user_root=$USER_ROOT" build "${BAZEL_FLAGS[@]}" //tacita_ste_bridge_fig7_v2:kahe_stage
mkdir -p "$ROOT/bin"
cp bazel-bin/tacita_ste_bridge_fig7_v2/kahe_stage "$ROOT/bin/kahe_stage_fig7_v2"
