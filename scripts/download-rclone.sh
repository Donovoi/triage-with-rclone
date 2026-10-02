#!/usr/bin/env bash
# Download the pinned runtime; validate the archive before extracting one entry.
set -euo pipefail
SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"
source "$REPO_ROOT/rclone-version.env"
platform=windows-amd64
binary=rclone.exe
target="$REPO_ROOT/rclone-triage/assets/rclone.exe"
archive_hash="$RCLONE_WINDOWS_ZIP_SHA256"
if [[ "${1:-}" == --linux && $# == 2 ]]; then
    platform=linux-amd64
    binary=rclone
    target="$2"
    archive_hash="$RCLONE_LINUX_ZIP_SHA256"
elif [[ $# != 0 ]]; then
    echo "Usage: $0 [--linux OUTPUT_PATH]" >&2
    exit 2
fi
if [[ "$platform" == windows-amd64 && -f "$target" ]]; then
    if [[ "$(sha256sum "$target" | cut -d ' ' -f 1)" == "$RCLONE_EXE_SHA256" ]]; then
        echo "rclone $RCLONE_VERSION already verified."
        exit 0
    fi
fi
scratch=$(mktemp -d)
trap 'rm -rf -- "$scratch"' EXIT
archive="rclone-v${RCLONE_VERSION}-${platform}"
curl --proto '=https' --tlsv1.2 -fSL --retry 3 \
    "https://github.com/rclone/rclone/releases/download/v${RCLONE_VERSION}/${archive}.zip" \
    -o "$scratch/runtime.zip"
printf '%s  %s\n' "$archive_hash" "$scratch/runtime.zip" | sha256sum --check --status
unzip -p "$scratch/runtime.zip" "$archive/$binary" > "$scratch/$binary"
if [[ "$platform" == windows-amd64 ]]; then
    printf '%s  %s\n' "$RCLONE_EXE_SHA256" "$scratch/$binary" | sha256sum --check --status
fi
mkdir -p -- "$(dirname "$target")"
install -m 700 -- "$scratch/$binary" "$target"
echo "Installed verified rclone $RCLONE_VERSION ($platform)."
