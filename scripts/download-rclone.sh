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
binary_hash="$RCLONE_EXE_SHA256"
if [[ "${1:-}" == --linux && $# == 2 ]]; then
    platform=linux-amd64
    binary=rclone
    target="$2"
    archive_hash="$RCLONE_LINUX_ZIP_SHA256"
    binary_hash="$RCLONE_LINUX_EXE_SHA256"
elif [[ "${1:-}" == --architecture && $# == 2 ]]; then
    case "$2" in
        x64) ;;
        x86)
            platform=windows-386
            archive_hash="$RCLONE_WINDOWS_X86_ZIP_SHA256"
            binary_hash="$RCLONE_WINDOWS_X86_EXE_SHA256" ;;
        arm64)
            platform=windows-arm64
            archive_hash="$RCLONE_WINDOWS_ARM64_ZIP_SHA256"
            binary_hash="$RCLONE_WINDOWS_ARM64_EXE_SHA256" ;;
        *) echo "Unsupported Windows architecture" >&2; exit 2 ;;
    esac
elif [[ $# != 0 ]]; then
    echo "Usage: $0 [--architecture x64|x86|arm64 | --linux OUTPUT_PATH]" >&2
    exit 2
fi
if [[ ! "$archive_hash" =~ ^[a-f0-9]{64}$ || ! "$binary_hash" =~ ^[a-f0-9]{64}$ ]]; then
    echo "Runtime architecture pins are missing or invalid" >&2
    exit 1
fi
if [[ "$platform" == windows-* && -f "$target" ]]; then
    if [[ "$(sha256sum "$target" | cut -d ' ' -f 1)" == "$binary_hash" ]]; then
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
printf '%s  %s\n' "$binary_hash" "$scratch/$binary" | sha256sum --check --status
mkdir -p -- "$(dirname "$target")"
install -m 700 -- "$scratch/$binary" "$target"
echo "Installed verified rclone $RCLONE_VERSION ($platform)."
