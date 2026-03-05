#!/usr/bin/env bash
# Download rclone.exe for embedding into the rclone-triage binary.
# Uses the version and SHA256 from src/embedded/mod.rs.
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"
ASSETS_DIR="$REPO_ROOT/rclone-triage/assets"
TARGET="$ASSETS_DIR/rclone.exe"

# Version and hash from src/embedded/mod.rs
RCLONE_VERSION="1.68.2"
EXPECTED_SHA256="dcbb5d188358df520b08a584df42a8e76161b30a90a62fefdd0001174d002122"

# Skip if already present and valid
if [[ -f "$TARGET" ]]; then
    ACTUAL_SHA256=$(sha256sum "$TARGET" | awk '{print $1}')
    if [[ "$ACTUAL_SHA256" == "$EXPECTED_SHA256" ]]; then
        echo "rclone.exe v${RCLONE_VERSION} already present and verified."
        exit 0
    fi
    echo "Existing rclone.exe has wrong hash, re-downloading..."
    rm -f "$TARGET"
fi

URL="https://github.com/rclone/rclone/releases/download/v${RCLONE_VERSION}/rclone-v${RCLONE_VERSION}-windows-amd64.zip"
TMPDIR=$(mktemp -d)
trap 'rm -rf "$TMPDIR"' EXIT

echo "Downloading rclone v${RCLONE_VERSION}..."
curl -fSL --retry 3 -o "$TMPDIR/rclone.zip" "$URL"

echo "Extracting..."
unzip -q -o "$TMPDIR/rclone.zip" -d "$TMPDIR"

mkdir -p "$ASSETS_DIR"
cp "$TMPDIR/rclone-v${RCLONE_VERSION}-windows-amd64/rclone.exe" "$TARGET"

echo "Verifying SHA256..."
ACTUAL_SHA256=$(sha256sum "$TARGET" | awk '{print $1}')
if [[ "$ACTUAL_SHA256" != "$EXPECTED_SHA256" ]]; then
    echo "ERROR: SHA256 mismatch!" >&2
    echo "  Expected: $EXPECTED_SHA256" >&2
    echo "  Got:      $ACTUAL_SHA256" >&2
    rm -f "$TARGET"
    exit 1
fi

echo "rclone.exe v${RCLONE_VERSION} downloaded and verified."
