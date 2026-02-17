#!/usr/bin/env bash
# collect-logs.sh — Gather rclone-triage debug logs for LLM troubleshooting.
#
# Usage:
#   ./scripts/collect-logs.sh [CASE_DIR]
#
# If CASE_DIR is not provided, the script searches for the most recent
# triage-* directory under the current working directory.
#
# Output: a timestamped .tar.gz bundle with all relevant logs, config
# (secrets redacted), and system info.  If Tailscale is available the
# bundle is optionally shared via `tailscale file cp`.

set -euo pipefail

# ── Helpers ──────────────────────────────────────────────────────────
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
CYAN='\033[0;36m'
NC='\033[0m' # No Colour

info()  { printf "${GREEN}[+]${NC} %s\n" "$*"; }
warn()  { printf "${YELLOW}[!]${NC} %s\n" "$*"; }
err()   { printf "${RED}[-]${NC} %s\n" "$*" >&2; }
header(){ printf "\n${CYAN}=== %s ===${NC}\n" "$*"; }

# ── Locate case directory ────────────────────────────────────────────
CASE_DIR="${1:-}"

if [[ -z "$CASE_DIR" ]]; then
    # Auto-detect: most recent triage-* directory
    CASE_DIR="$(find . -maxdepth 2 -type d -name 'triage-*' -printf '%T@ %p\n' 2>/dev/null \
        | sort -rn | head -1 | cut -d' ' -f2- || true)"
    if [[ -z "$CASE_DIR" ]]; then
        warn "No triage-* directory found. Collecting system info only."
    fi
fi

# ── Prepare staging area ────────────────────────────────────────────
TIMESTAMP="$(date +%Y%m%d-%H%M%S)"
STAGING="/tmp/rclone-triage-logs-${TIMESTAMP}"
mkdir -p "$STAGING"

info "Staging directory: $STAGING"

# ── 1. System info ──────────────────────────────────────────────────
header "System Information"
{
    echo "=== Date ==="
    date -u '+%Y-%m-%dT%H:%M:%SZ'
    echo ""

    echo "=== OS ==="
    uname -a
    if [[ -f /etc/os-release ]]; then
        cat /etc/os-release
    fi
    echo ""

    echo "=== Hostname ==="
    hostname 2>/dev/null || echo "(unknown)"
    echo ""

    echo "=== User ==="
    whoami 2>/dev/null || echo "(unknown)"
    id 2>/dev/null || true
    echo ""

    echo "=== Disk ==="
    df -h 2>/dev/null | head -20 || true
    echo ""

    echo "=== Memory ==="
    free -h 2>/dev/null || true
    echo ""

    echo "=== Network Interfaces ==="
    ip -brief addr 2>/dev/null || ifconfig 2>/dev/null || true
    echo ""

    echo "=== DNS ==="
    cat /etc/resolv.conf 2>/dev/null || true
    echo ""

    echo "=== Environment (filtered) ==="
    env | grep -iE '^(RCLONE_|PATH=|HOME=|USER=|SHELL=|LANG=|LC_|XDG_|TERM=)' | sort || true
    echo ""
} > "$STAGING/system-info.txt" 2>&1
info "Collected system info"

# ── 2. rclone version & diagnostics ────────────────────────────────
header "rclone Info"
{
    echo "=== rclone version ==="
    if command -v rclone &>/dev/null; then
        rclone version 2>&1 || echo "(rclone version failed)"
    else
        echo "(rclone not in PATH)"
    fi
    echo ""

    # Check for extracted rclone binary
    EXTRACTED="$(find /tmp -maxdepth 3 -name 'rclone' -o -name 'rclone.exe' 2>/dev/null | head -5 || true)"
    if [[ -n "$EXTRACTED" ]]; then
        echo "=== Extracted rclone binaries ==="
        echo "$EXTRACTED"
        for bin in $EXTRACTED; do
            echo "--- $bin ---"
            "$bin" version 2>&1 || echo "(failed)"
        done
    fi
    echo ""

    echo "=== rclone config file ==="
    RCLONE_CFG="${RCLONE_CONFIG:-}"
    if [[ -z "$RCLONE_CFG" ]]; then
        RCLONE_CFG="$(rclone config file 2>/dev/null | tail -1 || true)"
    fi
    if [[ -n "$RCLONE_CFG" && -f "$RCLONE_CFG" ]]; then
        echo "Path: $RCLONE_CFG"
        echo "---"
        # Redact tokens and secrets
        sed -E \
            -e 's/(token\s*=\s*).*/\1<REDACTED>/' \
            -e 's/(client_secret\s*=\s*).*/\1<REDACTED>/' \
            -e 's/(pass\s*=\s*).*/\1<REDACTED>/' \
            -e 's/(password\s*=\s*).*/\1<REDACTED>/' \
            -e 's/(access_token\s*=\s*).*/\1<REDACTED>/' \
            -e 's/(refresh_token\s*=\s*).*/\1<REDACTED>/' \
            "$RCLONE_CFG" 2>/dev/null || echo "(failed to read config)"
    else
        echo "Not found"
    fi
    echo ""

    echo "=== rclone remotes ==="
    rclone listremotes 2>&1 || echo "(not available)"
    echo ""
} > "$STAGING/rclone-info.txt" 2>&1
info "Collected rclone info"

# ── 3. rclone-triage binary info ────────────────────────────────────
header "rclone-triage Info"
{
    echo "=== rclone-triage version ==="
    TRIAGE_BIN="$(find . -maxdepth 3 -name 'rclone-triage' -type f 2>/dev/null | head -1 || true)"
    if [[ -n "$TRIAGE_BIN" ]]; then
        "$TRIAGE_BIN" --version 2>&1 || echo "(failed)"
    elif command -v rclone-triage &>/dev/null; then
        rclone-triage --version 2>&1 || echo "(failed)"
    else
        echo "(binary not found)"
    fi
    echo ""

    echo "=== Cargo.toml version ==="
    TOML="$(find . -maxdepth 3 -name 'Cargo.toml' -path '*/rclone-triage/*' 2>/dev/null | head -1 || true)"
    if [[ -n "$TOML" ]]; then
        grep -E '^(version|name)' "$TOML" || true
    fi
    echo ""
} > "$STAGING/triage-info.txt" 2>&1
info "Collected rclone-triage info"

# ── 4. Case directory logs ──────────────────────────────────────────
if [[ -n "$CASE_DIR" && -d "$CASE_DIR" ]]; then
    header "Case Directory: $CASE_DIR"

    # Tree listing
    if command -v tree &>/dev/null; then
        tree -a --du -h "$CASE_DIR" > "$STAGING/case-tree.txt" 2>&1 || true
    else
        find "$CASE_DIR" -type f -printf '%s\t%p\n' > "$STAGING/case-tree.txt" 2>&1 || true
    fi
    info "Collected case directory tree"

    # Copy log files
    mkdir -p "$STAGING/logs"
    if [[ -d "$CASE_DIR/logs" ]]; then
        cp -a "$CASE_DIR/logs/"* "$STAGING/logs/" 2>/dev/null || true
        info "Copied forensic logs"
    fi

    # Copy listing CSVs (headers + first 50 lines only to keep size down)
    mkdir -p "$STAGING/listings"
    if [[ -d "$CASE_DIR/listings" ]]; then
        for csv in "$CASE_DIR/listings/"*.csv; do
            [[ -f "$csv" ]] || continue
            head -51 "$csv" > "$STAGING/listings/$(basename "$csv")" 2>/dev/null || true
        done
        info "Copied listing samples"
    fi

    # Copy forensic report
    if [[ -f "$CASE_DIR/forensic_report.txt" ]]; then
        cp "$CASE_DIR/forensic_report.txt" "$STAGING/" 2>/dev/null || true
        info "Copied forensic report"
    fi

    # Copy config (redact secrets)
    mkdir -p "$STAGING/config"
    if [[ -d "$CASE_DIR/config" ]]; then
        for conf in "$CASE_DIR/config/"*; do
            [[ -f "$conf" ]] || continue
            sed -E \
                -e 's/(token\s*=\s*).*/\1<REDACTED>/' \
                -e 's/(client_secret\s*=\s*).*/\1<REDACTED>/' \
                -e 's/(pass\s*=\s*).*/\1<REDACTED>/' \
                -e 's/(password\s*=\s*).*/\1<REDACTED>/' \
                -e 's/(access_token\s*=\s*).*/\1<REDACTED>/' \
                -e 's/(refresh_token\s*=\s*).*/\1<REDACTED>/' \
                "$conf" > "$STAGING/config/$(basename "$conf")" 2>/dev/null || true
        done
        info "Copied config (secrets redacted)"
    fi
else
    warn "No case directory to collect from"
fi

# ── 5. Cargo build output (flycheck / recent build errors) ──────────
header "Build Diagnostics"
{
    FLYCHECK_STDERR="$(find . -path '*/target/flycheck0/stderr' 2>/dev/null | head -1 || true)"
    if [[ -n "$FLYCHECK_STDERR" && -s "$FLYCHECK_STDERR" ]]; then
        echo "=== flycheck stderr ==="
        cat "$FLYCHECK_STDERR"
    fi

    echo "=== Recent build errors ==="
    # Try to get any recent cargo build output
    cd "$(find . -maxdepth 2 -name 'Cargo.toml' -path '*/rclone-triage/*' -printf '%h\n' 2>/dev/null | head -1 || echo .)" 2>/dev/null || true
    cargo check --message-format=short 2>&1 | grep -E '(error|warning)' | head -50 || echo "(no errors)"
} > "$STAGING/build-diagnostics.txt" 2>&1
info "Collected build diagnostics"

# ── 6. Tailscale status ─────────────────────────────────────────────
header "Tailscale"
HAS_TAILSCALE=false
{
    echo "=== tailscale status ==="
    if command -v tailscale &>/dev/null; then
        tailscale status 2>&1 || echo "(not connected)"
        HAS_TAILSCALE=true
    else
        echo "(tailscale not installed)"
    fi
} > "$STAGING/tailscale-status.txt" 2>&1

# ── 7. Create a summary for LLM ────────────────────────────────────
header "Creating LLM summary"
{
    echo "# rclone-triage Debug Log Bundle"
    echo ""
    echo "Generated: $(date -u '+%Y-%m-%dT%H:%M:%SZ')"
    echo ""
    echo "## Files in this bundle"
    echo ""
    echo "- system-info.txt     — OS, disk, memory, network, env vars"
    echo "- rclone-info.txt     — rclone version, config (secrets redacted), remotes"
    echo "- triage-info.txt     — rclone-triage binary version"
    echo "- build-diagnostics.txt — Recent compile errors/warnings"
    echo "- tailscale-status.txt — Tailscale network status"
    if [[ -n "$CASE_DIR" && -d "$CASE_DIR" ]]; then
        echo "- case-tree.txt       — Case directory listing"
        echo "- forensic_report.txt — Forensic session report"
        echo "- logs/               — Hash-chained forensic log files"
        echo "- listings/           — First 50 lines of listing CSVs"
        echo "- config/             — rclone config (secrets redacted)"
    fi
    echo ""
    echo "## How to use this bundle"
    echo ""
    echo "Share the .tar.gz file with an LLM (e.g. paste the contents of"
    echo "the text files) for debugging. Secrets have been redacted."
    echo "Look for errors in logs/ and build-diagnostics.txt first."
} > "$STAGING/README.md"
info "Created LLM summary"

# ── 8. Compress ─────────────────────────────────────────────────────
header "Packaging"
ARCHIVE="/tmp/rclone-triage-logs-${TIMESTAMP}.tar.gz"
tar -czf "$ARCHIVE" -C /tmp "rclone-triage-logs-${TIMESTAMP}"
SIZE="$(du -h "$ARCHIVE" | cut -f1)"
info "Created archive: $ARCHIVE ($SIZE)"

# ── 9. Share via Tailscale ──────────────────────────────────────────
if command -v tailscale &>/dev/null; then
    header "Tailscale File Sharing"

    # Get list of peers
    PEERS="$(tailscale status --json 2>/dev/null | python3 -c '
import sys, json
data = json.load(sys.stdin)
peers = data.get("Peer", {})
self_node = data.get("Self", {}).get("HostName", "")
for key, peer in peers.items():
    if peer.get("Online", False):
        name = peer.get("HostName", peer.get("DNSName", "unknown"))
        ip = peer.get("TailscaleIPs", [""])[0]
        print(f"  {name} ({ip})")
' 2>/dev/null || true)"

    if [[ -n "$PEERS" ]]; then
        echo ""
        info "Online Tailscale peers:"
        echo "$PEERS"
        echo ""
        read -rp "$(printf "${CYAN}Share logs to a peer? Enter hostname (or press Enter to skip): ${NC}")" TARGET_PEER
        if [[ -n "$TARGET_PEER" ]]; then
            info "Sending $ARCHIVE to ${TARGET_PEER}..."
            if tailscale file cp "$ARCHIVE" "${TARGET_PEER}:" 2>&1; then
                info "Sent successfully! Peer should accept with: tailscale file get ."
            else
                err "Failed to send. You can manually share:"
                echo "  tailscale file cp $ARCHIVE ${TARGET_PEER}:"
            fi
        else
            info "Skipping Tailscale share."
        fi
    else
        warn "No online Tailscale peers found."
    fi
else
    warn "Tailscale not installed — skipping file share."
fi

echo ""
header "Done"
info "Log bundle: $ARCHIVE"
info "Staging dir: $STAGING"
echo ""
echo "To share manually:"
echo "  tailscale file cp $ARCHIVE <peer>:"
echo "  scp $ARCHIVE user@host:/path/"
echo ""
echo "To paste into an LLM, run:"
echo "  for f in $STAGING/*.txt $STAGING/logs/* $STAGING/README.md; do"
echo "    echo \"--- \$(basename \$f) ---\"; cat \"\$f\"; echo; done"
