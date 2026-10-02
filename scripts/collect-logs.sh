#!/usr/bin/env bash
# Build a private, conservatively redacted diagnostic archive. Nothing is sent.
# Usage: ./scripts/collect-logs.sh [CASE_DIR]
set -euo pipefail
umask 077
command -v python3 >/dev/null || { printf 'python3 is required for structured redaction.\n' >&2; exit 1; }

# Values are redacted before entering the staging area. Unknown settings are private.
redact_file() {
    python3 - "$1" <<'PY'
import json, pathlib, re, sys
safe = {'type', 'scope', 'region', 'provider', 'version', 'os', 'arch', 'chunk_size', 'upload_cutoff', 'drive_type', 'team_drive'}
redacted = '<REDACTED>'
def clean(value):
    if isinstance(value, dict):
        return {k: clean(v) if isinstance(v, (dict, list)) else v if k.lower() in safe else redacted for k, v in value.items()}
    if isinstance(value, list):
        return [clean(v) if isinstance(v, (dict, list)) else redacted for v in value]
    return redacted
text = pathlib.Path(sys.argv[1]).read_text(encoding='utf-8', errors='replace')
try:
    print(json.dumps(clean(json.loads(text)), ensure_ascii=False, indent=2))
except (ValueError, TypeError):
    for line in text.splitlines():
        if line.strip().startswith('[') and line.strip().endswith(']'):
            print(line)
        elif '=' in line:
            key, value = line.split('=', 1)
            print(key.rstrip() + '= ' + (value.strip() if key.strip().lower() in safe else redacted))
        elif re.search(r'token|secret|password|credential|authorization|bearer |cookie|private_key|access_key', line, re.I):
            print(redacted)
        elif re.match(r'\s*["\x27]?[^:]+["\x27]?\s*:', line):
            # Invalid/partial JSON and unfamiliar colon-delimited settings.
            print(redacted)
        else:
            print(line)
PY
}

CASE_DIR="${1:-}"
if [[ -z "$CASE_DIR" ]]; then
    CASE_DIR="$(find . -maxdepth 2 -type d -name 'triage-*' -printf '%T@ %p\n' 2>/dev/null | sort -rn | head -1 | cut -d' ' -f2- || true)"
fi
STAGING="$(mktemp -d "${TMPDIR:-/tmp}/rclone-triage-logs-XXXXXXXX")"
trap 'rm -rf -- "$STAGING"' EXIT
{
    printf 'Date: '; date -u '+%Y-%m-%dT%H:%M:%SZ'
    printf 'OS: '; uname -srm
    printf '\nRclone environment (presence only):\n'
    while IFS= read -r name; do
        case "$name" in RCLONE_*) printf '%s=<REDACTED>\n' "$name" ;; esac
    done < <(compgen -e | sort)
} > "$STAGING/system-info.txt"

if [[ -n "$CASE_DIR" && -d "$CASE_DIR" ]]; then
    for section in logs config; do
        mkdir -p "$STAGING/$section"
        if [[ -d "$CASE_DIR/$section" ]]; then
            while IFS= read -r -d '' file; do
                # Symlinks and unknown binary files are not included.
                redact_file "$file" > "$STAGING/$section/$(basename "$file")"
            done < <(find "$CASE_DIR/$section" -maxdepth 1 -type f -print0)
        fi
    done
    if [[ -f "$CASE_DIR/forensic_report.txt" && ! -L "$CASE_DIR/forensic_report.txt" ]]; then
        redact_file "$CASE_DIR/forensic_report.txt" > "$STAGING/forensic_report.txt"
    fi
    # Evidence filenames and file contents are deliberately not included by default.
    find "$CASE_DIR" -type f -printf '.\n' | wc -l > "$STAGING/case-file-count.txt"
fi
cat > "$STAGING/README.md" <<'README'
# rclone-triage diagnostic bundle
Environment values and unknown configuration fields have been omitted or redacted.
Logs and reports may still contain private case details. Review this archive before
sharing it. Redacted log copies are diagnostic extracts, not verifiable originals.
The original evidence files remain untouched. No network transfer was performed.
README
ARCHIVE="$(mktemp "${TMPDIR:-/tmp}/rclone-triage-logs-XXXXXXXX.tar.gz")"
tar -czf "$ARCHIVE" -C "$STAGING" .
printf 'Private diagnostic archive: %s\nReview its contents before sharing.\n' "$ARCHIVE"
