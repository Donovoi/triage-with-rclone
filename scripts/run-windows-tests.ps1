param(
    [switch]$Debug
)

$ErrorActionPreference = "Stop"

$repoRoot = Split-Path -Parent $PSScriptRoot
$crateDir = Join-Path $repoRoot "rclone-triage"

Set-Location $crateDir

if ($Debug) {
    cargo test -- --test-threads=1
} else {
    cargo test --release -- --test-threads=1
}
