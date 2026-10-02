param(
    [switch]$Debug
)

$ErrorActionPreference = "Stop"

$repoRoot = Split-Path -Parent $PSScriptRoot
$crateDir = Join-Path $repoRoot "rclone-triage"
& (Join-Path $PSScriptRoot 'download-rclone.ps1')
Push-Location $crateDir
try {
    cargo fmt --all -- --check
    if ($LASTEXITCODE -ne 0) { throw 'Formatting failed' }
    cargo clippy --locked --all-targets --all-features -- -D warnings
    if ($LASTEXITCODE -ne 0) { throw 'Clippy failed' }
    if ($Debug) { cargo test --locked -- --test-threads=1 }
    else { cargo test --locked --release -- --test-threads=1 }
    if ($LASTEXITCODE -ne 0) { throw 'Tests failed' }
} finally {
    Pop-Location
}
