param(
    [switch]$Debug
)

$ErrorActionPreference = "Stop"

$repoRoot = Split-Path -Parent $PSScriptRoot
$crateDir = Join-Path $repoRoot "rclone-triage"
& (Join-Path $PSScriptRoot 'download-rclone.ps1')
$previousSchemaBinary = [Environment]::GetEnvironmentVariable('RCLONE_PROVIDER_SCHEMA_BINARY', 'Process')
Push-Location $crateDir
try {
    python -B -m unittest discover -s (Join-Path $PSScriptRoot 'tests') -p 'test_*.py'
    if ($LASTEXITCODE -ne 0) { throw 'Python maintenance and provider evidence tests failed' }
    cargo fmt --all -- --check
    if ($LASTEXITCODE -ne 0) { throw 'Formatting failed' }
    cargo clippy --locked --all-targets --all-features -- -D warnings
    if ($LASTEXITCODE -ne 0) { throw 'Clippy failed' }
    if ($Debug) { cargo test --locked -- --test-threads=1 }
    else { cargo test --locked --release -- --test-threads=1 }
    if ($LASTEXITCODE -ne 0) { throw 'Tests failed' }
    $env:RCLONE_PROVIDER_SCHEMA_BINARY = Join-Path $crateDir 'assets/rclone.exe'
    [string[]]$profileArgs = if ($Debug) { @() } else { @('--release') }
    cargo test --locked @profileArgs --test provider_matrix pinned_rclone_catalog_matches_provider_contracts -- --ignored --exact --test-threads=1
    if ($LASTEXITCODE -ne 0) { throw 'Pinned provider catalog failed' }
} finally {
    [Environment]::SetEnvironmentVariable('RCLONE_PROVIDER_SCHEMA_BINARY', $previousSchemaBinary, 'Process')
    Pop-Location
}
