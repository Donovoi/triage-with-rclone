# Native Windows bootstrap. Never replace the existing asset until verification succeeds.
$ErrorActionPreference = 'Stop'
$repo = Split-Path -Parent $PSScriptRoot
$runtime = @{}
Get-Content -LiteralPath (Join-Path $repo 'rclone-version.env') | ForEach-Object {
    if ($_ -match '^(RCLONE_[A-Z0-9_]+)=(.+)$') { $runtime[$Matches[1]] = $Matches[2] }
}
$target = Join-Path $repo 'rclone-triage/assets/rclone.exe'
if ((Test-Path -LiteralPath $target) -and
    (Get-FileHash -LiteralPath $target -Algorithm SHA256).Hash -eq $runtime.RCLONE_EXE_SHA256) {
    Write-Output "rclone $($runtime.RCLONE_VERSION) already verified."
    exit 0
}
$tempRoot = [IO.Path]::GetFullPath([IO.Path]::GetTempPath())
$scratch = Join-Path $tempRoot ('triage-runtime-' + [Guid]::NewGuid().ToString('N'))
New-Item -ItemType Directory -Path $scratch | Out-Null
try {
    $name = "rclone-v$($runtime.RCLONE_VERSION)-windows-amd64"
    $zipPath = Join-Path $scratch 'runtime.zip'
    Invoke-WebRequest -Uri "https://github.com/rclone/rclone/releases/download/v$($runtime.RCLONE_VERSION)/$name.zip" -OutFile $zipPath
    if ((Get-FileHash -LiteralPath $zipPath -Algorithm SHA256).Hash -ne $runtime.RCLONE_WINDOWS_ZIP_SHA256) {
        throw 'Runtime archive SHA256 mismatch'
    }
    Add-Type -AssemblyName System.IO.Compression.FileSystem
    $zip = [IO.Compression.ZipFile]::OpenRead($zipPath)
    $binary = Join-Path $scratch 'rclone.exe'
    try {
        $entry = $zip.GetEntry("$name/rclone.exe")
        if ($null -eq $entry) { throw 'Runtime archive missing expected executable' }
        [IO.Compression.ZipFileExtensions]::ExtractToFile($entry, $binary)
    } finally { $zip.Dispose() }
    if ((Get-FileHash -LiteralPath $binary -Algorithm SHA256).Hash -ne $runtime.RCLONE_EXE_SHA256) {
        throw 'Runtime executable SHA256 mismatch'
    }
    New-Item -ItemType Directory -Force -Path (Split-Path -Parent $target) | Out-Null
    Copy-Item -LiteralPath $binary -Destination $target
    Write-Output "Installed verified rclone $($runtime.RCLONE_VERSION)."
} finally {
    $resolved = [IO.Path]::GetFullPath($scratch)
    if ($resolved.StartsWith($tempRoot, [StringComparison]::OrdinalIgnoreCase) -and
        (Split-Path -Leaf $resolved) -match '^triage-runtime-[0-9a-f]{32}$') {
        Remove-Item -LiteralPath $resolved -Recurse -Force
    } else { throw 'Refusing cleanup outside the runtime temporary directory' }
}
