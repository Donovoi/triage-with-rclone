#requires -Version 5.1
<#!
Run only in an isolated, disposable Hyper-V Windows guest. This script does not
install software, configure networking, use accounts or inspect browser profiles.
!#>
[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)][string]$BinaryPath,
    [Parameter(Mandatory = $true)][string]$ExpectedComputerName,
    [Parameter(Mandatory = $true)][switch]$IsolatedGuest,
    [string]$OutputRoot = 'C:\TriageAcceptance',
    [Parameter(Mandatory = $true)][ValidatePattern('^[a-fA-F0-9]{64}$')]
    [string]$ExpectedSha256,
    [ValidateRange(10, 600)][int]$CommandTimeoutSeconds = 90
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
$script:Utf8 = New-Object System.Text.UTF8Encoding($false)
$script:Checks = New-Object 'System.Collections.Generic.List[object]'
$script:Commands = New-Object 'System.Collections.Generic.List[object]'
$script:RunRoot = $null
$script:ResolvedBinary = $null
$script:Started = [DateTime]::UtcNow
$script:Guest = $null
$script:ActualSha256 = $null
$script:CommandNumber = 0

function Assert-Condition([bool]$Condition, [string]$Message) {
    if (-not $Condition) { throw $Message }
}

function Write-Utf8([string]$Path, [string]$Content) {
    [IO.File]::WriteAllText($Path, $Content, $script:Utf8)
}

function Get-Sha256([string]$Path) {
    return (Get-FileHash -LiteralPath $Path -Algorithm SHA256).Hash.ToLowerInvariant()
}

function Test-Inside([string]$Path, [string]$Root) {
    $resolved = [IO.Path]::GetFullPath($Path)
    $prefix = [IO.Path]::GetFullPath($Root).TrimEnd('\') + '\'
    return $resolved.StartsWith($prefix, [StringComparison]::OrdinalIgnoreCase)
}

function Assert-NoReparse([string]$Path) {
    $current = [IO.Path]::GetFullPath($Path)
    while ($current) {
        if (Test-Path -LiteralPath $current) {
            $item = Get-Item -LiteralPath $current -Force
            Assert-Condition (($item.Attributes -band [IO.FileAttributes]::ReparsePoint) -eq 0) "Reparse point refused: $current"
        }
        $parent = [IO.Directory]::GetParent($current)
        if ($null -eq $parent) { break }
        $current = $parent.FullName
    }
}

# ProcessStartInfo.Arguments uses Windows CRT argument escaping on PowerShell 5.1.
# Each argument is quoted separately; it is never evaluated as shell code.
function ConvertTo-NativeArgument([AllowEmptyString()][string]$Value) {
    $builder = New-Object Text.StringBuilder
    [void]$builder.Append('"')
    $slashes = 0
    foreach ($character in $Value.ToCharArray()) {
        if ($character -eq '\') { $slashes++; continue }
        if ($character -eq '"') {
            [void]$builder.Append(('\' * (2 * $slashes + 1)))
            [void]$builder.Append('"')
        } else {
            [void]$builder.Append(('\' * $slashes))
            [void]$builder.Append($character)
        }
        $slashes = 0
    }
    [void]$builder.Append(('\' * (2 * $slashes)))
    [void]$builder.Append('"')
    return $builder.ToString()
}

function Save-Results {
    if (-not $script:RunRoot) { return }
    $failed = @($script:Checks | Where-Object { $_.status -eq 'fail' }).Count
    $report = [ordered]@{
        schema_version = 1
        suite = 'rclone-triage-isolated-windows-guest'
        started_utc = $script:Started.ToString('o')
        updated_utc = [DateTime]::UtcNow.ToString('o')
        guest = $script:Guest
        binary = [ordered]@{ path = $script:ResolvedBinary; expected_sha256 = $ExpectedSha256.ToLowerInvariant(); actual_sha256 = $script:ActualSha256 }
        run_root = $script:RunRoot
        passed = @($script:Checks | Where-Object { $_.status -eq 'pass' }).Count
        failed = $failed
        checks = @($script:Checks.ToArray())
        commands = @($script:Commands.ToArray())
        scope = 'Offline synthetic local-alias CLI acceptance; no live provider, OAuth, TUI, mount or access-point acceptance.'
    }
    Write-Utf8 (Join-Path $script:RunRoot 'results.json') ($report | ConvertTo-Json -Depth 20)
}

function Invoke-Check([string]$Name, [scriptblock]$Body) {
    $timer = [Diagnostics.Stopwatch]::StartNew()
    try {
        $detail = & $Body
        $record = [ordered]@{ name = $Name; status = 'pass'; elapsed_ms = $timer.ElapsedMilliseconds; detail = $detail }
    } catch {
        $record = [ordered]@{ name = $Name; status = 'fail'; elapsed_ms = $timer.ElapsedMilliseconds; error = $_.Exception.Message; location = $_.ScriptStackTrace }
    }
    [void]$script:Checks.Add([pscustomobject]$record)
    Save-Results
    Write-Host ('[{0}] {1}' -f $record.status.ToUpperInvariant(), $Name)
}

function Invoke-Triage([string]$Label, [string[]]$Arguments, [hashtable]$ExtraEnvironment = @{}) {
    $script:CommandNumber++
    $commandLabel = '{0:d2}-{1}' -f $script:CommandNumber, $Label
    $stdoutPath = Join-Path $script:RunRoot ($commandLabel + '.stdout.txt')
    $stderrPath = Join-Path $script:RunRoot ($commandLabel + '.stderr.txt')
    $start = New-Object Diagnostics.ProcessStartInfo
    $start.FileName = $script:ResolvedBinary
    $start.Arguments = ($Arguments | ForEach-Object { ConvertTo-NativeArgument $_ }) -join ' '
    $start.WorkingDirectory = $script:RunRoot
    $start.UseShellExecute = $false
    $start.CreateNoWindow = $true
    $start.RedirectStandardOutput = $true
    $start.RedirectStandardError = $true
    $start.RedirectStandardInput = $true
    foreach ($key in @($start.EnvironmentVariables.Keys)) {
        if ($key -match '^(RCLONE_|RCLONE_TRIAGE_|TRIAGE_|RUST_LOG$)') { $start.EnvironmentVariables.Remove($key) }
    }
    # These are process-local overrides for a synthetic guest profile only.
    foreach ($key in @('TEMP', 'TMP')) { $start.EnvironmentVariables[$key] = (Join-Path $script:RunRoot 'temp') }
    $start.EnvironmentVariables['USERPROFILE'] = Join-Path $script:RunRoot 'profile'
    $start.EnvironmentVariables['APPDATA'] = Join-Path $script:RunRoot 'profile\AppData\Roaming'
    $start.EnvironmentVariables['LOCALAPPDATA'] = Join-Path $script:RunRoot 'profile\AppData\Local'
    foreach ($key in $ExtraEnvironment.Keys) { $start.EnvironmentVariables[$key] = [string]$ExtraEnvironment[$key] }
    $process = New-Object Diagnostics.Process
    $process.StartInfo = $start
    $timer = [Diagnostics.Stopwatch]::StartNew()
    $timedOut = $false
    try {
        Assert-Condition ($process.Start()) "Could not start verified binary for $Label"
        $process.StandardInput.Close()
        $outputTask = $process.StandardOutput.ReadToEndAsync()
        $errorTask = $process.StandardError.ReadToEndAsync()
        if (-not $process.WaitForExit($CommandTimeoutSeconds * 1000)) {
            $timedOut = $true
            # Exact PID of this still-running process, including its children.
            & "$env:SystemRoot\System32\taskkill.exe" /PID $process.Id /T /F 2>&1 | Out-Null
            [void]$process.WaitForExit(10000)
        }
        $captured = $outputTask.Wait(5000) -and $errorTask.Wait(5000)
        $stdout = if ($outputTask.IsCompleted) { $outputTask.GetAwaiter().GetResult() } else { '[stdout pipe did not close]' }
        $stderr = if ($errorTask.IsCompleted) { $errorTask.GetAwaiter().GetResult() } else { '[stderr pipe did not close]' }
        Write-Utf8 $stdoutPath $stdout
        Write-Utf8 $stderrPath $stderr
        $exitCode = if ($process.HasExited) { $process.ExitCode } else { $null }
        $record = [pscustomobject][ordered]@{
            name = $Label; arguments = $Arguments; exit_code = $exitCode; timed_out = $timedOut
            capture_complete = $captured; elapsed_ms = $timer.ElapsedMilliseconds
            stdout_path = $stdoutPath; stderr_path = $stderrPath
        }
        [void]$script:Commands.Add($record)
        Save-Results
        Assert-Condition (-not $timedOut -and $captured) "Command $Label timed out or retained a child output pipe; inspect its logs."
        return $record
    } finally { $process.Dispose() }
}

function New-QueueRun([string]$Name, [string]$Csv, [hashtable]$ExtraEnvironment = @{}) {
    $queue = Join-Path $script:RunRoot ($Name + '.csv')
    Write-Utf8 $queue $Csv
    $output = Join-Path $script:RunRoot ('cases-' + $Name)
    $command = Invoke-Triage $Name @('--name', 'guest-case', '--output-dir', $output, '--download', $queue, '--rclone-config-path', $script:SourceConfig) $ExtraEnvironment
    return [pscustomobject]@{ command = $command; case_root = (Join-Path $output 'guest-case'); output_root = $output }
}

function Read-Manifest([string]$CaseRoot) {
    $files = @(Get-ChildItem -LiteralPath $CaseRoot -Filter 'acquisition-*.json' -File)
    Assert-Condition ($files.Count -eq 1) "Expected one acquisition manifest under $CaseRoot; found $($files.Count)."
    return [pscustomobject]@{ path = $files[0].FullName; data = ([IO.File]::ReadAllText($files[0].FullName) | ConvertFrom-Json) }
}

function Read-GzipText([string]$Path) {
    $file = [IO.File]::OpenRead($Path)
    $gzip = New-Object IO.Compression.GZipStream($file, [IO.Compression.CompressionMode]::Decompress)
    $memory = New-Object IO.MemoryStream
    try {
        $buffer = New-Object byte[] 8192
        while (($count = $gzip.Read($buffer, 0, $buffer.Length)) -gt 0) {
            Assert-Condition (($memory.Length + $count) -le 16777216) 'Diagnostic archive exceeds synthetic 16 MiB inspection limit.'
            $memory.Write($buffer, 0, $count)
        }
        # Inspect the tar stream in memory; do not extract archive paths.
        return [Text.Encoding]::UTF8.GetString($memory.ToArray())
    } finally { $memory.Dispose(); $gzip.Dispose(); $file.Dispose() }
}

try {
    Assert-Condition $IsolatedGuest.IsPresent 'Specify -IsolatedGuest only inside the disposable VM.'
    Assert-Condition ($env:OS -eq 'Windows_NT') 'Windows guest required.'
    Assert-Condition ($env:COMPUTERNAME -ceq $ExpectedComputerName) 'Guest computer name does not match the explicitly supplied name.'
    $system = Get-CimInstance Win32_ComputerSystem
    Assert-Condition ($system.Manufacturer -eq 'Microsoft Corporation' -and $system.Model -eq 'Virtual Machine') 'This harness refuses to run the application outside a Hyper-V virtual machine.'
    $activeAdapters = @(Get-NetAdapter | Where-Object { $_.Status -eq 'Up' })
    Assert-Condition ($activeAdapters.Count -eq 0) 'Disconnect/remove guest network adapters before acceptance; an active adapter was found.'
    Assert-Condition (@(Get-Process -Name 'rclone', 'rclone-triage' -ErrorAction SilentlyContinue).Count -eq 0) 'Guest already has rclone/triage processes; use a clean guest.'
    $script:Guest = [ordered]@{ computer_name = $env:COMPUTERNAME; manufacturer = $system.Manufacturer; model = $system.Model; os_version = [Environment]::OSVersion.VersionString; powershell = $PSVersionTable.PSVersion.ToString(); active_network_adapters = 0 }
    $script:ResolvedBinary = (Resolve-Path -LiteralPath $BinaryPath).ProviderPath
    Assert-Condition ($script:ResolvedBinary -match '^[A-Za-z]:\\') 'Copy the executable to a local guest drive; UNC/shared-drive input is refused.'
    Assert-NoReparse $script:ResolvedBinary
    Assert-Condition ([IO.File]::Exists($script:ResolvedBinary)) 'Binary path is not a file.'
    $script:ActualSha256 = Get-Sha256 $script:ResolvedBinary
    Assert-Condition ($script:ActualSha256 -eq $ExpectedSha256.ToLowerInvariant()) 'Release executable SHA256 does not match the pinned verified artifact.'
    $resolvedOutput = [IO.Path]::GetFullPath($OutputRoot)
    Assert-Condition ($resolvedOutput -match '^[A-Za-z]:\\') 'OutputRoot must be on a local guest drive, not a UNC/shared path.'
    Assert-NoReparse $resolvedOutput
    [void][IO.Directory]::CreateDirectory($resolvedOutput)
    $script:RunRoot = Join-Path $resolvedOutput ('run-' + [DateTime]::UtcNow.ToString('yyyyMMddTHHmmss') + '-' + [Guid]::NewGuid().ToString('N'))
    [void][IO.Directory]::CreateDirectory($script:RunRoot)
    foreach ($directory in @('temp', 'profile\AppData\Roaming', 'profile\AppData\Local', 'synthetic sources\a', 'synthetic sources\b')) {
        [void][IO.Directory]::CreateDirectory((Join-Path $script:RunRoot $directory))
    }
    $script:SourceA = Join-Path $script:RunRoot 'synthetic sources\a\same.txt'
    $script:SourceB = Join-Path $script:RunRoot 'synthetic sources\b\same.txt'
    Write-Utf8 $script:SourceA 'SOURCE A'
    Write-Utf8 $script:SourceB 'SOURCE B'
    $script:SourceConfig = Join-Path $script:RunRoot 'original.conf'
    Write-Utf8 $script:SourceConfig ("[RemoteA]`ntype = alias`nremote = {0}`n[RemoteB]`ntype = alias`nremote = {1}`n[_triage_combined]`ntype = memory`n" -f (Split-Path $script:SourceA), (Split-Path $script:SourceB))
    $script:OriginalConfigHash = Get-Sha256 $script:SourceConfig
    $script:SourceHashes = @{ 'RemoteA:same.txt' = (Get-Sha256 $script:SourceA); 'RemoteB:same.txt' = (Get-Sha256 $script:SourceB) }
    Invoke-Check 'verified-release-and-isolated-guest' { return $script:Guest }

    Invoke-Check 'clean-guest-cli-startup' {
        $version = Invoke-Triage 'version' @('--version')
        $help = Invoke-Triage 'help' @('--help')
        Assert-Condition ($version.exit_code -eq 0 -and $help.exit_code -eq 0) 'CLI version/help failed on the clean guest.'
        Assert-Condition ([IO.File]::ReadAllText($help.stdout_path).Contains('--download')) 'Help did not expose the expected download interface.'
        return @{ version = [IO.File]::ReadAllText($version.stdout_path).Trim(); external_runtime_installed_by_harness = $false }
    }

    Invoke-Check 'local-alias-acquisition-integrity-and-source-provenance' {
        $csv = "Path,Remote,Size,Hash,HashType`nsame.txt,RemoteA,8,{0},SHA256`nsame.txt,RemoteB,8,{1},SHA256`n" -f $script:SourceHashes['RemoteA:same.txt'], $script:SourceHashes['RemoteB:same.txt']
        $run = New-QueueRun 'multi-remote' $csv
        Assert-Condition ($run.command.exit_code -eq 0) 'Two-remote acquisition failed; inspect multi-remote stderr and manifest.'
        $manifest = Read-Manifest $run.case_root
        Assert-Condition ($manifest.data.complete -eq $true -and @($manifest.data.results).Count -eq 2) 'Acquisition manifest is incomplete or missing outcomes.'
        $destinations = @()
        foreach ($result in $manifest.data.results) {
            Assert-Condition ($script:SourceHashes.ContainsKey([string]$result.source)) 'Manifest source identity is unexpected.'
            Assert-Condition (Test-Inside $result.destination (Join-Path $run.case_root 'downloads')) 'Destination escaped the case downloads directory.'
            Assert-Condition ($result.success -eq $true -and $result.integrity -eq 'Verified' -and $result.hash_verified -eq $true) 'Expected source SHA256 was not verified.'
            $expectedHash = $script:SourceHashes[[string]$result.source]
            Assert-Condition ((Get-Sha256 $result.destination) -eq $expectedHash -and $result.local_sha256 -eq $expectedHash) 'Downloaded bytes/local manifest SHA256 do not match their source.'
            Assert-Condition ($result.size -eq 8) 'Downloaded size differs from exact synthetic bytes.'
            $destinations += $result.destination
        }
        Assert-Condition ($destinations[0] -ine $destinations[1]) 'Different remotes collided at one destination.'
        Assert-Condition ($manifest.data.config_path -ine $script:SourceConfig -and (Test-Inside $manifest.data.config_path (Join-Path $run.case_root 'config'))) 'Acquisition did not use a private config snapshot.'
        $provenancePath = [IO.Path]::ChangeExtension([string]$manifest.data.config_path, 'provenance.json')
        $provenance = [IO.File]::ReadAllText($provenancePath) | ConvertFrom-Json
        Assert-Condition ($provenance.source_sha256 -eq $script:OriginalConfigHash) 'Snapshot source hash is incorrect.'
        Assert-Condition ((Get-Sha256 $script:SourceConfig) -eq $script:OriginalConfigHash) 'Original config changed.'
        $checkpoints = @(Get-ChildItem -LiteralPath (Join-Path $run.case_root 'logs') -Filter '*.checkpoint.json' -File)
        Assert-Condition ($checkpoints.Count -eq 1) 'Acquisition checkpoint is absent.'
        $checkpoint = [IO.File]::ReadAllText($checkpoints[0].FullName) | ConvertFrom-Json
        Assert-Condition ($checkpoint.hash -match '^[a-f0-9]{64}$' -and $checkpoint.entry_count -gt 0) 'Checkpoint structure is invalid.'
        return @{ manifest = $manifest.path; destinations = $destinations; provenance = $provenancePath; checkpoint = $checkpoints[0].FullName; checkpoint_verification = 'Presence and shape only; cryptographic log-chain verification is covered by repository tests.' }
    }

    Invoke-Check 'inherited-environment-cannot-redirect-or-dry-run-acquisition' {
        $run = New-QueueRun 'environment-overrides' "Path,Remote`nsame.txt,RemoteA`n" @{ RCLONE_CONFIG_REMOTEA_REMOTE = (Split-Path $script:SourceB); RCLONE_DRY_RUN = 'true' }
        Assert-Condition ($run.command.exit_code -eq 0) 'Acquisition with inherited overrides failed.'
        $manifest = Read-Manifest $run.case_root
        Assert-Condition ($manifest.data.complete -eq $true -and @($manifest.data.results).Count -eq 1) 'Override test did not produce a real acquisition.'
        $result = $manifest.data.results[0]
        Assert-Condition ((Get-Sha256 $result.destination) -eq $script:SourceHashes['RemoteA:same.txt']) 'Inherited environment redirected acquisition or prevented writing bytes.'
        return @{ manifest = $manifest.path; preserved_source = $result.source }
    }

    Invoke-Check 'invalid-path-rejected-before-transfer' {
        $outside = Join-Path $script:RunRoot 'synthetic sources\outside.txt'
        Write-Utf8 $outside 'SYNTHETIC OUTSIDE SENTINEL'
        $before = Get-Sha256 $outside
        $run = New-QueueRun 'traversal' "Path,Remote`n../outside.txt,RemoteA`n"
        Assert-Condition ($run.command.exit_code -ne 0) 'Traversal queue unexpectedly returned success.'
        Assert-Condition ([IO.File]::ReadAllText($run.command.stderr_path).Contains('Unsafe')) 'Traversal was not rejected by path validation.'
        $acquired = @(Get-ChildItem -LiteralPath $run.output_root -Recurse -File | Where-Object { $_.Name -eq 'outside.txt' })
        Assert-Condition ($acquired.Count -eq 0 -and (Get-Sha256 $outside) -eq $before) 'Traversal acquired or changed the outside sentinel.'
        return @{ exit_code = $run.command.exit_code; sentinel_sha256 = $before }
    }

    Invoke-Check 'missing-source-nonzero-and-durable-failure-manifest' {
        $run = New-QueueRun 'missing-source' "Path,Remote`nmissing.txt,RemoteA`n"
        Assert-Condition ($run.command.exit_code -ne 0) 'Missing source unexpectedly returned success.'
        $manifest = Read-Manifest $run.case_root
        Assert-Condition ($manifest.data.complete -eq $false -and @($manifest.data.results).Count -eq 1) 'Missing source has no durable failed outcome.'
        $result = $manifest.data.results[0]
        Assert-Condition ($result.success -eq $false -and $result.integrity -eq 'Failed' -and -not [string]::IsNullOrWhiteSpace($result.error)) 'Missing-source failure status is inaccurate.'
        Assert-Condition (-not [IO.File]::Exists($result.destination)) 'Missing source produced a destination file.'
        return @{ manifest = $manifest.path; exit_code = $run.command.exit_code; error = $result.error }
    }

    Invoke-Check 'hash-mismatch-nonzero-and-retained-evidence' {
        $run = New-QueueRun 'hash-mismatch' ("Path,Remote,Hash,HashType`nsame.txt,RemoteA,{0},SHA256`n" -f ('0' * 64))
        Assert-Condition ($run.command.exit_code -ne 0) 'Hash mismatch unexpectedly returned success.'
        $manifest = Read-Manifest $run.case_root
        $result = $manifest.data.results[0]
        Assert-Condition ($manifest.data.complete -eq $false -and $result.success -eq $false -and $result.integrity -eq 'Mismatch') 'Hash mismatch is not explicitly recorded.'
        Assert-Condition ($result.local_sha256 -eq (Get-Sha256 $result.destination)) 'Mismatch evidence was not retained with its actual local SHA256.'
        return @{ manifest = $manifest.path; exit_code = $run.command.exit_code; destination = $result.destination }
    }

    Invoke-Check 'diagnostics-canaries-redacted-original-preserved' {
        $output = Join-Path $script:RunRoot 'diagnostics-output'
        $configDir = Join-Path $output 'guest-case\config'
        [void][IO.Directory]::CreateDirectory($configDir)
        $config = Join-Path $configDir 'rclone.conf'
        $configCanary = 'SYNTHETIC-CONFIG-' + [Guid]::NewGuid().ToString('N')
        $envCanary = 'SYNTHETIC-ENV-' + [Guid]::NewGuid().ToString('N')
        Write-Utf8 $config ("[canary]`ntype = s3`nunknown_key = $configCanary`n")
        $originalHash = Get-Sha256 $config
        $command = Invoke-Triage 'diagnostics' @('--name', 'guest-case', '--output-dir', $output, '--collect-logs') @{ RCLONE_CONFIG_CANARY_SECRET_ACCESS_KEY = $envCanary }
        Assert-Condition ($command.exit_code -eq 0) 'Diagnostic collection failed.'
        $archives = @(Get-ChildItem -LiteralPath $output -Filter '*.tar.gz' -File)
        Assert-Condition ($archives.Count -eq 1) 'Expected one diagnostic bundle.'
        $contents = Read-GzipText $archives[0].FullName
        Assert-Condition ($contents.Contains('REDACTED') -and $contents.Contains('unknown_key') -and $contents.Contains('RCLONE_CONFIG_CANARY_SECRET_ACCESS_KEY')) 'Expected synthetic config/environment diagnostics were not included and redacted.'
        Assert-Condition (-not $contents.Contains($configCanary) -and -not $contents.Contains($envCanary)) 'Synthetic secret canary leaked into the diagnostic archive.'
        Assert-Condition ((Get-Sha256 $config) -eq $originalHash) 'Diagnostic collection modified original credentials.'
        return @{ archive = $archives[0].FullName; archive_sha256 = (Get-Sha256 $archives[0].FullName); inspected_uncompressed_bytes = [Text.Encoding]::UTF8.GetByteCount($contents); original_config_preserved = $true }
    }

    Invoke-Check 'source-and-release-immutability' {
        Assert-Condition ((Get-Sha256 $script:ResolvedBinary) -eq $script:ActualSha256) 'Release executable changed.'
        Assert-Condition ((Get-Sha256 $script:SourceConfig) -eq $script:OriginalConfigHash) 'Original source configuration changed.'
        Assert-Condition ((Get-Sha256 $script:SourceA) -eq $script:SourceHashes['RemoteA:same.txt'] -and (Get-Sha256 $script:SourceB) -eq $script:SourceHashes['RemoteB:same.txt']) 'A synthetic source file changed.'
        return @{ binary_sha256 = $script:ActualSha256; config_sha256 = $script:OriginalConfigHash; sources = $script:SourceHashes }
    }

    Invoke-Check 'no-orphaned-triage-or-rclone-processes' {
        $remaining = @(Get-Process -Name 'rclone', 'rclone-triage' -ErrorAction SilentlyContinue)
        Assert-Condition ($remaining.Count -eq 0) ('Processes remain after CLI exit: ' + (($remaining | ForEach-Object { $_.Id }) -join ','))
        return @{ remaining_processes = 0 }
    }
    Save-Results
    Write-Host ('Results: ' + (Join-Path $script:RunRoot 'results.json'))
    if (@($script:Checks | Where-Object { $_.status -eq 'fail' }).Count -gt 0) { exit 1 }
    exit 0
} catch {
    $failure = [pscustomobject][ordered]@{ name = 'harness-preflight-or-fatal'; status = 'fail'; error = $_.Exception.Message; location = $_.ScriptStackTrace }
    [void]$script:Checks.Add($failure)
    Save-Results
    # Preflight refusal occurs before creating a run directory; still emit JSON.
    [ordered]@{ schema_version = 1; status = 'refused-or-fatal'; error = $_.Exception.Message; run_root = $script:RunRoot } | ConvertTo-Json -Compress | Write-Output
    exit 2
}
