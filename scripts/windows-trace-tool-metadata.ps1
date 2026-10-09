# Hosted metadata only. Never invoke WPR/tracerpt or change token/session state.
# Signature verification is deliberately omitted: the PowerShell cmdlet has no
# documented cache-only switch. No signature, permission or capture claim follows.
Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

function Get-PreflightGate {
    param([bool]$Windows, [bool]$Process64Bit, [string]$Actions, [string]$RunnerEnvironment)
    if (-not $Windows) { return 'not_windows' }
    if ($Actions -cne 'true' -or $RunnerEnvironment -cne 'github-hosted') { return 'not_hosted' }
    if (-not $Process64Bit) { return 'not_64_bit' }
    return 'passed'
}

function ConvertTo-FixedVersion {
    param([object[]]$Parts)
    if ($Parts.Count -ne 4) { throw 'version_invalid' }
    foreach ($part in $Parts) {
        if ($part -isnot [int] -or $part -lt 0 -or $part -gt 65535) { throw 'version_invalid' }
    }
    if ($Parts[0] -eq 0) { throw 'version_invalid' }
    return (($Parts | ForEach-Object { $_.ToString([Globalization.CultureInfo]::InvariantCulture) }) -join '.')
}

function New-ToolMetadata {
    param([string]$Status = 'not_attempted', [string]$Reason = 'gate_denied',
          [object]$Size = $null, [object]$Hash = $null, [object]$Version = $null)
    return [ordered]@{
        status = $Status; reason = $Reason; size_bytes = $Size; sha256 = $Hash; file_version = $Version
        metadata_stable = ($Status -ceq 'metadata_observed')
        signature_status = 'unverified'; trusted = $false; identity_verified = $false
    }
}

function New-PreflightRecord {
    param([string]$Gate, [object]$Admin = $null, [object]$Wpr = $null, [object]$Tracerpt = $null)
    if ($null -eq $Wpr) { $Wpr = New-ToolMetadata }
    if ($null -eq $Tracerpt) { $Tracerpt = New-ToolMetadata }
    return [ordered]@{
        schema_version = 1; scope = 'hosted_windows_trace_tool_metadata_only'; gate = $Gate
        admin_role_observed = ($null -ne $Admin); admin_role = $Admin
        tools = [ordered]@{ wpr = $Wpr; tracerpt = $Tracerpt }
        signature_verification_performed = $false; tools_executed = $false; capture_ready = $false
        query_permission_verified = $false; event_support_verified = $false; profile_support_verified = $false
    }
}

function Assert-Keys {
    param([object]$Value, [string[]]$Keys)
    if ($Value -isnot [Collections.IDictionary] -or $Value.Count -ne $Keys.Count) { throw 'record_shape' }
    foreach ($key in $Keys) { if (-not $Value.Contains($key)) { throw 'record_shape' } }
}

function ConvertTo-ClosedPreflightJson {
    param([object]$Record)
    Assert-Keys $Record @('schema_version', 'scope', 'gate', 'admin_role_observed', 'admin_role', 'tools',
        'signature_verification_performed', 'tools_executed', 'capture_ready', 'query_permission_verified',
        'event_support_verified', 'profile_support_verified')
    if ($Record.schema_version -isnot [int] -or $Record.schema_version -ne 1 -or
        $Record.scope -cne 'hosted_windows_trace_tool_metadata_only' -or
        $Record.gate -cnotin @('passed', 'not_windows', 'not_hosted', 'not_64_bit', 'system_root_invalid', 'preflight_failed')) {
        throw 'record_shape'
    }
    foreach ($key in @('signature_verification_performed', 'tools_executed', 'capture_ready', 'query_permission_verified',
                      'event_support_verified', 'profile_support_verified')) {
        if ($Record[$key] -isnot [bool] -or $Record[$key]) { throw 'record_claim' }
    }
    if ($Record.admin_role_observed -isnot [bool] -or
        ($Record.admin_role_observed -and $Record.admin_role -isnot [bool]) -or
        (-not $Record.admin_role_observed -and $null -ne $Record.admin_role)) { throw 'record_admin' }
    Assert-Keys $Record.tools @('wpr', 'tracerpt')
    foreach ($name in @('wpr', 'tracerpt')) {
        $tool = $Record.tools[$name]
        Assert-Keys $tool @('status', 'reason', 'size_bytes', 'sha256', 'file_version', 'metadata_stable',
                           'signature_status', 'trusted', 'identity_verified')
        if ($tool.status -cnotin @('metadata_observed', 'unavailable', 'not_attempted') -or
            $tool.reason -cnotin @('signature_not_checked', 'gate_denied', 'missing', 'reparse', 'not_file',
                                  'size_invalid', 'version_invalid', 'metadata_changed', 'read_failed', 'close_failed') -or
            $tool.signature_status -cne 'unverified') { throw 'record_tool' }
        foreach ($key in @('trusted', 'identity_verified')) {
            if ($tool[$key] -isnot [bool] -or $tool[$key]) { throw 'record_claim' }
        }
        if ($tool.metadata_stable -isnot [bool] -or $tool.metadata_stable -ne ($tool.status -ceq 'metadata_observed')) {
            throw 'record_tool'
        }
        if ($tool.status -ceq 'metadata_observed') {
            if ($tool.reason -cne 'signature_not_checked' -or
                ($tool.size_bytes -isnot [long] -and $tool.size_bytes -isnot [int]) -or
                $tool.size_bytes -lt 1 -or $tool.size_bytes -gt 67108864 -or
                $tool.sha256 -isnot [string] -or $tool.sha256 -cnotmatch '\A[a-f0-9]{64}\z' -or
                $tool.file_version -isnot [string] -or $tool.file_version -cnotmatch '\A[1-9][0-9]{0,4}(?:\.(?:0|[1-9][0-9]{0,4})){3}\z') {
                throw 'record_metadata'
            }
            foreach ($part in $tool.file_version.Split('.')) { if ([int]$part -gt 65535) { throw 'record_metadata' } }
        } elseif ($null -ne $tool.size_bytes -or $null -ne $tool.sha256 -or $null -ne $tool.file_version -or
                  ($tool.status -ceq 'not_attempted' -and $tool.reason -cne 'gate_denied') -or
                  ($tool.status -ceq 'unavailable' -and $tool.reason -cin @('gate_denied', 'signature_not_checked'))) {
            throw 'record_metadata'
        }
        if ($Record.gate -cne 'passed' -and $tool.status -cne 'not_attempted') { throw 'record_gate' }
    }
    if ($Record.gate -cne 'passed' -and $Record.admin_role_observed) { throw 'record_gate' }
    $json = ConvertTo-Json -InputObject $Record -Depth 5 -Compress
    if ($json.Length -gt 2048 -or $json -cmatch '[^\x20-\x7e]') { throw 'record_bound' }
    return $json
}

function Read-PlainSnapshot {
    param([string]$Path)
    $file = [IO.FileInfo]::new($Path)
    $file.Refresh()
    if (-not $file.Exists) { throw 'missing' }
    if (($file.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0) { throw 'reparse' }
    if (($file.Attributes -band [IO.FileAttributes]::Directory) -ne 0) { throw 'not_file' }
    $directory = $file.Directory
    $depth = 0
    while ($null -ne $directory) {
        $depth++
        $directory.Refresh()
        if ($depth -gt 16 -or -not $directory.Exists -or
            ($directory.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0) { throw 'reparse' }
        $directory = $directory.Parent
    }
    if ($file.Length -lt 1 -or $file.Length -gt 67108864) { throw 'size_invalid' }
    return @([long]$file.Length, [long]$file.CreationTimeUtc.Ticks, [long]$file.LastWriteTimeUtc.Ticks, [int]$file.Attributes)
}

function Read-ToolMetadata {
    param([string]$System32, [ValidateSet('wpr.exe', 'tracerpt.exe')][string]$Name)
    $stream = $null; $hash = $null
    $result = New-ToolMetadata -Status 'unavailable' -Reason 'read_failed'
    try {
        $path = [IO.Path]::Combine($System32, $Name)
        $before = Read-PlainSnapshot $path
        # Read sharing only excludes other write/delete opens for this leaf.
        # Path snapshots are stability evidence, not a file-ID/ancestor pin claim.
        $stream = [IO.FileStream]::new($path, [IO.FileMode]::Open, [IO.FileAccess]::Read, [IO.FileShare]::Read)
        if ($stream.Length -ne $before[0]) { throw 'metadata_changed' }
        $versionInfo = [Diagnostics.FileVersionInfo]::GetVersionInfo($path)
        $version = ConvertTo-FixedVersion @($versionInfo.FileMajorPart, $versionInfo.FileMinorPart,
                                           $versionInfo.FileBuildPart, $versionInfo.FilePrivatePart)
        $hash = [Security.Cryptography.SHA256]::Create()
        $buffer = [byte[]]::new(65536)
        [long]$total = 0
        while ($total -lt $before[0]) {
            $limit = [int][Math]::Min([long]$buffer.Length, $before[0] - $total)
            $count = $stream.Read($buffer, 0, $limit)
            if ($count -le 0) { throw 'metadata_changed' }
            [void]$hash.TransformBlock($buffer, 0, $count, $buffer, 0)
            $total += $count
        }
        [void]$hash.TransformFinalBlock([byte[]]::new(0), 0, 0)
        $after = Read-PlainSnapshot $path
        if ($total -ne $before[0] -or $stream.Length -ne $before[0]) { throw 'metadata_changed' }
        for ($i = 0; $i -lt 4; $i++) { if ($before[$i] -ne $after[$i]) { throw 'metadata_changed' } }
        $digest = [BitConverter]::ToString($hash.Hash).Replace('-', '').ToLowerInvariant()
        $result = New-ToolMetadata -Status 'metadata_observed' -Reason 'signature_not_checked' -Size $total -Hash $digest -Version $version
    } catch {
        # Only our fixed thrown identifiers are admitted; no exception is emitted.
        $reason = 'read_failed'
        if ($_.Exception.Message -cin @('missing', 'reparse', 'not_file', 'size_invalid', 'version_invalid', 'metadata_changed')) {
            $reason = $_.Exception.Message
        }
        $result = New-ToolMetadata -Status 'unavailable' -Reason $reason
    } finally {
        foreach ($item in @($hash, $stream)) {
            if ($null -ne $item) {
                try { $item.Dispose() } catch { $result = New-ToolMetadata -Status 'unavailable' -Reason 'close_failed' }
            }
        }
    }
    return $result
}

function Invoke-TraceToolMetadataPreflight {
    $gate = Get-PreflightGate ([Environment]::OSVersion.Platform -eq [PlatformID]::Win32NT) `
        ([Environment]::Is64BitProcess) $env:GITHUB_ACTIONS $env:RUNNER_ENVIRONMENT
    if ($gate -cne 'passed') { return (New-PreflightRecord -Gate $gate) }
    try {
        $windows = [Environment]::GetFolderPath([Environment+SpecialFolder]::Windows)
        $system32 = [Environment]::SystemDirectory
        if ($windows -notmatch '\A[A-Za-z]:\\[^\x00-\x1f"<>|?*:]+\z' -or
            [IO.Path]::GetFullPath($windows) -ine $windows -or
            [IO.Path]::GetFullPath($system32) -ine [IO.Path]::Combine($windows, 'System32')) {
            return (New-PreflightRecord -Gate 'system_root_invalid')
        }
        $admin = $null; $identity = $null
        try {
            $identity = [Security.Principal.WindowsIdentity]::GetCurrent()
            $principal = [Security.Principal.WindowsPrincipal]::new($identity)
            $admin = $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
        } catch { $admin = $null } finally {
            if ($null -ne $identity) { try { $identity.Dispose() } catch { $admin = $null } }
        }
        $wpr = Read-ToolMetadata -System32 $system32 -Name 'wpr.exe'
        $tracerpt = Read-ToolMetadata -System32 $system32 -Name 'tracerpt.exe'
        return (New-PreflightRecord -Gate 'passed' -Admin $admin -Wpr $wpr -Tracerpt $tracerpt)
    } catch { return (New-PreflightRecord -Gate 'preflight_failed') }
}

try {
    ConvertTo-ClosedPreflightJson (Invoke-TraceToolMetadataPreflight)
} catch {
    # Finite fallback, including an unexpected serialization failure. No raw errors.
    ConvertTo-ClosedPreflightJson (New-PreflightRecord -Gate 'preflight_failed')
}
