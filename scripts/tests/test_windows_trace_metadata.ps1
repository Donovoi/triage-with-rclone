# Parser and pure record checks only. Do not dot-source or invoke the entrypoint.
Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
$source = Join-Path $PSScriptRoot '../windows-trace-tool-metadata.ps1'
$tokens = $null; $errors = $null
$ast = [Management.Automation.Language.Parser]::ParseFile($source, [ref]$tokens, [ref]$errors)
if ($errors.Count -ne 0) { throw 'source_parse_failed' }
$pureNames = @('Get-PreflightGate', 'ConvertTo-FixedVersion', 'New-ToolMetadata', 'New-PreflightRecord',
               'Assert-Keys', 'ConvertTo-ClosedPreflightJson')
foreach ($name in $pureNames) {
    $functions = @($ast.FindAll({ param($node)
        $node -is [Management.Automation.Language.FunctionDefinitionAst] -and $node.Name -ceq $name
    }, $false))
    if ($functions.Count -ne 1) { throw 'pure_function_missing' }
    . ([scriptblock]::Create($functions[0].Extent.Text))
}
$script:checks = 0
function Require {
    param([bool]$Value)
    if (-not $Value) { throw 'pure_check_failed' }
    $script:checks++
}
function Reject {
    param([scriptblock]$Action)
    $refused = $false
    try { & $Action | Out-Null } catch { $refused = $true }
    Require $refused
}
function Good {
    $tool = New-ToolMetadata -Status 'metadata_observed' -Reason 'signature_not_checked' `
        -Size ([long]1024) -Hash ('a' * 64) -Version '10.0.26100.1'
    return (New-PreflightRecord -Gate 'passed' -Admin $true -Wpr $tool -Tracerpt $tool)
}

Require ((Get-PreflightGate $true $true 'true' 'github-hosted') -ceq 'passed')
foreach ($row in @(
    @($false, $true, 'true', 'github-hosted', 'not_windows'),
    @($true, $true, 'false', 'github-hosted', 'not_hosted'),
    @($true, $true, 'true', 'self-hosted', 'not_hosted'),
    @($true, $true, 'True', 'github-hosted', 'not_hosted'),
    @($true, $false, 'true', 'github-hosted', 'not_64_bit'))) {
    Require ((Get-PreflightGate $row[0] $row[1] $row[2] $row[3]) -ceq $row[4])
}
Require ((ConvertTo-FixedVersion @(10, 0, 26100, 1)) -ceq '10.0.26100.1')
foreach ($parts in @(@(10, 0, 1), @(0, 0, 1, 0), @(10, -1, 0, 0), @(10, 0, 65536, 0), @('10', 0, 1, 0))) {
    Reject { ConvertTo-FixedVersion $parts }
}

$json = ConvertTo-ClosedPreflightJson (Good)
$roundtrip = ConvertFrom-Json -AsHashtable -InputObject $json
Require ($json.Length -lt 2048 -and $json -cnotmatch '[^\x20-\x7e]')
Require ($roundtrip.tools.wpr.file_version -ceq '10.0.26100.1' -and $roundtrip.tools.wpr.sha256 -ceq ('a' * 64))
foreach ($name in @('wpr', 'tracerpt')) {
    Require ($roundtrip.tools[$name].signature_status -ceq 'unverified')
    Require (-not $roundtrip.tools[$name].trusted -and -not $roundtrip.tools[$name].identity_verified)
}
foreach ($name in @('signature_verification_performed', 'tools_executed', 'capture_ready',
                    'query_permission_verified', 'event_support_verified', 'profile_support_verified')) {
    Require ($roundtrip[$name] -is [bool] -and -not $roundtrip[$name])
    $bad = Good; $bad[$name] = $true
    Reject { ConvertTo-ClosedPreflightJson $bad }
}
foreach ($gate in @('not_windows', 'not_hosted', 'not_64_bit', 'system_root_invalid', 'preflight_failed')) {
    $closed = ConvertFrom-Json -AsHashtable -InputObject (ConvertTo-ClosedPreflightJson (New-PreflightRecord -Gate $gate))
    Require ($closed.gate -ceq $gate -and -not $closed.admin_role_observed -and $null -eq $closed.admin_role)
    Require ($closed.tools.wpr.status -ceq 'not_attempted' -and $closed.tools.tracerpt.reason -ceq 'gate_denied')
}
foreach ($reason in @('missing', 'reparse', 'not_file', 'size_invalid', 'version_invalid',
                      'metadata_changed', 'read_failed', 'close_failed')) {
    $tool = New-ToolMetadata -Status 'unavailable' -Reason $reason
    $closed = ConvertFrom-Json -AsHashtable -InputObject (ConvertTo-ClosedPreflightJson (New-PreflightRecord -Gate 'passed' -Wpr $tool -Tracerpt $tool))
    Require ($closed.tools.wpr.reason -ceq $reason -and $null -eq $closed.tools.wpr.sha256 -and $null -eq $closed.tools.wpr.file_version)
}

foreach ($field in @('path', 'account', 'subject', 'message')) {
    $bad = Good; $bad[$field] = 'private-canary'
    Reject { ConvertTo-ClosedPreflightJson $bad }
    $bad = Good; $bad.tools.wpr[$field] = 'private-canary'
    Reject { ConvertTo-ClosedPreflightJson $bad }
}
foreach ($row in @(@('reason', 'private-canary'), @('file_version', '10.0.1.2 private-canary'),
                   @('file_version', '10.0.01.2'), @('file_version', '10.0.65536.2'),
                   @('sha256', 'A' * 64), @('size_bytes', [long]67108865), @('size_bytes', 0),
                   @('size_bytes', $true), @('trusted', 0), @('signature_status', 'Valid'))) {
    $bad = Good; $bad.tools.wpr[$row[0]] = $row[1]
    Reject { ConvertTo-ClosedPreflightJson $bad }
}
$bad = Good; $bad.gate = 'not_hosted'
Reject { ConvertTo-ClosedPreflightJson $bad }
$bad = Good; $bad.admin_role = 'synthetic-account'
Reject { ConvertTo-ClosedPreflightJson $bad }
$bad = Good; $bad.admin_role_observed = $false
Reject { ConvertTo-ClosedPreflightJson $bad }
$bad = Good; $bad.tools.wpr.metadata_stable = $false
Reject { ConvertTo-ClosedPreflightJson $bad }
$bad = Good; $bad.tools.wpr.status = 'unavailable'
Reject { ConvertTo-ClosedPreflightJson $bad }
$bad = Good; $bad.tools.wpr.reason = 'missing'
Reject { ConvertTo-ClosedPreflightJson $bad }
Require ($null -eq (Get-Command Read-ToolMetadata -ErrorAction SilentlyContinue))
Require ($null -eq (Get-Command Invoke-TraceToolMetadataPreflight -ErrorAction SilentlyContinue))
[ordered]@{ pure_checks = $script:checks; source_parsed = $true; metadata_entrypoint_invoked = $false
            tools_executed = $false; signature_verification_performed = $false } | ConvertTo-Json -Compress
