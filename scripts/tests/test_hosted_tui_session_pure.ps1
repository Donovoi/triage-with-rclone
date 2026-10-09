# Compile and pure encoding/protocol/state checks only. No native session calls.
Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
$root = Split-Path -Parent $PSScriptRoot
$script:passed = 0
function Check([bool]$Value) {
    if (-not $Value) { throw 'pure_tui_assertion_failed' }
    $script:passed++
}
function Reject([scriptblock]$Action) {
    $rejected = $false
    try { & $Action | Out-Null } catch { $rejected = $true }
    Check $rejected
}
function Hex([byte[]]$Value) { [BitConverter]::ToString($Value) }

$sourcePath = Join-Path $root 'application-lab/HostedConPtySession.cs'
$source = [IO.File]::ReadAllText($sourcePath)
Check ($source.Length -gt 0 -and $source.Length -le 65536)
if ($null -eq ('TriageApplicationLab.HostedConPtySession' -as [type])) {
    Add-Type -Path $sourcePath -ErrorAction Stop -WarningAction SilentlyContinue 2>$null
}
# Compilation does not create a session; only the pure types below are invoked.
$keys = @{
    enter='0D'; escape='1B'; up='1B-5B-41'; down='1B-5B-42'; right='1B-5B-43'; left='1B-5B-44';
    tab='09'; backspace='7F'; home='1B-5B-48'; end='1B-5B-46'; page_up='1B-5B-35-7E';
    page_down='1B-5B-36-7E'; space='20'
}
foreach ($key in $keys.Keys) {
    Check ((Hex ([TriageApplicationLab.HostedTuiProtocol]::KeyBytes($key))) -ceq $keys[$key])
}
foreach ($key in @('', 'Enter', 'ctrl_c', 'ctrl+C', 'escape_sequence', 'down 2', "`e[A", $null)) {
    Reject { [TriageApplicationLab.HostedTuiProtocol]::KeyBytes($key) }
}
foreach ($text in @('Synthetic', 'http://127.0.0.1:12345/root/', 'spaced name', '?', ('a' * 256))) {
    $value = [TriageApplicationLab.HostedTuiProtocol]::TextBytes($text)
    Check ($value.Length -eq $text.Length -and [Text.Encoding]::ASCII.GetString($value) -ceq $text)
}
foreach ($text in @('', ('a' * 257), "a`r", "a`n", "a`t", ([string][char]3),
                    ([string][char]27), ([string][char]127), ([string][char]160),
                    ([string][char]0xD800), ([string][char]0x202E), $null)) {
    Reject { [TriageApplicationLab.HostedTuiProtocol]::TextBytes($text) }
}
foreach ($size in @(@(120,34), @(80,24))) {
    Check ([TriageApplicationLab.HostedTuiProtocol]::SizeAllowed($size[0], $size[1]))
}
foreach ($size in @(@(120,24), @(80,34), @(0,0), @(121,34), @(80,23), @(32768,24), @(-1,34))) {
    Check (-not [TriageApplicationLab.HostedTuiProtocol]::SizeAllowed($size[0], $size[1]))
}

$budget = [TriageApplicationLab.HostedTuiInputBudget]::new()
for ($i=0; $i -lt 256; $i++) { $budget.ReserveInput(1) }
Check ($budget.InputCommands -eq 256 -and $budget.InputBytes -eq 256)
Reject { $budget.ReserveInput(1) }
Reject { $budget.ReserveResize(80,24) }
Check ($budget.InputCommands -eq 256 -and $budget.InputBytes -eq 256 -and $budget.ResizeCount -eq 0)
$budget = [TriageApplicationLab.HostedTuiInputBudget]::new()
for ($i=0; $i -lt 32; $i++) { $budget.ReserveInput(256) }
Check ($budget.InputCommands -eq 32 -and $budget.InputBytes -eq 8192)
Reject { $budget.ReserveInput(1) }
Check ($budget.InputCommands -eq 32 -and $budget.InputBytes -eq 8192)
foreach ($length in @(-1,0,257,[int]::MaxValue)) {
    $budget = [TriageApplicationLab.HostedTuiInputBudget]::new()
    Reject { $budget.ReserveInput($length) }
    Reject { $budget.ReserveInput(1) }
    Check ($budget.InputCommands -eq 0 -and $budget.InputBytes -eq 0)
}
$budget = [TriageApplicationLab.HostedTuiInputBudget]::new()
for ($i=0; $i -lt 16; $i++) { $budget.ReserveResize(80,24) }
Check ($budget.ResizeCount -eq 16)
Reject { $budget.ReserveResize(120,34) }
Reject { $budget.ReserveInput(1) }
Check ($budget.ResizeCount -eq 16)
$budget = [TriageApplicationLab.HostedTuiInputBudget]::new()
Reject { $budget.ReserveResize(80,34) }
Reject { $budget.ReserveResize(120,34) }
Check ($budget.ResizeCount -eq 0)

$wire = '{"action":"ready"}' + "`n" + '{"action":"poll"}' + "`r`n"
$reader = [IO.StringReader]::new($wire)
$protocol = [TriageApplicationLab.HostedTuiProtocol]::new()
Check ($protocol.Read($reader)['action'] -ceq 'ready')
Check ($protocol.CommandCount -eq 1 -and $protocol.RequestBytes -eq 19)
Check ($protocol.Read($reader)['action'] -ceq 'poll')
Check ($protocol.CommandCount -eq 2 -and $protocol.RequestBytes -eq $wire.Length)
Check ($null -eq $protocol.Read($reader))
$request = [TriageApplicationLab.HostedProtocol]::Parse('{"action":"key","key":"enter"}')
[TriageApplicationLab.HostedProtocol]::Keys($request, 'action,key')
Check ($request['key'] -ceq 'enter')
foreach ($json in @('{"action":"key","key":"enter","repeat":2}', '{"action":"key","Key":"enter"}',
                     '{"action":"text","text":"x","extra":1}', '{"action":"resize","columns":80,"rows":24,"extra":1}')) {
    $parsed = [TriageApplicationLab.HostedProtocol]::Parse($json)
    $shape = switch ($parsed['action']) { 'key' {'action,key'} 'text' {'action,text'} 'resize' {'action,columns,rows'} }
    Reject { [TriageApplicationLab.HostedProtocol]::Keys($parsed, $shape) }
}
foreach ($json in @('{"action":"resize","columns":true,"rows":24}', '{"action":"resize","columns":80.0,"rows":24}',
                     '{"action":"key","key":"enter","key":"escape"}', '{"action":"text","text":"\u001b"}')) {
    $protocol = [TriageApplicationLab.HostedTuiProtocol]::new()
    Reject { $protocol.Read([IO.StringReader]::new($json + "`n")) }
    Reject { $protocol.Read([IO.StringReader]::new('{"action":"poll"}' + "`n")) }
}
foreach ($json in @('{"action":"resize","columns":"80","rows":24}', '{"action":"resize","columns":-1,"rows":24}')) {
    $parsed = [TriageApplicationLab.HostedProtocol]::Parse($json)
    Reject { [TriageApplicationLab.HostedProtocol]::Integer($parsed, 'columns') }
}
foreach ($wire in @('{"action":"poll"}', ((' ' * 65537) + "`n"), ('{"action":"text","text":"' + [char]160 + '"}' + "`n"))) {
    $protocol = [TriageApplicationLab.HostedTuiProtocol]::new()
    Reject { $protocol.Read([IO.StringReader]::new($wire)) }
    Reject { $protocol.Read([IO.StringReader]::new('{"action":"poll"}' + "`n")) }
    Check ($protocol.CommandCount -le 1024 -and $protocol.RequestBytes -le 1048576)
}
$protocol = [TriageApplicationLab.HostedTuiProtocol]::new()
$line = '{"action":"poll"}' + "`n"
$reader = [IO.StringReader]::new($line * 1025)
for ($i=0; $i -lt 1024; $i++) { $null = $protocol.Read($reader) }
Check ($protocol.CommandCount -eq 1024)
Reject { $protocol.Read($reader) }
Check ($protocol.CommandCount -eq 1024)
$prefix = '{"action":"text","text":"'; $suffix = '"}'
$line = $prefix + ('x' * (65535-$prefix.Length-$suffix.Length)) + $suffix + "`n"
Check ($line.Length -eq 65536)
$reader = [IO.StringReader]::new(($line * 16) + '{"action":"poll"}' + "`n")
$protocol = [TriageApplicationLab.HostedTuiProtocol]::new()
for ($i=0; $i -lt 16; $i++) { $null = $protocol.Read($reader) }
Check ($protocol.CommandCount -eq 16 -and $protocol.RequestBytes -eq 1048576)
Reject { $protocol.Read($reader) }
Check ($protocol.CommandCount -eq 16 -and $protocol.RequestBytes -eq 1048576)
$failure = $protocol.Failure()
Check ($failure['schema_version'] -eq 2 -and $failure['ok'] -eq $false -and $failure['state'] -ceq 'finished')
Check ($failure['protocol_commands'] -eq 16 -and $failure['protocol_bytes'] -eq 1048576)
Check ($failure['input_commands'] -eq 0 -and $failure['input_bytes'] -eq 0 -and $failure['resize_count'] -eq 0)
Check ($failure['columns'] -eq 120 -and $failure['rows'] -eq 34)
$legacy = [TriageApplicationLab.HostedProtocol]::Failure()
Check ($legacy['schema_version'] -eq 1 -and -not $legacy.ContainsKey('input_commands') -and -not $legacy.ContainsKey('protocol_bytes'))
Check ($failure.Count -eq $legacy.Count + 7)

# Parse bridge source as data. Never dot-source or execute either bridge.
$bridge = [IO.File]::ReadAllText((Join-Path $root 'application-lab/hosted_tui_session.ps1'))
$tokens = $null; $errors = $null
$null = [Management.Automation.Language.Parser]::ParseInput($bridge, [ref]$tokens, [ref]$errors)
Check ($errors.Count -eq 0)
Check ($bridge.IndexOf("`$env:RUNNER_ENVIRONMENT -cne 'github-hosted'") -ge 0)
Check ($bridge.IndexOf("throw 'hosted_only'") -lt $bridge.IndexOf('Add-Type -Path'))
Check ($bridge.IndexOf('$request = $protocol.Read([Console]::In)') -lt $bridge.IndexOf('switch -CaseSensitive ($action)'))
$actions = @([regex]::Matches($bridge, "(?m)^\s*'([a-z_]+)' \{") | ForEach-Object { $_.Groups[1].Value })
Check (($actions -join ',') -ceq 'ready,start,close_ready,poll,observe_runtime,key,text,resize,ctrl_c,finish')
Check ($bridge.Contains('[TriageApplicationLab.HostedConPtySession]::StartTui(') -and -not $bridge.Contains(']::Start('))
Check ($bridge.Contains('$session.SendCtrlCOnce()') -and $bridge.Contains('$session.Abort()'))
Check ($bridge.Contains('application_bridge_stage=compile') -and $bridge.Contains('application_bridge_stage=compiled'))
Check ($source.Contains('maxOutputBytes<=8388608') -and $source.Contains('deadlineMilliseconds<=180000'))
Check ($source.Contains('if(tui) transcript.Flush();'))
$ctrl = [regex]::Match($source, '(?s)public Dictionary<string,object> SendCtrlCOnce\(\) \{(.*?)public Dictionary<string,object> Abort\(')
Check ($ctrl.Success -and $ctrl.Groups[1].Value.Contains('!runtimeObserved'))
$live = [regex]::Match($source, '(?s)void RequireTuiLive\(\) \{(.*?)Dictionary<string,object> TuiFailure')
Check ($live.Success -and -not $live.Groups[1].Value.Contains('runtimeObserved'))
Check ($live.Groups[1].Value.Contains('IsProcessInJob') -and $live.Groups[1].Value.Contains('errors.Count==0'))
Check ($source.IndexOf('if(resizer!=null && !resizer.Join(1000))') -lt $source.IndexOf('if(console!=IntPtr.Zero) { ClosePseudoConsole(console)'))
[pscustomobject]@{ result='passed'; checks=$script:passed; native_executed=$false } | ConvertTo-Json -Compress
