# Separate hosted TUI bridge. Never invoke locally to launch an application.
# Closed input/resize actions; private transcript bytes never enter responses.
[CmdletBinding()]
param()
Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
$session = $null
$protocol = $null
$ready = $false
$action = 'invalid'
try {
    if ($env:GITHUB_ACTIONS -cne 'true' -or $env:RUNNER_OS -cne 'Windows' -or
        $env:RUNNER_ENVIRONMENT -cne 'github-hosted' -or $PSVersionTable.PSEdition -cne 'Desktop') { throw 'hosted_only' }
    [Console]::Error.WriteLine('application_bridge_stage=compile')
    [Console]::Error.Flush()
    Add-Type -Path (Join-Path $PSScriptRoot 'HostedConPtySession.cs') -ErrorAction Stop
    [Console]::Error.WriteLine('application_bridge_stage=compiled')
    [Console]::Error.Flush()
    $protocol = [TriageApplicationLab.HostedTuiProtocol]::new()
    while ($true) {
        # Budgets apply before parsing, dispatch, or any native session action.
        $request = $protocol.Read([Console]::In)
        if ($null -eq $request) {
            if ($null -ne $session) {
                $null = $session.Abort()
                $result = $protocol.Counters($session.TuiSnapshot())
                $result['action'] = 'eof'
                [Console]::Out.WriteLine(($result | ConvertTo-Json -Depth 4 -Compress))
                [Console]::Out.Flush()
            }
            break
        }
        $action = [TriageApplicationLab.HostedProtocol]::Text($request, 'action')
        switch -CaseSensitive ($action) {
            'ready' {
                [TriageApplicationLab.HostedProtocol]::Keys($request, 'action')
                if ($ready -or $null -ne $session) { throw 'protocol_invalid' }
                $ready = $true
                $result = @{ schema_version=1; ok=$true; state='ready' }
            }
            'start' {
                if (-not $ready -or $null -ne $session) { throw 'protocol_invalid' }
                [TriageApplicationLab.HostedProtocol]::Keys($request, 'action,app_path,app_sha256,args,case_root,environment,transcript_path,max_output_bytes,deadline_ms,max_runtime_processes')
                $session = [TriageApplicationLab.HostedConPtySession]::StartTui(
                    [TriageApplicationLab.HostedProtocol]::Text($request, 'app_path'),
                    [TriageApplicationLab.HostedProtocol]::Text($request, 'app_sha256'),
                    [TriageApplicationLab.HostedProtocol]::Arguments($request),
                    [TriageApplicationLab.HostedProtocol]::Text($request, 'case_root'),
                    [TriageApplicationLab.HostedProtocol]::EnvironmentMap($request),
                    [TriageApplicationLab.HostedProtocol]::Text($request, 'transcript_path'),
                    [TriageApplicationLab.HostedProtocol]::Integer($request, 'max_output_bytes'),
                    [TriageApplicationLab.HostedProtocol]::Integer($request, 'deadline_ms'),
                    [TriageApplicationLab.HostedProtocol]::RuntimeProcessLimit($request))
                $null = $session.Poll()
                $result = $session.TuiSnapshot()
            }
            'close_ready' {
                [TriageApplicationLab.HostedProtocol]::Keys($request, 'action')
                if (-not $ready -or $null -ne $session) { throw 'protocol_invalid' }
                $ready = $false
                $result = @{ schema_version=1; ok=$true; state='closed' }
            }
            'poll' {
                [TriageApplicationLab.HostedProtocol]::Keys($request, 'action')
                if ($null -eq $session) { throw 'protocol_invalid' }
                $null = $session.Poll()
                $result = $session.TuiSnapshot()
            }
            'observe_runtime' {
                [TriageApplicationLab.HostedProtocol]::Keys($request, 'action,extraction_root,expected_sha256')
                if ($null -eq $session) { throw 'protocol_invalid' }
                $null = $session.ObserveOwnedRuntime(
                    [TriageApplicationLab.HostedProtocol]::Text($request, 'extraction_root'),
                    [TriageApplicationLab.HostedProtocol]::Text($request, 'expected_sha256'))
                $result = $session.TuiSnapshot()
            }
            'key' {
                [TriageApplicationLab.HostedProtocol]::Keys($request, 'action,key')
                if ($null -eq $session) { throw 'protocol_invalid' }
                $result = $session.SendTuiKey([TriageApplicationLab.HostedProtocol]::Text($request, 'key'))
            }
            'text' {
                [TriageApplicationLab.HostedProtocol]::Keys($request, 'action,text')
                if ($null -eq $session) { throw 'protocol_invalid' }
                $result = $session.SendTuiText([TriageApplicationLab.HostedProtocol]::Text($request, 'text'))
            }
            'resize' {
                [TriageApplicationLab.HostedProtocol]::Keys($request, 'action,columns,rows')
                if ($null -eq $session) { throw 'protocol_invalid' }
                $result = $session.ResizeTui(
                    [TriageApplicationLab.HostedProtocol]::Integer($request, 'columns'),
                    [TriageApplicationLab.HostedProtocol]::Integer($request, 'rows'))
            }
            'ctrl_c' {
                [TriageApplicationLab.HostedProtocol]::Keys($request, 'action')
                if ($null -eq $session) { throw 'protocol_invalid' }
                $null = $session.SendCtrlCOnce()
                $result = $session.TuiSnapshot()
            }
            'finish' {
                [TriageApplicationLab.HostedProtocol]::Keys($request, 'action,grace_ms')
                if ($null -eq $session) { throw 'protocol_invalid' }
                $null = $session.Finish([TriageApplicationLab.HostedProtocol]::Integer($request, 'grace_ms'))
                $result = $session.TuiSnapshot()
            }
            default { $action = 'invalid'; throw 'protocol_invalid' }
        }
        if ($result['schema_version'] -eq 2) { $result = $protocol.Counters($result) }
        $result['action'] = $action
        [Console]::Out.WriteLine(($result | ConvertTo-Json -Depth 4 -Compress))
        [Console]::Out.Flush()
        if ($result['state'] -eq 'finished' -or $result['state'] -eq 'closed') { break }
    }
} catch {
    if ($null -ne $session) {
        $null = $session.Abort()
        $result = $protocol.Counters($session.TuiSnapshot())
    } elseif ($null -ne $protocol) { $result = $protocol.Failure() }
    else {
        $result = @{ schema_version=2; ok=$false; state='finished'; app_exit_code=$null;
            runtime_image_observed=$false; runtime_sha256=$null; runtime_process_count=$null; ctrl_c_sent=$false; output_bytes=0;
            output_limit_exceeded=$false; forced_termination=$false; app_exited=$false;
            observed_children_exited=$false; job_zero_confirmed=$false; reader_joined=$false;
            conpty_closed=$false; errors=@('protocol_invalid'); input_commands=0; input_bytes=0; resize_count=0;
            columns=120; rows=34; protocol_commands=0; protocol_bytes=0 }
    }
    $result['action'] = 'invalid'
    [Console]::Out.WriteLine(($result | ConvertTo-Json -Depth 4 -Compress))
    [Console]::Out.Flush()
} finally {
    if ($null -ne $session) { $session.Dispose() }
}
