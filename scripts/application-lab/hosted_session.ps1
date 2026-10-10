# Dedicated hosted Windows acceptance bridge. Never invoke locally to launch an app.
# One bounded strict JSON command and one finite JSON response per line.
[CmdletBinding()]
param()
Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
$session = $null
$ready = $false
$observed = $false
$action = 'invalid'
function Get-SessionResponse($Value, [bool]$Observed, [string]$Operation, [int]$Grace = 0) {
    if ($Operation -ceq 'poll') { $reply = $Value.Poll() }
    elseif ($Operation -ceq 'finish') { $reply = $Value.Finish($Grace) }
    elseif ($Operation -ceq 'abort') { $reply = $Value.Abort() }
    else { throw 'protocol_invalid' }
    if ($Observed) { return $Value.LaunchSnapshot() }
    return $reply
}
function Add-ObservedFailureFields($Value) {
    $Value['schema_version'] = 3
    foreach ($item in @(@('observation_kind','launch_image'), @('launch_image_observed',$false), @('launch_sha256',$null),
        @('runtime_launch_count',0), @('peak_runtime_processes',0), @('debug_event_count',0),
        @('debug_events_drained',$false), @('debug_pump_joined',$false), @('debug_handles_closed',$false),
        @('system_helper_image_observed',$false), @('system_helper_sha256',$null), @('system_helper_launch_count',0),
        @('peak_system_helper_processes',0), @('system_helper_reference_closed',$false))) { $Value[$item[0]]=$item[1] }
    return $Value
}
try {
    if ($env:GITHUB_ACTIONS -cne 'true' -or $env:RUNNER_OS -cne 'Windows' -or
        $env:RUNNER_ENVIRONMENT -cne 'github-hosted' -or $PSVersionTable.PSEdition -cne 'Desktop') { throw 'hosted_only' }
    [Console]::Error.WriteLine('application_bridge_stage=compile')
    [Console]::Error.Flush()
    Add-Type -Path (Join-Path $PSScriptRoot 'HostedConPtySession.cs') -ErrorAction Stop
    [Console]::Error.WriteLine('application_bridge_stage=compiled')
    [Console]::Error.Flush()
    while ($true) {
        $request = [TriageApplicationLab.HostedProtocol]::Read([Console]::In)
        if ($null -eq $request) {
            if ($null -ne $session) {
                $result = Get-SessionResponse $session $observed 'abort'
                $result['action'] = 'eof'
                [Console]::Out.WriteLine(($result | ConvertTo-Json -Depth 4 -Compress))
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
                $session = [TriageApplicationLab.HostedConPtySession]::Start(
                    [TriageApplicationLab.HostedProtocol]::Text($request, 'app_path'),
                    [TriageApplicationLab.HostedProtocol]::Text($request, 'app_sha256'),
                    [TriageApplicationLab.HostedProtocol]::Arguments($request),
                    [TriageApplicationLab.HostedProtocol]::Text($request, 'case_root'),
                    [TriageApplicationLab.HostedProtocol]::EnvironmentMap($request),
                    [TriageApplicationLab.HostedProtocol]::Text($request, 'transcript_path'),
                    [TriageApplicationLab.HostedProtocol]::Integer($request, 'max_output_bytes'),
                    [TriageApplicationLab.HostedProtocol]::Integer($request, 'deadline_ms'),
                    [TriageApplicationLab.HostedProtocol]::RuntimeProcessLimit($request))
                $result = $session.Poll()
            }
            'close_ready' {
                [TriageApplicationLab.HostedProtocol]::Keys($request, 'action')
                if (-not $ready -or $null -ne $session) { throw 'protocol_invalid' }
                $ready = $false
                $result = @{ schema_version=1; ok=$true; state='closed' }
            }
            'start_source' {
                if (-not $ready -or $null -ne $session) { throw 'protocol_invalid' }
                [TriageApplicationLab.HostedProtocol]::Keys($request, 'action,app_path,app_sha256,args,case_root,environment,transcript_path,max_output_bytes,deadline_ms,max_runtime_processes')
                $session = [TriageApplicationLab.HostedConPtySession]::StartSource(
                    [TriageApplicationLab.HostedProtocol]::Text($request, 'app_path'),
                    [TriageApplicationLab.HostedProtocol]::Text($request, 'app_sha256'),
                    [TriageApplicationLab.HostedProtocol]::Arguments($request),
                    [TriageApplicationLab.HostedProtocol]::Text($request, 'case_root'),
                    [TriageApplicationLab.HostedProtocol]::EnvironmentMap($request),
                    [TriageApplicationLab.HostedProtocol]::Text($request, 'transcript_path'),
                    [TriageApplicationLab.HostedProtocol]::Integer($request, 'max_output_bytes'),
                    [TriageApplicationLab.HostedProtocol]::Integer($request, 'deadline_ms'),
                    [TriageApplicationLab.HostedProtocol]::RuntimeProcessLimit($request))
                $result = $session.Poll()
            }
            'start_source_observed' {
                if (-not $ready -or $null -ne $session) { throw 'protocol_invalid' }
                $observed = $true
                [TriageApplicationLab.HostedProtocol]::Keys($request, 'action,app_path,app_sha256,args,case_root,environment,transcript_path,max_output_bytes,deadline_ms,max_runtime_processes,expected_runtime_sha256,max_runtime_launches')
                $runtimeHash = [TriageApplicationLab.HostedProtocol]::Text($request, 'expected_runtime_sha256')
                $launches = [TriageApplicationLab.HostedProtocol]::Integer($request, 'max_runtime_launches')
                if ($runtimeHash -cnotmatch '\A[0-9a-f]{64}\z' -or $launches -lt 1 -or $launches -gt 32) { throw 'protocol_invalid' }
                $session = [TriageApplicationLab.HostedConPtySession]::StartSourceObserved(
                    [TriageApplicationLab.HostedProtocol]::Text($request, 'app_path'),
                    [TriageApplicationLab.HostedProtocol]::Text($request, 'app_sha256'),
                    [TriageApplicationLab.HostedProtocol]::Arguments($request),
                    [TriageApplicationLab.HostedProtocol]::Text($request, 'case_root'),
                    [TriageApplicationLab.HostedProtocol]::EnvironmentMap($request),
                    [TriageApplicationLab.HostedProtocol]::Text($request, 'transcript_path'),
                    [TriageApplicationLab.HostedProtocol]::Integer($request, 'max_output_bytes'),
                    [TriageApplicationLab.HostedProtocol]::Integer($request, 'deadline_ms'),
                    [TriageApplicationLab.HostedProtocol]::RuntimeProcessLimit($request), $runtimeHash, $launches)
                $result = Get-SessionResponse $session $observed 'poll'
            }
            'poll' {
                [TriageApplicationLab.HostedProtocol]::Keys($request, 'action')
                if ($null -eq $session) { throw 'protocol_invalid' }
                $result = Get-SessionResponse $session $observed 'poll'
            }
            'observe_runtime' {
                [TriageApplicationLab.HostedProtocol]::Keys($request, 'action,extraction_root,expected_sha256')
                if ($null -eq $session -or $observed) { throw 'protocol_invalid' }
                $result = $session.ObserveOwnedRuntime(
                    [TriageApplicationLab.HostedProtocol]::Text($request, 'extraction_root'),
                    [TriageApplicationLab.HostedProtocol]::Text($request, 'expected_sha256'))
            }
            'ctrl_c' {
                [TriageApplicationLab.HostedProtocol]::Keys($request, 'action')
                if ($null -eq $session -or $observed) { throw 'protocol_invalid' }
                $result = $session.SendCtrlCOnce()
            }
            'finish' {
                [TriageApplicationLab.HostedProtocol]::Keys($request, 'action,grace_ms')
                if ($null -eq $session) { throw 'protocol_invalid' }
                $result = Get-SessionResponse $session $observed 'finish' ([TriageApplicationLab.HostedProtocol]::Integer($request, 'grace_ms'))
            }
            default { $action = 'invalid'; throw 'protocol_invalid' }
        }
        $result['action'] = $action
        [Console]::Out.WriteLine(($result | ConvertTo-Json -Depth 4 -Compress))
        [Console]::Out.Flush()
        if ($result['state'] -eq 'finished' -or $result['state'] -eq 'closed') { break }
    }
} catch {
    if ($null -ne $session) { $result = Get-SessionResponse $session $observed 'abort' }
    else {
        $result = @{ schema_version=1; action='invalid'; ok=$false; state='finished'; app_exit_code=$null;
            runtime_image_observed=$false; runtime_sha256=$null; runtime_process_count=$null; ctrl_c_sent=$false; output_bytes=0;
            output_limit_exceeded=$false; forced_termination=$false; app_exited=$false;
            observed_children_exited=$false; job_zero_confirmed=$false; reader_joined=$false;
            conpty_closed=$false; errors=@('protocol_invalid') }
        if ($observed) { $result = Add-ObservedFailureFields $result }
    }
    $result['action'] = 'invalid'
    [Console]::Out.WriteLine(($result | ConvertTo-Json -Depth 4 -Compress))
    [Console]::Out.Flush()
} finally {
    if ($null -ne $session) { $session.Dispose() }
}
