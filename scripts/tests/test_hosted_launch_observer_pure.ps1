# Managed state/ABI tests only. Never starts a session or invokes Win32 APIs.
Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
$script:passed = 0
function Check([bool]$Value) { if (-not $Value) { throw 'pure_assertion_failed' }; $script:passed++ }
function Reject([scriptblock]$Action) {
    $rejected = $false
    try { & $Action | Out-Null } catch { $rejected = $true }
    Check $rejected
}
function State([int]$Concurrent = 1, [int]$Launches = 2) {
    $state = [TriageApplicationLab.HostedLaunchState]::new($Concurrent, $Launches)
    $state.SetRoot(10)
    return $state
}
function Create($State, [uint32]$PidValue, [uint32]$TidValue, [bool]$Runtime) {
    $State.Begin(3, $PidValue, $TidValue); $State.Create($Runtime); $State.Continued()
}
function Breakpoint($State, [uint32]$PidValue, [uint32]$TidValue) {
    $State.Begin(1, $PidValue, $TidValue)
    Check ($State.ExceptionDisposition([uint32]2147483651, 1) -eq 65538)
    $State.Continued()
}
function ExitProcess($State, [uint32]$PidValue, [uint32]$TidValue) {
    $State.Begin(5, $PidValue, $TidValue); $State.Continued()
}

try {
    $source = Join-Path (Split-Path -Parent $PSScriptRoot) 'application-lab/HostedConPtySession.cs'
    Check ((Get-Item -LiteralPath $source).Length -gt 0 -and (Get-Item -LiteralPath $source).Length -le 131072)
    if ($null -eq ('TriageApplicationLab.HostedLaunchState' -as [type])) {
        Add-Type -Path $source -ErrorAction Stop -WarningAction SilentlyContinue 2>$null
    }
    # These calls inspect native declarations' managed layouts; they never call
    # WaitForDebugEvent, CreateProcess or any session/lease method.
    $layout = [TriageApplicationLab.HostedConPtySession]::LaunchDebugLayout()
    Check ($layout.Count -eq 7 -and $layout.pointer -eq [IntPtr]::Size)
    if ([IntPtr]::Size -eq 8) {
        Check ($layout.event_size -eq 176 -and $layout.union_offset -eq 16)
        Check ($layout.create_size -eq 72 -and $layout.create_process_offset -eq 8 -and $layout.create_thread_offset -eq 16)
        Check ($layout.exception_first_offset -eq 152)
        $high = [IntPtr]::new([int64]1311768467750121217)
    } else {
        Check ($layout.event_size -eq 96 -and $layout.union_offset -eq 12)
        Check ($layout.create_size -eq 40 -and $layout.create_process_offset -eq 4 -and $layout.create_thread_offset -eq 8)
        Check ($layout.exception_first_offset -eq 80)
        $high = [IntPtr]::new(-2147483000)
    }
    Check ([TriageApplicationLab.HostedLaunchState]::EventOwnsCreationHandle($high, $high))
    Check (-not [TriageApplicationLab.HostedLaunchState]::EventOwnsCreationHandle($high, [IntPtr]::new(31)))
    foreach ($invalid in @([IntPtr]::Zero, [IntPtr]::new(-1))) {
        Reject { [TriageApplicationLab.HostedLaunchState]::EventOwnsCreationHandle($invalid, $high) }
        Reject { [TriageApplicationLab.HostedLaunchState]::EventOwnsCreationHandle($high, $invalid) }
    }
    $method = [TriageApplicationLab.HostedConPtySession].GetMethod('StartSourceObserved')
    $parameters = $method.GetParameters()
    Check ($method.ReturnType -eq [TriageApplicationLab.HostedConPtySession] -and $parameters.Count -eq 11)
    Check ($parameters[9].ParameterType -eq [string] -and $parameters[10].ParameterType -eq [int])
    foreach ($name in @('Start', 'StartSource', 'StartTui')) {
        Check ([TriageApplicationLab.HostedConPtySession].GetMethod($name).GetParameters().Count -eq 9)
    }
    $diagnosticMethod = [TriageApplicationLab.HostedConPtySession].GetMethod('LaunchFailureDiagnostic')
    Check ($diagnosticMethod.GetParameters().Count -eq 0 -and $diagnosticMethod.ReturnType -eq [Collections.Generic.Dictionary[string,object]])

    $root = 'C:\owned\case'
    Check ([TriageApplicationLab.HostedLaunchState]::RuntimeTempPath($root) -ceq 'C:\owned\case\temp')
    Check ([TriageApplicationLab.HostedLaunchState]::RuntimeImagePathAllowed($root, 'C:\owned\case\temp\rclone-triage-launch1\rclone.exe'))
    foreach ($invalid in @('C:\owned\case\rclone.exe', 'C:\outside\temp\rclone-triage-one\rclone.exe',
            'C:\owned\case\temp\.rclone-triage-one\rclone.exe', 'C:\owned\case\temp\rclone-triage-\rclone.exe',
            'C:\owned\case\temp\rclone-triage-one\other.exe', 'C:\owned\case\temp\rclone-triage-one\RCLONE.EXE',
            'C:\owned\case\temp\rclone-triage-one\nested\rclone.exe', 'C:\owned\case\temp\rclone-triage-one\..\rclone.exe',
            'C:\owned\case\temp\rclone-triage-one \rclone.exe', 'C:\owned\case\temp\rclone-triage-one\rclone.exe:stream')) {
        Check (-not [TriageApplicationLab.HostedLaunchState]::RuntimeImagePathAllowed($root, $invalid))
    }
    foreach ($limits in @(@(0, 1), @(5, 1), @(1, 0), @(1, 33))) {
        Reject { [TriageApplicationLab.HostedLaunchState]::new($limits[0], $limits[1]) }
    }
    # Only exact known location categories escape; a basename or common prefix
    # never blesses an unexpected process, and no classification grants admission.
    $application = 'C:\owned\case\application.exe'
    $systemDirectory = 'C:\Windows\System32'
    $roleCases = @(
        @($application, 'application_path'),
        @('C:\owned\case\APPLICATION.EXE', 'application_path'),
        @('C:\owned\case\temp\rclone-triage-launch1\rclone.exe', 'runtime_path'),
        @('C:\Windows\System32\conhost.exe', 'system_console_host'),
        @('C:\WINDOWS\SYSTEM32\CONHOST.EXE', 'system_console_host'),
        @('C:\owned\case\conhost.exe', 'other'),
        @('C:\Windows\System32-other\conhost.exe', 'other'),
        @('C:\Windows\System32\conhost.exe.other', 'other'),
        @('C:\owned\case\temp\other\rclone.exe', 'other'),
        @('C:\owned\case-other\application.exe', 'other'),
        @('C:\outside\private-path-or-secret.exe', 'other'),
        @('C:\owned\case\temp\rclone-triage-one\..\rclone.exe', 'unavailable'),
        @('relative.exe', 'unavailable'), @('', 'unavailable'),
        @("C:\owned\case\bad`nname.exe", 'unavailable')
    )
    foreach ($item in $roleCases) {
        Check ([TriageApplicationLab.HostedLaunchState]::FailureImageRole($root, $application, $systemDirectory, $item[0]) -ceq $item[1])
    }
    $expectedKeys = @('schema_version', 'event_ordinal', 'image_role', 'owned_job', 'image_path_matches') | Sort-Object
    foreach ($role in @('application_path', 'runtime_path', 'system_console_host', 'other', 'unavailable')) {
        $record = [TriageApplicationLab.HostedLaunchState]::CreateFailureDiagnostic(57, $role, $null, $null)
        Check (($record.Keys | Sort-Object) -join ',' -ceq ($expectedKeys -join ','))
        Check ($record.schema_version -is [int] -and $record.schema_version -eq 1 -and $record.event_ordinal -is [int] -and $record.event_ordinal -eq 57)
        Check ($record.image_role -ceq $role -and $null -eq $record.owned_job -and $null -eq $record.image_path_matches)
    }
    foreach ($flags in @(@($true, $false), @($false, $true))) {
        $record = [TriageApplicationLab.HostedLaunchState]::CreateFailureDiagnostic(4096, 'other', $flags[0], $flags[1])
        Check ($record.owned_job -is [bool] -and $record.owned_job -eq $flags[0] -and $record.image_path_matches -is [bool] -and $record.image_path_matches -eq $flags[1])
    }
    foreach ($ordinal in @(0, -1, 4097)) { Reject { [TriageApplicationLab.HostedLaunchState]::CreateFailureDiagnostic($ordinal, 'other', $null, $null) } }
    foreach ($role in @('', 'Runtime_path', 'conhost.exe', 'private-path-or-secret')) {
        Reject { [TriageApplicationLab.HostedLaunchState]::CreateFailureDiagnostic(1, $role, $null, $null) }
    }
    $state = State 1 1; Create $state 10 100 $false; Create $state 20 200 $true
    $state.Begin(3, 30, 300); Reject { $state.Create($true) }
    $null = [TriageApplicationLab.HostedLaunchState]::CreateFailureDiagnostic($state.Events, 'system_console_host', $true, $true)
    Check ($state.Failure -ceq 'debug_launch_limit' -and $state.Launches -eq 2 -and $state.Peak -eq 2 -and -not $state.Qualified)
    # A late creator cannot admit Create/Resume after Finish has stopped startup.
    # Stopping is monotone and also applies before a root process is registered.
    $state = [TriageApplicationLab.HostedLaunchState]::new(1, 1)
    $state.CheckStarting($false, $false)
    $state.StopStarting(); $state.StopStarting()
    Reject { $state.CheckStarting($false, $false) }
    Check ($state.Failure -ceq 'debug_start_failed' -and $state.Launches -eq 0)
    foreach ($stop in @(@($true, $false), @($false, $true))) {
        $state = State
        Reject { $state.CheckStarting($stop[0], $stop[1]) }
        Reject { $state.CheckStarting($false, $false) }
        Check ($state.Failure -ceq 'debug_start_failed')
    }
    # A source lease's failed unwind is distinct from an image mismatch. The
    # pure model used by the pump makes cleanup uncertainty permanent and emits
    # only the existing closed categories, never the primary diagnostic text.
    $primary = [InvalidOperationException]::new('private-path-or-secret')
    $state = State
    $codes = $state.ObserveSourceFailure($primary)
    Check ($codes.Length -eq 0 -and -not $state.CleanupUncertain -and $null -eq $state.Failure)
    $invalid = [InvalidOperationException]::new('source_directory_invalid', $primary)
    $codes = $state.ObserveSourceFailure($invalid)
    Check ($codes.Length -eq 1 -and $codes[0] -ceq 'source_directory_invalid' -and -not $state.CleanupUncertain)
    $cleanup = [InvalidOperationException]::new('source_directory_cleanup_failed', $invalid)
    $codes = $state.ObserveSourceFailure($cleanup)
    Check ($codes.Length -eq 2 -and $codes[0] -ceq 'source_directory_cleanup_failed' -and $codes[1] -ceq 'source_directory_invalid')
    Check ($state.CleanupUncertain -and $state.Failure -ceq 'debug_cleanup_failed')
    $null = $state.ObserveSourceFailure($primary)
    Check ($state.CleanupUncertain -and $state.Failure -ceq 'debug_cleanup_failed')
    $state = State; $state.Fail('debug_image_invalid')
    $null = $state.ObserveSourceFailure($cleanup)
    Check ($state.CleanupUncertain -and $state.Failure -ceq 'debug_image_invalid')

    $state = State 1 1
    Create $state 10 100 $false; Breakpoint $state 10 100
    Create $state 20 200 $true; Breakpoint $state 20 200
    Check ($state.Launches -eq 1 -and $state.Peak -eq 1 -and -not $state.Drained -and -not $state.Qualified)
    ExitProcess $state 20 200; ExitProcess $state 10 100
    Check ($state.Qualified -and $state.Drained -and $state.Events -eq 6 -and $null -eq $state.Failure)

    $state = State 1 2
    Create $state 10 100 $false; Breakpoint $state 10 100
    foreach ($item in @(20, 30)) {
        Create $state $item ($item * 10) $true; Breakpoint $state $item ($item * 10)
        ExitProcess $state $item ($item * 10)
    }
    ExitProcess $state 10 100
    Check ($state.Qualified -and $state.Launches -eq 2 -and $state.Peak -eq 1 -and $state.Events -eq 9)

    $state = State 2 2
    Create $state 10 100 $false; Breakpoint $state 10 100
    Create $state 20 200 $true; Breakpoint $state 20 200
    Create $state 30 300 $true; Breakpoint $state 30 300
    ExitProcess $state 10 100
    Check (-not $state.Drained) # Root exit never proves descendants drained.
    ExitProcess $state 30 300; ExitProcess $state 20 200
    Check ($state.Qualified -and $state.Peak -eq 2)

    # Limit errors preserve recorded processes so a failed experiment can still
    # prove its subsequent continuation/reap sequence without becoming eligible.
    $state = State 1 1
    Create $state 10 100 $false; Breakpoint $state 10 100
    Create $state 20 200 $true; Breakpoint $state 20 200; ExitProcess $state 20 200
    $state.Begin(3, 30, 300); Reject { $state.Create($true) }; $state.Continued()
    Check ($state.Failure -ceq 'debug_launch_limit' -and $state.Launches -eq 2)
    ExitProcess $state 30 300; ExitProcess $state 10 100
    Check ($state.Drained -and -not $state.Qualified)
    $state.Fail('debug_cleanup_failed'); Check ($state.Failure -ceq 'debug_launch_limit')

    $state = State 1 2; Create $state 10 100 $false; Create $state 20 200 $true
    $state.Begin(3, 30, 300); Reject { $state.Create($true) }
    Check ($state.Failure -ceq 'debug_launch_limit' -and $state.Peak -eq 2)
    $state = State; Create $state 10 100 $false
    $state.Begin(5, 10, 100); Check (-not $state.Drained)
    Reject { $state.Begin(8, 10, 100) }; Check (-not $state.Qualified)
    $state = State; Create $state 10 100 $false; ExitProcess $state 10 100
    Reject { $state.Begin(3, 10, 101) } # Never accept recycled PID identity.
    $state = State; Create $state 10 100 $false
    Reject { $state.Begin(8, 99, 999) }
    $state = State; Reject { $state.Continued() }
    $state = State; Reject { $state.SetRoot(11) }
    $state = State; $state.Begin(3, 10, 100); Reject { $state.Create($true) }
    foreach ($code in @(0, 10)) { $state = State; Reject { $state.Begin($code, 10, 100) } }

    $state = State; Create $state 10 100 $false; Breakpoint $state 10 100
    $state.Begin(1, 10, 100)
    Check ($state.ExceptionDisposition([uint32]3762504530, 1) -eq [uint32]2147549185 -and $null -eq $state.Failure)
    $state.Continued(); $state.Begin(1, 10, 100)
    Check ($state.ExceptionDisposition([uint32]2147483651, 1) -eq [uint32]2147549185 -and $state.Failure -ceq 'debug_exception_failed')
    $state = State; Create $state 10 100 $false; $state.Begin(1, 10, 101)
    Check ($state.ExceptionDisposition([uint32]2147483651, 1) -eq [uint32]2147549185 -and $state.Failure -ceq 'debug_exception_failed')
    $state = State; Create $state 10 100 $false; $state.Begin(1, 10, 100)
    Check ($state.ExceptionDisposition([uint32]3221225477, 0) -eq [uint32]2147549185 -and $state.Failure -ceq 'debug_exception_failed')
    $state = State; Create $state 10 100 $false; $state.Begin(1, 10, 100)
    Reject { $state.ExceptionDisposition([uint32]2147483651, 2) }
    $state = State; Create $state 10 100 $false
    for ($i=1; $i -lt 4096; $i++) { $state.Begin(8, 10, 100); $state.Continued() }
    Check ($state.Events -eq 4096); Reject { $state.Begin(8, 10, 100) }
    Check ($state.Failure -ceq 'debug_event_limit' -and -not $state.Drained)
    Reject { $state.Fail('private-path-or-secret') }
    [pscustomobject]@{ scope='hosted_launch_observer_pure'; result='passed'; checks=$script:passed; native_session_executed=$false } | ConvertTo-Json -Compress
} catch {
    [pscustomobject]@{ scope='hosted_launch_observer_pure'; result='failed'; checks=$script:passed; native_session_executed=$false } | ConvertTo-Json -Compress
    throw 'hosted_launch_observer_pure_failed'
}
