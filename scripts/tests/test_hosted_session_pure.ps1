# Compile and pure protocol/quoting checks ONLY. Never creates a native session.
Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
$root = Split-Path -Parent $PSScriptRoot
$script:passed = 0
$script:pidReadFailureKind = 'none'
function Check([bool]$Value) {
    if (-not $Value) { throw 'pure_assertion_failed' }
    $script:passed++
}
function Reject([scriptblock]$Action) {
    $rejected = $false
    try { & $Action | Out-Null } catch { $rejected = $true }
    Check $rejected
}

function CompileObservation([string]$Result) {
    [pscustomobject]@{ phase=$script:phase; result=$Result; elapsed_ms=$script:clock.ElapsedMilliseconds; checks=$script:passed; pid_read_failure=$script:pidReadFailureKind } | ConvertTo-Json -Compress
}
$script:phase = 'prepare_source_validation'
$script:clock = [Diagnostics.Stopwatch]::StartNew()
try {
    # Parse the source as data; never dot-source or invoke the private-folder helper.
    $sourceFile = [IO.File]::OpenRead((Join-Path $root 'application-lab/prepare_case.ps1'))
    try {
        $bytes = New-Object byte[] 65537
        $count = 0
        while ($count -lt $bytes.Length) {
            $read = $sourceFile.Read($bytes, $count, $bytes.Length - $count)
            if ($read -eq 0) { break }
            $count += $read
        }
        Check ($count -gt 0 -and $count -le 65536)
        $source = [Text.UTF8Encoding]::new($false, $true).GetString($bytes, 0, $count)
    } finally { $sourceFile.Dispose() }
    $sourceTokens = $null; $sourceErrors = $null
    $sourceAst = [System.Management.Automation.Language.Parser]::ParseInput($source, [ref]$sourceTokens, [ref]$sourceErrors)
    Check ($sourceErrors.Count -eq 0)
    $compileCommands = @($sourceAst.FindAll({ param($node)
        $node -is [System.Management.Automation.Language.CommandAst] -and $node.GetCommandName() -ieq 'Add-Type'
    }, $true))
    Check ($compileCommands.Count -eq 1)
    $elements = $compileCommands[0].CommandElements
    Check ($elements.Count -eq 3 -and $compileCommands[0].Redirections.Count -eq 0)
    Check ($elements[1] -is [System.Management.Automation.Language.CommandParameterAst] -and
           $elements[1].ParameterName -ceq 'TypeDefinition' -and $null -eq $elements[1].Argument)
    Check ($elements[2] -is [System.Management.Automation.Language.StringConstantExpressionAst] -and
           $elements[2].StringConstantType -eq [System.Management.Automation.Language.StringConstantType]::SingleQuotedHereString)
    $definition = $elements[2].Value
    Check ($definition.Length -gt 0 -and $definition.Length -le 8192)

    # These observations cover the Add-Type boundary, including module loading;
    # they do not assert that a compiler child was observed or started.
    $script:phase = 'private_directory_add_type'
    $script:clock.Restart()
    CompileObservation 'started'
    Add-Type -TypeDefinition $definition -ErrorAction Stop -WarningAction SilentlyContinue 2>$null
    $compiled = 'AppLabPrivateDirectory' -as [type]
    Check ($null -ne $compiled -and $compiled.FullName -ceq 'AppLabPrivateDirectory')
    $methods = @($compiled.GetMethods([Reflection.BindingFlags]'Public,Static,DeclaredOnly'))
    Check ($methods.Count -eq 1 -and $methods[0].Name -ceq 'Create' -and $methods[0].ReturnType -eq [void])
    $parameters = $methods[0].GetParameters()
    Check ($parameters.Count -eq 2 -and $parameters[0].ParameterType -eq [string] -and $parameters[1].ParameterType -eq [byte[]])
    # Metadata inspection only. AppLabPrivateDirectory.Create is never invoked.
    CompileObservation 'passed'

    $script:phase = 'hosted_conpty_add_type'
    $script:clock.Restart()
    CompileObservation 'started'
    # A managed holder preserves the by-ref observation even when Read throws.
    # This test-only adapter calls the production loop; it has no native methods.
    $pidObservationHarness = @'
namespace TriageApplicationLab.PureTests {
    public sealed class PidListObservation {
        HostedProcessObservation observation;
        public PidListObservation(bool sticky) {
            observation.Begin();
            if(sticky) { observation.At(HostedProcessObservationStage.ChildOpen); observation.Capture(); }
        }
        public long[] Read(System.Func<int,HostedPidListSnapshot> query,System.Func<long> clock,
                System.Action<int> pause,long frequency) {
            try { return HostedPidListReader.Read(query,clock,pause,frequency,ref observation); }
            finally { observation.End(); }
        }
        public string Code { get { return observation.Code; } }
    }
}
'@
    $sessionSource=[IO.File]::ReadAllText((Join-Path $root 'application-lab/HostedConPtySession.cs'))
    Add-Type -TypeDefinition ($sessionSource + [Environment]::NewLine + $pidObservationHarness) -ErrorAction Stop -WarningAction SilentlyContinue 2>$null

    CompileObservation 'passed'
    $script:phase = 'poll_observation_pure'
    # BEGIN PURE POLL OBSERVATION TESTS: uses only the isolated diagnostic enum/struct.
    $observation = [TriageApplicationLab.HostedProcessObservation]::new()
    Check ($null -eq $observation.Code)
    $observation.At([TriageApplicationLab.HostedProcessObservationStage]::ChildOpen)
    $observation.Capture()
    Check ($null -eq $observation.Code)
    $stageCases = [ordered]@{
        Unknown='unknown'; PidBufferAllocate='pid_buffer_allocate'; PidListQuery='pid_list_query'
        PidListShape='pid_list_shape'; PidValue='pid_value'; RetainedChildWait='retained_child_wait'
        PidListCountNegative='pid_list_count_negative'
        PidListCountCapacity='pid_list_count_capacity'
        PidListAssignedCapacity='pid_list_assigned_capacity'
        PidListCountBelowAssigned='pid_list_count_below_assigned'
        PidListCountAboveAssigned='pid_list_count_above_assigned'
        ChildOpen='child_open'; ChildMembership='child_membership'; ChildExitWait='child_exit_wait'
        ChildCapacity='child_capacity'; ChildCreated='child_created'; ChildHandleClose='child_handle_close'
        PidBufferFree='pid_buffer_free'; JobAccounting='job_accounting'; AppExitWait='app_exit_wait'; AppExitCode='app_exit_code'
    }
    foreach ($entry in $stageCases.GetEnumerator()) {
        $stage = [TriageApplicationLab.HostedProcessObservationStage]([Enum]::Parse([TriageApplicationLab.HostedProcessObservationStage], $entry.Key))
        $observation.Begin(); $observation.At($stage)
        Check ($null -eq $observation.Code)
        $observation.Capture()
        Check ($observation.Code -ceq ('process_observation_stage_' + $entry.Value))
        $observation.At([TriageApplicationLab.HostedProcessObservationStage]::PidBufferFree)
        $observation.Capture(); $observation.End()
        $observation.At([TriageApplicationLab.HostedProcessObservationStage]::ChildOpen); $observation.Capture()
        Check ($observation.Code -ceq ('process_observation_stage_' + $entry.Value))
        $observation.Begin(); $observation.At($stage); $observation.End(); $observation.Capture()
        Check ($null -eq $observation.Code)
    }
    $observation.Begin(); $observation.At([Enum]::ToObject([TriageApplicationLab.HostedProcessObservationStage], 2147483647)); $observation.Capture()
    Check ($observation.Code -ceq 'process_observation_stage_unknown')


    # Exercise the production shape predicate with synthetic integers only.
    # The expected truth table is the original native observer conjunction.
    $shapeValues = @([int]::MinValue,-1,0,1,63,64,65,[int]::MaxValue)
    foreach ($assigned in $shapeValues) {
        foreach ($count in $shapeValues) {
            $expected = $count -ge 0 -and $count -le 64 -and $assigned -le 64 -and $assigned -eq $count
            $shape = [TriageApplicationLab.HostedProcessObservation]::new()
            $shape.Begin()
            $actual = $shape.CheckPidListShape($assigned,$count,64)
            Check ($actual -eq $expected)
            if ($actual) { Check ($null -eq $shape.Code) }
            else {
                $shape.Capture(); $shape.End()
                $reason = if ($count -lt 0) { 'pid_list_count_negative' }
                    elseif ($count -gt 64) { 'pid_list_count_capacity' }
                    elseif ($assigned -gt 64) { 'pid_list_assigned_capacity' }
                    elseif ($assigned -gt $count) { 'pid_list_count_below_assigned' }
                    else { 'pid_list_count_above_assigned' }
                Check ($shape.Code -ceq ('process_observation_stage_' + $reason))
                $shape.At([TriageApplicationLab.HostedProcessObservationStage]::PidBufferFree)
                $shape.Capture()
                Check ($shape.Code -ceq ('process_observation_stage_' + $reason))
            }
            $inactive = [TriageApplicationLab.HostedProcessObservation]::new()
            Check ($inactive.CheckPidListShape($assigned,$count,64) -eq $expected)
            $inactive.Capture()
            Check ($null -eq $inactive.Code)
        }
    }

    # Exercise the production retry loop with managed fake queries and a virtual clock.
    # No HostedConPtySession is constructed and no native entry point is called.
    function PidSnapshot([int]$Assigned,[int]$Count,[long[]]$Ids,[bool]$Success=$true,[int]$ErrorCode=0) {
        [TriageApplicationLab.HostedPidListSnapshot]::new($Success,$ErrorCode,$Assigned,$Count,$Ids)
    }
    function InvokePidReadCase([hashtable]$Case) {
        # A single snapshot also has a Count field; normalize the sequence before indexing.
        $queryFrames=[TriageApplicationLab.HostedPidListSnapshot[]]@($Case.Frames)
        $state = @{ Tick=[long]0; Queries=0; ClockCalls=0; Pauses=0; Capacities=[Collections.Generic.List[int]]::new() }
        if ($Case.ContainsKey('Start')) { $state.Tick=[long]$Case.Start }
        $queryBlock = {
            param([int]$capacity)
            $state.Capacities.Add($capacity)
            $index=$state.Queries; $state.Queries++
            if ($Case.ContainsKey('QueryThrows') -and $index -eq $Case.QueryThrows) { throw 'synthetic_query_failure' }
            if ($Case.ContainsKey('QueryAdvance')) { $state.Tick += [long]$Case.QueryAdvance }
            $queryFrames[[Math]::Min($index,$queryFrames.Length-1)]
        }.GetNewClosure()
        $clockBlock = {
            $index=$state.ClockCalls; $state.ClockCalls++
            if ($Case.ContainsKey('ClockThrows') -and $index -eq $Case.ClockThrows) { throw 'synthetic_clock_failure' }
            if ($Case.ContainsKey('ClockSequence')) { return [long]$Case.ClockSequence[[Math]::Min($index,$Case.ClockSequence.Count-1)] }
            return [long]$state.Tick
        }.GetNewClosure()
        $pauseBlock = {
            param([int]$delay)
            if ($delay -ne 5) { throw 'unexpected_pause' }
            $state.Pauses++
            if ($Case.ContainsKey('PauseThrows')) { throw 'synthetic_pause_failure' }
            if ($Case.ContainsKey('PauseAdvance')) { $state.Tick += [long]$Case.PauseAdvance }
            else { $state.Tick += $delay }
        }.GetNewClosure()
        $query = [Func[int,TriageApplicationLab.HostedPidListSnapshot]]$queryBlock
        $clock = [Func[long]]$clockBlock
        $pause = [Action[int]]$pauseBlock
        $frequency = if ($Case.ContainsKey('Frequency')) { [long]$Case.Frequency } else { [long]1000 }
        $readObservation=[TriageApplicationLab.PureTests.PidListObservation]::new($Case.ContainsKey('Sticky'))
        $ids=$null; $rejected=$false; $script:pidReadFailureKind='none'
        try { $ids=$readObservation.Read($query,$clock,$pause,$frequency) }
        catch {
            $rejected=$true
            $failure=$_.Exception
            for ($depth=0; $depth -lt 8 -and $null -ne $failure.InnerException; $depth++) { $failure=$failure.InnerException }
            $script:pidReadFailureKind=if($failure -is [ComponentModel.Win32Exception]) { 'native_error' }
                elseif($failure -is [InvalidOperationException]) { 'invalid_operation' }
                elseif($failure -is [InvalidCastException]) { 'invalid_cast' }
                elseif($failure -is [Management.Automation.RuntimeException]) { 'powershell_runtime' }
                elseif($failure -is [ArgumentException]) { 'argument' }
                else { 'other' }
        }
        [pscustomobject]@{ Rejected=$rejected; Ids=$ids; Code=$readObservation.Code; State=$state }
    }
    $script:phase = 'pid_snapshot_recovery'
    $frames=@((PidSnapshot 2 1 @(101)),(PidSnapshot 2 2 @(41,42)))
    $read=InvokePidReadCase @{ Frames=$frames }
    Check (-not $read.Rejected -and $null -eq $read.Code)
    Check (($read.Ids -join ',') -ceq '41,42')
    Check (($read.State.Capacities -join ',') -ceq '64,128' -and $read.State.Pauses -eq 1)
    Check ($frames[0].ProcessIds[0] -eq 0 -and $frames[1].ProcessIds[0] -eq 41)
    $script:phase = 'pid_snapshot_empty'
    $read=InvokePidReadCase @{ Frames=@((PidSnapshot 0 0 @())) }
    Check (-not $read.Rejected -and $read.State.Queries -eq 1 -and $read.State.Pauses -eq 0 -and $null -eq $read.Code)
    $script:phase = 'pid_snapshot_more_data'
    $frames=@((PidSnapshot 0 0 @(9) $false 234),(PidSnapshot 1 1 @(77)))
    $read=InvokePidReadCase @{ Frames=$frames }
    Check (-not $read.Rejected -and $read.Ids[0] -eq 77 -and $read.State.Queries -eq 2)
    Check ($frames[0].ProcessIds[0] -eq 0)
    $script:phase = 'pid_snapshot_fourth'
    # Success is possible on the fourth attempt, including at the exact 64-process cap.
    $frames=@((PidSnapshot 4 2 @(1,2)),(PidSnapshot 0 0 @() $false 234),(PidSnapshot 64 63 @(1)),(PidSnapshot 64 64 (1..64)))
    $read=InvokePidReadCase @{ Frames=$frames }
    Check (-not $read.Rejected -and $read.Ids.Count -eq 64 -and $read.State.Pauses -eq 3)
    Check (($read.State.Capacities -join ',') -ceq '64,128,256,512')
    $script:phase = 'pid_snapshot_exhaustion'
    # A frozen clock cannot evade the independent attempt bound.
    foreach ($nativeFailure in @($false,$true)) {
        $frame=if($nativeFailure) { PidSnapshot 999 -1 @(9) $false 234 } else { PidSnapshot 2 1 @(9) }
        $read=InvokePidReadCase @{ Frames=@($frame); PauseAdvance=0 }
        Check ($read.Rejected -and $read.State.Queries -eq 4 -and $read.State.Pauses -eq 3)
        Check (($read.State.Capacities -join ',') -ceq '64,128,256,512' -and $frame.ProcessIds[0] -eq 0)
        $expected=if($nativeFailure) { 'pid_list_query' } else { 'pid_list_count_below_assigned' }
        Check ($read.Code -ceq ('process_observation_stage_'+$expected))
    }
    $script:phase = 'pid_snapshot_malformed'
    # Every other malformed shape is fatal on its first query, even after storage growth.
    foreach ($shapeCase in @(
        @{ Assigned=1; Count=-1; Code='pid_list_count_negative' },
        @{ Assigned=65; Count=65; Code='pid_list_count_capacity' },
        @{ Assigned=65; Count=1; Code='pid_list_assigned_capacity' },
        @{ Assigned=0; Count=1; Code='pid_list_count_above_assigned' },
        @{ Assigned=-1; Count=0; Code='pid_list_count_above_assigned' }
    )) {
        foreach ($prefix in @($false,$true)) {
            $bad=PidSnapshot $shapeCase.Assigned $shapeCase.Count @(123)
            $frames=if($prefix) { @((PidSnapshot 2 1 @()),$bad) } else { @($bad) }
            $read=InvokePidReadCase @{ Frames=$frames }
            Check ($read.Rejected -and $read.State.Queries -eq (1+[int]$prefix))
            Check ($read.Code -ceq ('process_observation_stage_'+$shapeCase.Code) -and $bad.ProcessIds[0] -eq 0)
        }
    }
    $script:phase = 'pid_snapshot_pid_values'
    foreach ($ids in @([long[]]@(0),[long[]]@(-1),[long[]]@(4294967296),[long[]]@(4,5))) {
        $bad=PidSnapshot 1 1 $ids
        $read=InvokePidReadCase @{ Frames=@($bad) }
        Check ($read.Rejected -and $read.State.Queries -eq 1 -and $read.Code -ceq 'process_observation_stage_pid_value')
        Check (@($bad.ProcessIds | Where-Object { $_ -ne 0 }).Count -eq 0)
    }
    $read=InvokePidReadCase @{ Frames=@((PidSnapshot 1 1 $null)) }
    Check ($read.Rejected -and $read.Code -ceq 'process_observation_stage_pid_value')
    $read=InvokePidReadCase @{ Frames=@((PidSnapshot 1 1 @(4294967295))) }
    Check (-not $read.Rejected -and $read.Ids[0] -eq 4294967295)
    $script:phase = 'pid_snapshot_native_errors'
    foreach ($errorCode in @(0,5,87,233)) {
        $frame=PidSnapshot 1 1 @(41) $false $errorCode
        $read=InvokePidReadCase @{ Frames=@($frame) }
        Check ($read.Rejected -and $read.State.Queries -eq 1 -and $read.Code -ceq 'process_observation_stage_pid_list_query')
        Check ($frame.ProcessIds[0] -eq 0)
    }
    $script:phase = 'pid_snapshot_null'
    $read=InvokePidReadCase @{ Frames=@($null) }
    Check ($read.Rejected -and $read.State.Queries -eq 1 -and $read.Code -ceq 'process_observation_stage_pid_list_query')
    $read=InvokePidReadCase @{ Frames=@((PidSnapshot 1 1 @(41))); QueryAdvance=99 }
    Check (-not $read.Rejected -and $read.Ids[0] -eq 41)
    $script:phase = 'pid_snapshot_budget'
    # A query that crosses the single budget cannot publish even a complete snapshot.
    $frame=PidSnapshot 1 1 @(41)
    $read=InvokePidReadCase @{ Frames=@($frame); QueryAdvance=100 }
    Check ($read.Rejected -and $read.State.Queries -eq 1 -and $frame.ProcessIds[0] -eq 0)
    Check ($read.Code -ceq 'process_observation_stage_pid_list_query')
    $frames=@((PidSnapshot 2 1 @(3)),(PidSnapshot 1 1 @(41)))
    $read=InvokePidReadCase @{ Frames=$frames; QueryAdvance=50 }
    Check ($read.Rejected -and $read.State.Queries -eq 2 -and $read.State.Pauses -eq 1)
    Check ($frames[0].ProcessIds[0] -eq 0 -and $frames[1].ProcessIds[0] -eq 0)
    $read=InvokePidReadCase @{ Frames=@((PidSnapshot 2 1 @())); PauseAdvance=100 }
    Check ($read.Rejected -and $read.State.Queries -eq 1 -and $read.Code -ceq 'process_observation_stage_pid_list_query')
    $script:phase = 'pid_snapshot_clock'
    foreach ($settings in @(
        @{ Frequency=0 },@{ Frequency=-1 },@{ Start=-1 },
        @{ ClockSequence=@(10,9) },@{ ClockSequence=@(10,10,9) },
        @{ ClockThrows=0 },@{ ClockThrows=2 },@{ QueryThrows=0 },@{ PauseThrows=$true }
    )) {
        $settings.Frames=@((PidSnapshot 2 1 @(31)))
        $read=InvokePidReadCase $settings
        Check ($read.Rejected -and $read.State.Queries -le 1 -and $read.Code -ceq 'process_observation_stage_pid_list_query')
    }
    $script:phase = 'pid_snapshot_arithmetic'
    # The deadline arithmetic remains bounded near Int64.MaxValue.
    $read=InvokePidReadCase @{ Frames=@((PidSnapshot 1 1 @(41))); Start=([long]::MaxValue-10); Frequency=[long]::MaxValue }
    Check (-not $read.Rejected -and $read.State.Queries -eq 1)
    $read=InvokePidReadCase @{ Frames=@((PidSnapshot 1 1 @(41))); ClockSequence=@(0,0,1); Frequency=1 }
    Check ($read.Rejected -and $read.Code -ceq 'process_observation_stage_pid_list_query')
    $script:phase = 'pid_snapshot_sticky'
    foreach ($frames in @(@((PidSnapshot 1 1 @(41))),@((PidSnapshot 0 1 @(41))))) {
        $read=InvokePidReadCase @{ Frames=$frames; Sticky=$true }
        Check ($read.Code -ceq 'process_observation_stage_child_open')
    }
    # END PURE PID SNAPSHOT RETRY TESTS.

    $originalErrors = [string[]]@('process_observation_failed','forced_termination','console_cleanup_failed')
    $projected = $observation.Project($originalErrors)
    Check (($originalErrors -join ',') -ceq 'process_observation_failed,forced_termination,console_cleanup_failed')
    Check (($projected -join ',') -ceq 'process_observation_failed,forced_termination,console_cleanup_failed,process_observation_stage_unknown')
    Check (-not [Object]::ReferenceEquals($projected,$originalErrors))
    Check ([Object]::ReferenceEquals($observation.Project($projected),$projected))
    Check ($null -eq $observation.Project($null))
    foreach ($unchanged in @([string[]]@(),[string[]]@('forced_termination'),
            [string[]]@('PROCESS_OBSERVATION_FAILED'),
            [string[]]@('process_observation_failed','process_observation_stage_private-canary'))) {
        Check ([Object]::ReferenceEquals($observation.Project($unchanged),$unchanged))
    }
    foreach ($count in @(23,24,25)) {
        $buffer = [Collections.Generic.List[string]]::new()
        $buffer.Add('process_observation_failed')
        for ($i=1;$i -lt $count-1;$i++) { $buffer.Add(('original_{0:d2}' -f $i)) }
        $buffer.Add('console_cleanup_failed')
        $before = $buffer.ToArray()
        $after = $observation.Project($before)
        Check (($before -join ',') -ceq ($buffer.ToArray() -join ','))
        Check (($after[0..($count-1)] -join ',') -ceq ($before -join ','))
        Check ($after[$count-1] -ceq 'console_cleanup_failed')
        if ($count -eq 23) {
            Check ($after.Length -eq 24 -and $after[23] -ceq 'process_observation_stage_unknown')
        } else { Check ([Object]::ReferenceEquals($after,$before)) }
    }
    # A projected earlier copy cannot consume a slot subsequently needed by the
    # original list's cleanup outcome, even when the next snapshot reaches 24.
    $buffer = [Collections.Generic.List[string]]::new()
    $buffer.Add('process_observation_failed')
    for ($i=1;$i -lt 23;$i++) { $buffer.Add(('original_{0:d2}' -f $i)) }
    $early = $observation.Project($buffer.ToArray())
    Check ($early.Length -eq 24 -and $buffer.Count -eq 23)
    $buffer.Add('reader_cleanup_failed')
    $late = $observation.Project($buffer.ToArray())
    Check ($late.Length -eq 24 -and $late[23] -ceq 'reader_cleanup_failed')
    Check (@($late | Where-Object { $_.StartsWith('process_observation_stage_', [StringComparison]::Ordinal) }).Count -eq 0)
    $observation.Begin(); $observation.End()
    Check ([Object]::ReferenceEquals($observation.Project($originalErrors),$originalErrors))

    function Invoke-PureObservationFlow([bool]$Instrument, [bool]$PrimaryFailure, [bool]$CleanupFailure, [bool]$DiagnosticFailure) {
        $state = [TriageApplicationLab.HostedProcessObservation]::new()
        $events = [Collections.Generic.List[string]]::new()
        $codes = [Collections.Generic.List[string]]::new()
        $finishCount = 0
        if ($Instrument) { $state.Begin() }
        try {
            try {
                if ($Instrument) { $state.At([TriageApplicationLab.HostedProcessObservationStage]::ChildMembership) }
                $events.Add('membership')
                if ($PrimaryFailure) { throw 'private-primary-canary' }
            } catch { if ($Instrument) { $state.Capture() }; throw }
            finally {
                if ($Instrument) { $state.At([TriageApplicationLab.HostedProcessObservationStage]::ChildHandleClose) }
                $events.Add('close')
                if ($CleanupFailure) { throw 'private-cleanup-canary' }
            }
        } catch {
            if ($Instrument) { $state.Capture(); $state.End() }
            $codes.Add('process_observation_failed')
            $events.Add('finish:0'); $finishCount++
            $codes.Add('forced_termination')
        }
        if ($Instrument) { $state.End() }
        $current = $codes.ToArray()
        if ($Instrument) { try { if ($DiagnosticFailure) { throw 'private-diagnostic-canary' }; $current=$state.Project($current) } catch { } }
        return @{Events=($events -join ','); Codes=$current; OriginalCodes=$codes.ToArray(); FinishCount=$finishCount}
    }
    foreach ($primary in @($false,$true)) {
        foreach ($cleanup in @($false,$true)) {
            foreach ($diagnostic in @($false,$true)) {
                $original = Invoke-PureObservationFlow $false $primary $cleanup $diagnostic
                $tracked = Invoke-PureObservationFlow $true $primary $cleanup $diagnostic
                Check ($tracked.Events -ceq $original.Events -and $tracked.FinishCount -eq $original.FinishCount)
                Check (($tracked.OriginalCodes -join ',') -ceq ($original.OriginalCodes -join ','))
                Check ((@($tracked.Codes | Where-Object { -not $_.StartsWith('process_observation_stage_', [StringComparison]::Ordinal) }) -join ',') -ceq ($original.Codes -join ','))
                $diagnostics = @($tracked.Codes | Where-Object { $_.StartsWith('process_observation_stage_', [StringComparison]::Ordinal) })
                if (($primary -or $cleanup) -and -not $diagnostic) {
                    $expected = if ($primary) { 'child_membership' } else { 'child_handle_close' }
                    Check ($diagnostics.Count -eq 1 -and $diagnostics[0] -ceq ('process_observation_stage_' + $expected))
                } else { Check ($diagnostics.Count -eq 0) }
            }
        }
    }
    # END PURE POLL OBSERVATION TESTS
    $script:phase = 'pure_checks'
    $script:clock.Restart()

Check ([TriageApplicationLab.HostedConPtySession]::Quote('') -ceq '""')
Check ([TriageApplicationLab.HostedConPtySession]::Quote('plain') -ceq '"plain"')
Check ([TriageApplicationLab.HostedSourceDirectory]::SourcePath('C:\owned\case') -ceq 'C:\owned\case\source')
Check ([TriageApplicationLab.HostedSourceDirectory]::SourcePath('C:/owned/case/') -ceq 'C:\owned\case\source')
foreach ($invalid in @('', 'relative', 'C:relative', 'C:\', '\\server\case', '\\?\C:\owned',
        'C:\owned\..\outside', 'C:\owned\.\case', 'C:\owned\case:stream', '1:\owned', "C:\owned`ncase", ('C:\' + ('a' * 2001)))) {
    $path = $invalid
    Reject { [TriageApplicationLab.HostedSourceDirectory]::SourcePath($path) }
}
# Only the pure path derivation above executes; Acquire, Verify and Dispose are native.
Check ([TriageApplicationLab.HostedSourceDirectory].GetMethod('Acquire').ReturnType -eq [TriageApplicationLab.HostedSourceDirectory])
$cleanupFactory = [TriageApplicationLab.HostedSourceDirectory].GetMethod('CleanupFailure', [Reflection.BindingFlags]'Static,NonPublic')
Check ($null -ne $cleanupFactory -and $cleanupFactory.ReturnType -eq [Exception])
$primaryFailure = [InvalidOperationException]::new('source_directory_invalid', [Exception]::new('private-canary'))
# Invoke only the pure exception combiner, never any directory/handle operation.
$combinedFailure = $cleanupFactory.Invoke($null, [object[]]@($primaryFailure))
Check ([object]::ReferenceEquals($combinedFailure.InnerException, $primaryFailure))
$codes = [TriageApplicationLab.HostedSourceDirectory]::FailureCodes($combinedFailure)
Check ($codes.Count -eq 2 -and $codes[0] -ceq 'source_directory_cleanup_failed' -and $codes[1] -ceq 'source_directory_invalid')
Check ([TriageApplicationLab.HostedSourceDirectory]::FailureCodes([Exception]::new('private-canary')).Count -eq 0)
$repeatedFailure = $cleanupFactory.Invoke($null, [object[]]@($combinedFailure))
Check ([TriageApplicationLab.HostedSourceDirectory]::FailureCodes($repeatedFailure).Count -eq 2)
foreach ($method in @('Start','StartTui','StartSource')) {
    Check ([TriageApplicationLab.HostedConPtySession].GetMethod($method).GetParameters().Count -eq 9)
}
Check ([TriageApplicationLab.HostedConPtySession]::Quote('a b') -ceq '"a b"')
Check ([TriageApplicationLab.HostedConPtySession]::Quote('a"b') -ceq '"a\"b"')
Check ([TriageApplicationLab.HostedConPtySession]::Quote('a\') -ceq '"a\\"')
Check ([TriageApplicationLab.HostedConPtySession]::Quote('a\"b') -ceq '"a\\\"b"')
Reject { [TriageApplicationLab.HostedConPtySession]::Quote("a`nb") }
Reject { [TriageApplicationLab.HostedConPtySession]::Quote(('x' * 4097)) }

$poll = [TriageApplicationLab.HostedProtocol]::Parse('{"action":"poll"}')
[TriageApplicationLab.HostedProtocol]::Keys($poll, 'action')
Check ([TriageApplicationLab.HostedProtocol]::Text($poll, 'action') -ceq 'poll')
foreach ($invalid in @(
    '{"action":"poll","action":"finish"}',
    '{"action":"poll","ACTION":"finish"}',
    '{"action":"poll"}{}',
    '{"action":"poll",}',
    '{"action":"poll","grace_ms":1.0}',
    '{"action":"poll","grace_ms":1e3}',
    '{"action":"poll","grace_ms":NaN}',
    '{"action":"poll","grace_ms":true}',
    '{"action":"poll","grace_ms":null}',
    '{"action":"poll","grace_ms":01}',
    '{"action":"poll","grace_ms":-01}',
    '{"action":"pol\u0000l"}',
    '{"action":"pol\ud800l"}',
    '{"action":"pol\nl"}',
    '[]',
    ('{"action":"' + ('x' * 65536) + '"}'),
    '{"a":{"b":{"c":{"d":{"e":"x"}}}}}'
)) {
    $text = $invalid
    Reject { [TriageApplicationLab.HostedProtocol]::Parse($text) }
}
Reject { [TriageApplicationLab.HostedProtocol]::Keys([TriageApplicationLab.HostedProtocol]::Parse('{"Action":"poll"}'), 'action') }
Reject { [TriageApplicationLab.HostedProtocol]::Keys([TriageApplicationLab.HostedProtocol]::Parse('{"action":"poll","extra":"x"}'), 'action') }
Reject { [TriageApplicationLab.HostedProtocol]::Text([TriageApplicationLab.HostedProtocol]::Parse('{"action":1}'), 'action') }
Reject { [TriageApplicationLab.HostedProtocol]::Integer([TriageApplicationLab.HostedProtocol]::Parse('{"grace_ms":"1"}'), 'grace_ms') }
Reject { [TriageApplicationLab.HostedProtocol]::Integer([TriageApplicationLab.HostedProtocol]::Parse('{"grace_ms":-1}'), 'grace_ms') }
Check ([TriageApplicationLab.HostedProtocol]::Integer([TriageApplicationLab.HostedProtocol]::Parse('{"grace_ms":15000}'), 'grace_ms') -eq 15000)
foreach ($limit in @(1, 2, 3, 4)) {
    Check ([TriageApplicationLab.HostedProtocol]::RuntimeProcessLimit([TriageApplicationLab.HostedProtocol]::Parse(('{"max_runtime_processes":' + $limit + '}'))) -eq $limit)
    foreach ($count in @(-1, 0, 1, 2, 4, 5, 64)) {
        Check ([TriageApplicationLab.HostedConPtySession]::RuntimeCountAllowed($limit, $count) -eq ($count -ge 1 -and $count -le $limit))
    }
}
foreach ($invalid in @('{}', '{"max_runtime_processes":0}', '{"max_runtime_processes":5}',
        '{"max_runtime_processes":-1}', '{"max_runtime_processes":"1"}', '{"max_runtime_processes":true}',
        '{"max_runtime_processes":1.0}', '{"max_runtime_processes":1,"max_runtime_processes":4}')) {
    $text = $invalid
    Reject { [TriageApplicationLab.HostedProtocol]::RuntimeProcessLimit([TriageApplicationLab.HostedProtocol]::Parse($text)) }
}
Check (-not [TriageApplicationLab.HostedConPtySession]::RuntimeCountAllowed(0, 1))
Check (-not [TriageApplicationLab.HostedConPtySession]::RuntimeCountAllowed(5, 1))
# PowerShell coerces a direct string $null argument to empty; reflection here
# invokes only this public pure predicate and preserves the C# null sentinel.
Check ([TriageApplicationLab.HostedConPtySession].GetMethod('SameRuntimeImage').Invoke($null, [object[]]@($null, 'C:\owned\one\rclone.exe')))
Check ([TriageApplicationLab.HostedConPtySession]::SameRuntimeImage('C:\owned\one\rclone.exe', 'c:\OWNED\one\rclone.exe'))
Check (-not [TriageApplicationLab.HostedConPtySession]::SameRuntimeImage('C:\owned\one\rclone.exe', 'C:\owned\two\rclone.exe'))
Check (-not [TriageApplicationLab.HostedConPtySession]::SameRuntimeImage('C:\owned\one\rclone.exe', 'C:\owned\one\rclone.exe.extra'))
Check (-not [TriageApplicationLab.HostedConPtySession]::SameRuntimeImage($null, $null))
$argsValue = [TriageApplicationLab.HostedProtocol]::Arguments([TriageApplicationLab.HostedProtocol]::Parse('{"args":["a","b c"]}'))
Check ($argsValue.Count -eq 2 -and $argsValue[1] -ceq 'b c')
Reject { [TriageApplicationLab.HostedProtocol]::Arguments([TriageApplicationLab.HostedProtocol]::Parse('{"args":[1]}')) }
Reject { [TriageApplicationLab.HostedProtocol]::EnvironmentMap([TriageApplicationLab.HostedProtocol]::Parse('{"environment":{"PATH":"x","path":"y"}}')) }
Reject { [TriageApplicationLab.HostedProtocol]::EnvironmentMap([TriageApplicationLab.HostedProtocol]::Parse('{"environment":{"PATH":1}}')) }
$reader = New-Object System.IO.StringReader("{`"action`":`"poll`"}`n")
Check ([TriageApplicationLab.HostedProtocol]::Read($reader)['action'] -ceq 'poll')
Check ($null -eq [TriageApplicationLab.HostedProtocol]::Read($reader))
$reader.Dispose()
Reject { [TriageApplicationLab.HostedProtocol]::Read((New-Object System.IO.StringReader('{"action":"poll"}'))) }
$failure = [TriageApplicationLab.HostedProtocol]::Failure()
Check ($failure.Count -eq 17 -and $failure['ok'] -eq $false -and $failure['errors'][0] -ceq 'protocol_invalid' -and $null -eq $failure['runtime_process_count'])
Check ($null -eq $failure['runtime_sha256'] -and $null -eq $failure['app_exit_code'])

$tokens = $null
$errors = $null
$bridgeAst = [System.Management.Automation.Language.Parser]::ParseFile((Join-Path $root 'application-lab/hosted_session.ps1'), [ref]$tokens, [ref]$errors)
Check ($errors.Count -eq 0)
$switches = @($bridgeAst.FindAll({ param($node) $node -is [System.Management.Automation.Language.SwitchStatementAst] }, $true))
Check ($switches.Count -eq 1)
$sourceClauses = @($switches[0].Clauses | Where-Object { $_.Item1.Extent.Text -ceq "'start_source'" })
Check ($sourceClauses.Count -eq 1)
$sourceCalls = @($sourceClauses[0].Item2.FindAll({ param($node)
    $node -is [System.Management.Automation.Language.InvokeMemberExpressionAst] -and $node.Member.Value -ceq 'StartSource'
}, $true))
Check ($sourceCalls.Count -eq 1 -and $sourceCalls[0].Arguments.Count -eq 9)
$sourceKeys = @($sourceClauses[0].Item2.FindAll({ param($node)
    $node -is [System.Management.Automation.Language.InvokeMemberExpressionAst] -and $node.Member.Value -ceq 'Keys'
}, $true))
Check ($sourceKeys.Count -eq 1 -and $sourceKeys[0].Arguments[1].Value -ceq 'action,app_path,app_sha256,args,case_root,environment,transcript_path,max_output_bytes,deadline_ms,max_runtime_processes')
# Compile only the two pure response adapters, never the bridge or native session.
foreach ($functionName in @('Get-SessionResponse','Add-ObservedFailureFields')) {
    $functions = @($bridgeAst.FindAll({ param($node)
        $node -is [System.Management.Automation.Language.FunctionDefinitionAst] -and $node.Name -ceq $functionName
    }, $true))
    Check ($functions.Count -eq 1)
    . ([scriptblock]::Create($functions[0].Extent.Text))
}
$fake = [pscustomobject]@{ Calls=[Collections.Generic.List[string]]::new() }
$fake | Add-Member ScriptMethod Poll { $this.Calls.Add('poll'); return @{schema_version=1; operation='poll'} }
$fake | Add-Member ScriptMethod Finish { param([int]$Grace) $this.Calls.Add("finish:$Grace"); return @{schema_version=1; operation='finish'} }
$fake | Add-Member ScriptMethod Abort { $this.Calls.Add('abort'); return @{schema_version=1; operation='abort'} }
$fake | Add-Member ScriptMethod LaunchSnapshot { $this.Calls.Add('launch'); return @{schema_version=3; operation='launch'} }
foreach ($operation in @('poll','finish','abort')) {
    foreach ($observedMode in @($false,$true)) {
        $fake.Calls.Clear()
        $response = Get-SessionResponse $fake $observedMode $operation 123
        $first = if ($operation -ceq 'finish') { 'finish:123' } else { $operation }
        if ($observedMode) {
            Check ($response.schema_version -eq 3 -and $response.operation -ceq 'launch')
            Check (($fake.Calls -join ',') -ceq "$first,launch")
        } else {
            Check ($response.schema_version -eq 1 -and $response.operation -ceq $operation)
            Check (($fake.Calls -join ',') -ceq $first)
        }
    }
}
Reject { Get-SessionResponse $fake $true 'unknown' }
$failure = [TriageApplicationLab.HostedProtocol]::Failure()
$failedObserved = Add-ObservedFailureFields $failure
Check ($failedObserved.Count -eq 31 -and $failedObserved.schema_version -eq 3 -and -not $failedObserved.ok)
Check ($failedObserved.observation_kind -ceq 'launch_image' -and $failedObserved.runtime_launch_count -eq 0 -and
       $null -eq $failedObserved.launch_sha256 -and $null -eq $failedObserved.system_helper_sha256)
foreach ($name in @('launch_image_observed','system_helper_image_observed','debug_events_drained','debug_pump_joined',
                   'debug_handles_closed','system_helper_reference_closed')) { Check ($failedObserved[$name] -is [bool] -and -not $failedObserved[$name]) }
$observedClauses = @($switches[0].Clauses | Where-Object { $_.Item1.Extent.Text -ceq "'start_source_observed'" })
Check ($observedClauses.Count -eq 1)
$observedCalls = @($observedClauses[0].Item2.FindAll({ param($node)
    $node -is [System.Management.Automation.Language.InvokeMemberExpressionAst] -and $node.Member.Value -ceq 'StartSourceObserved'
}, $true))
Check ($observedCalls.Count -eq 1 -and $observedCalls[0].Arguments.Count -eq 11)
$observedKeys = @($observedClauses[0].Item2.FindAll({ param($node)
    $node -is [System.Management.Automation.Language.InvokeMemberExpressionAst] -and $node.Member.Value -ceq 'Keys'
}, $true))
Check ($observedKeys.Count -eq 1 -and $observedKeys[0].Arguments[1].Value -ceq 'action,app_path,app_sha256,args,case_root,environment,transcript_path,max_output_bytes,deadline_ms,max_runtime_processes,expected_runtime_sha256,max_runtime_launches')
foreach ($actionName in @('observe_runtime','ctrl_c')) {
    $clause = @($switches[0].Clauses | Where-Object { $_.Item1.Value -ceq $actionName })
    Check ($clause.Count -eq 1 -and $clause[0].Item2.Extent.Text.Contains('$null -eq $session -or $observed'))
}
# The same adapter must cover explicit poll/finish and both EOF/error abort paths.
$adapterCalls = @($bridgeAst.FindAll({ param($node)
    $node -is [System.Management.Automation.Language.CommandAst] -and $node.GetCommandName() -ceq 'Get-SessionResponse'
}, $true))
Check ($adapterCalls.Count -eq 5)
Check (@($adapterCalls | Where-Object { $_.Extent.Text -ceq "Get-SessionResponse `$session `$observed 'abort'" }).Count -eq 2)
# The standalone bridge must refuse non-hosted callers before compiling or reading commands.
$outerTry = @($bridgeAst.FindAll({ param($node) $node -is [System.Management.Automation.Language.TryStatementAst] }, $true))[0]
$guard = $outerTry.Body.Statements[0]
Check ($guard -is [System.Management.Automation.Language.IfStatementAst] -and $guard.Clauses.Count -eq 1 -and $null -eq $guard.ElseClause)
$expectedGuard = '$env:GITHUB_ACTIONS -cne ''true'' -or $env:RUNNER_OS -cne ''Windows'' -or $env:RUNNER_ENVIRONMENT -cne ''github-hosted'' -or $PSVersionTable.PSEdition -cne ''Desktop'''
Check (($guard.Clauses[0].Item1.Extent.Text -replace '\s+', ' ') -ceq $expectedGuard -and
       $guard.Clauses[0].Item2.Statements.Count -eq 1 -and $guard.Clauses[0].Item2.Statements[0] -is [System.Management.Automation.Language.ThrowStatementAst])
[pscustomobject]@{ passed=$script:passed; failed=0; native_calls=0; session_started=$false } | ConvertTo-Json -Compress
} catch {
    CompileObservation 'failed'
    $compilerCodes=@([regex]::Matches($_.Exception.ToString(), '(?<![A-Z0-9])CS[0-9]{4}(?![0-9])') | ForEach-Object { $_.Value } | Sort-Object -Unique | Select-Object -First 8)
    [pscustomobject]@{ compiler_codes=$compilerCodes } | ConvertTo-Json -Compress
    # Do not expose compiler output, source paths, exception text or identities.
    [Console]::Error.WriteLine('hosted_harness_validation_failed')
    exit 1
}
