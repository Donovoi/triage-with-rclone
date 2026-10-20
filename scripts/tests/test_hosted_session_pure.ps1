# Compile and pure protocol/quoting checks ONLY. Never creates a native session.
Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
$root = Split-Path -Parent $PSScriptRoot
$script:passed = 0
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
    [pscustomobject]@{ phase=$script:phase; result=$Result; elapsed_ms=$script:clock.ElapsedMilliseconds } | ConvertTo-Json -Compress
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
    Add-Type -Path (Join-Path $root 'application-lab/HostedConPtySession.cs') -ErrorAction Stop -WarningAction SilentlyContinue 2>$null

    # BEGIN PURE POLL OBSERVATION TESTS: uses only the isolated diagnostic enum/struct.
    $observation = [TriageApplicationLab.HostedProcessObservation]::new()
    Check ($null -eq $observation.Code)
    $observation.At([TriageApplicationLab.HostedProcessObservationStage]::ChildOpen)
    $observation.Capture()
    Check ($null -eq $observation.Code)
    $stageCases = [ordered]@{
        Unknown='unknown'; PidBufferAllocate='pid_buffer_allocate'; PidListQuery='pid_list_query'
        PidListShape='pid_list_shape'; PidValue='pid_value'; RetainedChildWait='retained_child_wait'
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
    CompileObservation 'passed'
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
    # Do not expose compiler output, source paths, exception text or identities.
    [Console]::Error.WriteLine('hosted_harness_validation_failed')
    exit 1
}
