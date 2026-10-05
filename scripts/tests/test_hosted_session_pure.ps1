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
    CompileObservation 'passed'
    $script:phase = 'pure_checks'
    $script:clock.Restart()

Check ([TriageApplicationLab.HostedConPtySession]::Quote('') -ceq '""')
Check ([TriageApplicationLab.HostedConPtySession]::Quote('plain') -ceq '"plain"')
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
Check ($failure.Count -eq 16 -and $failure['ok'] -eq $false -and $failure['errors'][0] -ceq 'protocol_invalid')
Check ($null -eq $failure['runtime_sha256'] -and $null -eq $failure['app_exit_code'])

$tokens = $null
$errors = $null
$bridgeAst = [System.Management.Automation.Language.Parser]::ParseFile((Join-Path $root 'application-lab/hosted_session.ps1'), [ref]$tokens, [ref]$errors)
Check ($errors.Count -eq 0)
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
