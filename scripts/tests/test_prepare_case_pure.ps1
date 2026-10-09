# Pure string classification only. Never invokes prepare_case or native ACL APIs.
Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
$path = Join-Path (Split-Path -Parent $PSScriptRoot) 'application-lab/prepare_case.ps1'
$tokens = $null; $errors = $null
$ast = [System.Management.Automation.Language.Parser]::ParseFile($path, [ref]$tokens, [ref]$errors)
if ($errors.Count -ne 0) { throw 'prepare_source_invalid' }
$functions = @($ast.FindAll({ param($node)
    $node -is [System.Management.Automation.Language.FunctionDefinitionAst] -and $node.Name -ceq 'Get-SetupNodeCategory'
}, $false))
if ($functions.Count -ne 1) { throw 'prepare_source_invalid' }
# Extract the one reviewed pure function, never the script's creation/verification body.
. ([scriptblock]::Create($functions[0].Extent.Text))
$root = 'X:\synthetic'
$cases = @(
    @('', 'unknown'), @($root, 'root'), @(($root + '\helper-env'), 'helper_root'),
    @(($root + '\helper-env\profile\private-canary'), 'helper_descendant'),
    @(($root + '\helper-env-other\profile'), 'other'), @(($root + '\profile\private-canary'), 'other'),
    @(($root + '\bridge-stdout.private'), 'bridge_log'), @(($root + '\bridge-stderr.private'), 'bridge_log'),
    @(($root + '\bridge-stdout.private-canary'), 'other'), @('private-canary', 'other')
)
foreach ($name in @('temp','home','profile','appdata','localappdata')) {
    $cases += ,@(($root + '\' + $name), 'application_root')
    $cases += ,@(($root + '\helper-env\' + $name), 'helper_private_root')
}
foreach ($case in $cases) {
    if ((Get-SetupNodeCategory $root $case[0]) -cne $case[1]) { throw 'prepare_category_failed' }
}
if ((Get-SetupNodeCategory '' 'private-canary') -cne 'unknown') { throw 'prepare_category_failed' }
[Console]::Out.WriteLine('prepare_category_pure_passed:21')
