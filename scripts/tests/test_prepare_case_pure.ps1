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
$nameFunctions = @($ast.FindAll({ param($node)
    $node -is [System.Management.Automation.Language.FunctionDefinitionAst] -and $node.Name -ceq 'Test-SetupName'
}, $false))
if ($nameFunctions.Count -ne 1) { throw 'prepare_source_invalid' }
. ([scriptblock]::Create($nameFunctions[0].Extent.Text))
$acceptedNames = @('listing','acquisition','mismatch','missing','denial','cancellation',
    'webdav-credential-setup','webdav-credentials','webdav-listing','webdav-acquisition','webdav-mismatch','webdav-missing',
    'webdav-wrong-credentials','webdav-accepted-a','webdav-revoked-a','webdav-replacement-b',
    'webdav-permission-denied','webdav-truncated-transfer','webdav-cancellation',
    'fs-archive-corrupt-member','fs-archive-truncated-archive',
    ('app-http-' + ('a' * 32)), ('app-webdav-' + ('b' * 32)))
foreach ($name in $acceptedNames) {
    if (-not (Test-SetupName $name)) { throw 'prepare_name_rejected' }
    foreach ($invalid in @($name.ToUpperInvariant(), ($name + "`n"), ($name + '\child'),
        ('..\' + $name), (' ' + $name), ($name + ' '), ($name + [char]0))) {
        if (Test-SetupName $invalid) { throw 'prepare_name_boundary_failed' }
    }
}
foreach ($invalid in @('', 'webdav', 'webdav-unknown', 'webdav_wrong_credentials', 'accepted_a',
    'webdav-suite', 'app-webdav-', ('app-webdav-' + ('a' * 31)), ('app-webdav-' + ('a' * 33)),
    ('app-webdav-' + ('g' * 32)), 'app-http-private-canary',
    ('fs-archive-corrupt-member' + [char]0 + 'private-canary'),
    ('fs-archive-truncated-archive' + [char]0 + 'private-canary'))) {
    if (Test-SetupName $invalid) { throw 'prepare_name_unknown_accepted' }
}
[Console]::Out.WriteLine('prepare_names_pure_passed:' + $acceptedNames.Count)
$root = 'X:\synthetic'
$cases = @(
    @('', 'unknown'), @($root, 'root'), @(($root + '\helper-env'), 'helper_root'),
    @(($root + '\helper-env\profile\private-canary'), 'helper_profile_descendant'),
    @(($root + '\helper-env-other\profile'), 'other'), @(($root + '\profile\private-canary'), 'other'),
    @(($root + '\bridge-stdout.private'), 'bridge_log'), @(($root + '\bridge-stderr.private'), 'bridge_log'),
    @(($root + '\bridge-stdout.private-canary'), 'other'), @('private-canary', 'other')
)
foreach ($name in @('temp','home','profile','appdata','localappdata')) {
    $cases += ,@(($root + '\' + $name), 'application_root')
    $cases += ,@(($root + '\helper-env\' + $name), 'helper_private_root')
    $cases += ,@(($root + '\HELPER-ENV\' + $name.ToUpperInvariant()), 'helper_private_root')
    $direct = if ($name -ceq 'temp') { 'helper_temp_direct' } else { 'helper_' + $name + '_descendant' }
    $deeper = if ($name -ceq 'temp') { 'helper_temp_deeper' } else { $direct }
    $cases += ,@(($root + '\helper-env\' + $name + '\private-canary'), $direct)
    $cases += ,@(($root + '\HELPER-ENV\' + $name.ToUpperInvariant() + '\private-canary'), $direct)
    $cases += ,@(($root + '\helper-env\' + $name + '\private-canary\child'), $deeper)
    $cases += ,@(($root + '\helper-env\' + $name + '-other\private-canary'), 'helper_descendant')
    $cases += ,@(($root + '\helper-env\' + $name + '\'), 'helper_descendant')
}
$cases += ,@(($root + '\helper-env\unknown\private-canary'), 'helper_descendant')
$listingNodes = @(
    @('application.exe', 'application_binary'), @('source.conf', 'source_config'),
    @('queue.csv', 'acquisition_queue'), @('transcript.private', 'session_transcript'),
    @('output', 'output_root'), @('output\synthetic-case', 'case_root'),
    @('output\synthetic-case\logs', 'case_logs'), @('output\synthetic-case\downloads', 'case_downloads'),
    @('output\synthetic-case\listings', 'case_listings'), @('output\synthetic-case\config', 'case_config'),
    @('output\synthetic-case\listings\inventory.csv', 'listing_inventory')
)
foreach ($node in $listingNodes) {
    $full = $root + '\' + $node[0]
    $cases += ,@($full, $node[1])
    $cases += ,@($full.ToUpperInvariant(), $node[1])
    $cases += ,@(($full + '-private-canary'), 'other')
    $cases += ,@(($full + '\private-canary'), 'other')
}
foreach ($nonce in @('Ab09_-', 'SYNTHETIC', '_', '-')) {
    foreach ($suffix in @(@('.conf', 'working_config'), @('.provenance.json', 'config_provenance'))) {
        $leaf = 'working-' + $nonce + $suffix[0]
        $cases += ,@(($root + '\output\synthetic-case\config\' + $leaf), $suffix[1])
        $cases += ,@(($root + '\OUTPUT\SYNTHETIC-CASE\CONFIG\' + $leaf), $suffix[1])
    }
}
foreach ($leaf in @('working-.conf', 'working-.provenance.json', 'working-A.conf.private-canary',
    'working-A.provenance.json.private-canary', 'WORKING-A.conf', 'working-A.CONF', 'working-A.PROVENANCE.JSON',
    'working-a.b.conf', 'working-a b.conf', 'working-a+b.conf', 'working-a=b.conf', 'working-a:b.conf',
    'working-a/b.conf', 'child\working-A.conf', 'child\working-A.provenance.json',
    '..\config\working-A.conf', '..\config\working-A.provenance.json',
    'working-A.conf\', 'working-A.provenance.json\', "working-A.conf`n", "working-A.provenance.json`n",
    ("working-" + [char]0x00e9 + '.conf'), ("working-" + [char]0 + '.conf'))) {
    $cases += ,@(($root + '\output\synthetic-case\config\' + $leaf), 'other')
}
foreach ($parent in @('output\synthetic-case\config-other', 'output\synthetic-case-other\config',
    'output-other\synthetic-case\config', 'output\synthetic-case\listings', 'config',
    'output\synthetic-case\config\child', 'output\synthetic-case\config\..\config')) {
    foreach ($leaf in @('working-A.conf', 'working-A.provenance.json')) {
        $cases += ,@(($root + '\' + $parent + '\' + $leaf), 'other')
    }
}
$cases += ,@(($root + '-other\output\synthetic-case\config\working-A.conf'), 'other')
$cases += ,@(($root + '-other\output\synthetic-case\listings\inventory.csv'), 'other')
$maximumTerminalBytes = 0
foreach ($case in $cases) {
    if ((Get-SetupNodeCategory $root $case[0]) -cne $case[1]) { throw 'prepare_category_failed' }
    # Exercise the actual PowerShell JSON renderer without the native verification body.
    foreach ($reason in @('owner_invalid', 'verification_failed', 'enumeration_failed')) {
        $owner = if ($reason -ceq 'owner_invalid') { $false } else { $null }
        $failure = [ordered]@{ reason=$reason; category=$case[1];
            owner_is_user=$owner; owner_is_token_owner=$owner; token_owner_is_user=$owner }
        $terminal = [ordered]@{ schema_version=1; ok=$false; failure=$failure } | ConvertTo-Json -Compress
        $length = [Text.Encoding]::UTF8.GetByteCount($terminal)
        if ($length -gt 256) { throw 'prepare_terminal_bound_failed' }
        $maximumTerminalBytes = [Math]::Max($maximumTerminalBytes, $length)
    }
}
if ((Get-SetupNodeCategory '' 'private-canary') -cne 'unknown') { throw 'prepare_category_failed' }
[Console]::Out.WriteLine('prepare_category_pure_passed:' + ($cases.Count + 1))
[Console]::Out.WriteLine('prepare_terminal_max_bytes:' + $maximumTerminalBytes)
