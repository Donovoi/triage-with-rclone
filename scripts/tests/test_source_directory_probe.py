"""Pure PowerShell AST/function checks only; never invoke the hosted probe."""
import base64
import json
import os
from pathlib import Path
import subprocess
import unittest


PATH = Path(__file__).resolve().parents[1] / "application-lab/probe_source_directory.ps1"
PREPARE = PATH.with_name("prepare_case.ps1")
CHECKS = {"missing_rejected", "file_rejected", "junction_rejected", "acl_rejected", "rejected_leases_released",
          "lease_verified", "source_rename_denied", "case_rename_denied", "sandbox_rename_denied", "release_observed",
          "source_cwd", "descendant_cwd", "source_preserved", "session_cleanup"}


@unittest.skipUnless(os.name == "nt", "Windows PowerShell pure parser/function checks")
class SourceDirectoryProbeTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        # Parse the whole file, then define only four named PURE functions.
        # The probe body and native methods are never invoked; literal C# compilation is explicit below.
        script = r"""
Set-StrictMode -Version Latest
$ErrorActionPreference='Stop'
$ProgressPreference='SilentlyContinue'
$tokens=$null; $errors=$null
$source=[IO.File]::ReadAllText('__SOURCE__')
$ast=[System.Management.Automation.Language.Parser]::ParseInput($source,[ref]$tokens,[ref]$errors)
if ($errors.Count -ne 0) { throw 'probe_parse_failed' }
$names=@('Test-ProbeHosted','New-ProbeReport','Get-ProbeCreator','Test-ProbeRejectionCodes')
foreach ($name in $names) {
    $nodes=@($ast.FindAll({ param($n) $n -is [System.Management.Automation.Language.FunctionDefinitionAst] -and $n.Name -ceq $name },$true))
    if ($nodes.Count -ne 1) { throw 'pure_function_shape' }
    . ([scriptblock]::Create($nodes[0].Extent.Text))
}
function Add-Type { throw 'compile_prohibited' }
function Start-Process { throw 'process_prohibited' }
function New-Item { throw 'filesystem_mutation_prohibited' }
function Reject([scriptblock]$Action) {
    try { & $Action | Out-Null; return $false } catch { return $true }
}
function Checks([bool]$Value) {
    $result=[ordered]@{}
    foreach ($name in @('missing_rejected','file_rejected','junction_rejected','acl_rejected','rejected_leases_released',
        'lease_verified','source_rename_denied','case_rename_denied','sandbox_rename_denied','release_observed',
        'source_cwd','descendant_cwd','source_preserved','session_cleanup')) { $result[$name]=$Value }
    return $result
}
function Renames([string]$Value) { return [ordered]@{ source=$Value; case=$Value; sandbox=$Value } }
$guard=@()
$guard+=Test-ProbeHosted 'true' 'Windows' 'github-hosted' 'Desktop' $true $true
foreach ($row in @(
    @('TRUE','Windows','github-hosted','Desktop',$true,$true),
    @('true','Linux','github-hosted','Desktop',$true,$true),
    @('true','Windows','self-hosted','Desktop',$true,$true),
    @('true','Windows','github-hosted','Core',$true,$true),
    @('true','Windows','github-hosted','Desktop',$false,$true),
    @('true','Windows','github-hosted','Desktop',$true,$false),
    @('true','Windows','github-hosted','Desktop','true',$true),
    @($null,'Windows','github-hosted','Desktop',$true,$true))) {
    $guard+=Test-ProbeHosted @row
}
$reports=@()
$reports+=New-ProbeReport (Checks $true) '' $true $false (Renames 'denied')
$reports+=New-ProbeReport (Checks $false) 'hosted_only' $true $false (Renames 'not_attempted')
$reports+=New-ProbeReport (Checks $false) 'cleanup_failed' $false $true (Renames 'not_attempted')
$reports+=New-ProbeReport (Checks $false) 'rename_failed' $false $true ([ordered]@{ source='moved'; case='not_attempted'; sandbox='not_attempted' })
$reports+=New-ProbeReport (Checks $false) 'rename_failed' $true $false ([ordered]@{ source='denied'; case='unexpected_error'; sandbox='not_attempted' })
$invalid=@()
$invalid+=Reject { $c=Checks $true; $c.Remove('source_cwd'); New-ProbeReport $c '' $true $false (Renames 'denied') }
$invalid+=Reject { $c=Checks $true; $c['private-canary-path']='x'; New-ProbeReport $c '' $true $false (Renames 'denied') }
$invalid+=Reject { $c=Checks $true; $c.source_cwd='true'; New-ProbeReport $c '' $true $false (Renames 'denied') }
$invalid+=Reject { New-ProbeReport (Checks $true) 'private-canary-path' $false $true (Renames 'denied') }
$invalid+=Reject { New-ProbeReport (Checks $true) '' $true $true (Renames 'denied') }
$invalid+=Reject { New-ProbeReport (Checks $false) '' $true $false (Renames 'denied') }
$invalid+=Reject { New-ProbeReport (Checks $true) '' $false $true (Renames 'denied') }
$badRenames=@()
$badRenames+=Reject { New-ProbeReport (Checks $true) '' $true $false (Renames 'not_attempted') }
$badRenames+=Reject { New-ProbeReport (Checks $true) '' $true $false (Renames 'moved') }
$badRenames+=Reject { New-ProbeReport (Checks $true) '' $true $false (Renames 'unexpected_error') }
$badRenames+=Reject { New-ProbeReport (Checks $true) '' $true $false (Renames 'DENIED') }
$badRenames+=Reject { $r=Renames 'denied'; $r.source=$true; New-ProbeReport (Checks $true) '' $true $false $r }
$badRenames+=Reject { $r=Renames 'denied'; $r.Remove('source'); New-ProbeReport (Checks $true) '' $true $false $r }
$badRenames+=Reject { $r=Renames 'denied'; $r['private-canary-path']='denied'; New-ProbeReport (Checks $true) '' $true $false $r }
$badRenames+=Reject { New-ProbeReport (Checks $true) '' $true $false (Renames 'private-canary-path') }
$codes=@()
$codes+=Test-ProbeRejectionCodes @('source_directory_invalid')
foreach ($row in @(
    @('source_directory_cleanup_failed','source_directory_invalid'),
    @('source_directory_invalid','source_directory_cleanup_failed'),
    @('source_directory_cleanup_failed'),@('source_directory_invalid','source_directory_invalid'),
    @('unexpected_failure'),@())) { $codes+=Test-ProbeRejectionCodes $row }
$definition=Get-ProbeCreator ([IO.File]::ReadAllText('__PREPARE__'))
$creator=@()
$creator+=$definition.Contains('public static class AppLabPrivateDirectory')
$creator+=Reject { Get-ProbeCreator 'Add-Type -Path private-canary-path' }
$creator+=Reject { Get-ProbeCreator 'Add-Type -TypeDefinition $privateCanary' }
$creator+=Reject { Get-ProbeCreator 'if (' }
$creator+=Reject { Get-ProbeCreator '' }
$creator+=Reject { Get-ProbeCreator (([IO.File]::ReadAllText('__PREPARE__')) + "`nAdd-Type -Path x") }
$guards=@($ast.EndBlock.Statements | Where-Object { $_ -is [System.Management.Automation.Language.IfStatementAst] -and $_.Extent.Text.Contains('Test-ProbeHosted') })
$compiles=@($ast.FindAll({ param($n) $n -is [System.Management.Automation.Language.CommandAst] -and $n.GetCommandName() -ieq 'Add-Type' },$true))
$gateFirst=$guards.Count -eq 1 -and $compiles.Count -eq 4 -and
    @($compiles | Where-Object { $_.Extent.StartOffset -le $guards[0].Extent.EndOffset }).Count -eq 0
$native=@($ast.FindAll({ param($n) $n -is [System.Management.Automation.Language.InvokeMemberExpressionAst] -and $n.Member.Value -ceq 'StartSource' },$true))
$finally=@($ast.FindAll({ param($n) $n -is [System.Management.Automation.Language.TryStatementAst] -and $null -ne $n.Finally -and $n.Finally.Extent.Text.Contains('$session.Finish(10000)') },$true))
$launchClosed=$native.Count -eq 1 -and $native[0].Arguments.Count -eq 9 -and $finally.Count -eq 1 -and
    $finally[0].Body.Extent.Text.Contains('::StartSource') -and
    $source.IndexOf('Read-ProbeFile $transcript') -gt $finally[0].Finally.Extent.EndOffset
$compiled=0
foreach ($command in $compiles) {
    $literals=@($command.CommandElements | Where-Object {
        $_ -is [System.Management.Automation.Language.StringConstantExpressionAst] -and
        $_.StringConstantType -eq [System.Management.Automation.Language.StringConstantType]::SingleQuotedHereString
    })
    if ($literals.Count -eq 1) {
        # Compile the two literal probe-only classes into memory; call no method,
        # write no executable, and never invoke the probe or inert helper Main.
        Microsoft.PowerShell.Utility\Add-Type -TypeDefinition $literals[0].Value -ErrorAction Stop -WarningAction SilentlyContinue
        $compiled++
    }
}
$disposition=[SourceProbeOwnedTree].GetNestedType('Disposition',[Reflection.BindingFlags]::NonPublic)
$dispositionSize=[Runtime.InteropServices.Marshal]::SizeOf([Activator]::CreateInstance($disposition))
$dispositionByte=$disposition.GetField('deleteFile').FieldType -eq [byte]
$absenceMethod=[SourceProbeOwnedTree].GetMethod('IsAbsent',[Reflection.BindingFlags]'NonPublic,Static')
$absence=@()
foreach ($code in @(2,3,5,32,0)) {
    $absence+=$absenceMethod.Invoke($null,[object[]]@([uint32]::MaxValue,[int]$code))
}
$absence+=$absenceMethod.Invoke($null,[object[]]@([uint32]16,[int]2))
$last=[ordered]@{ guard=$guard; reports=$reports; invalid_reports=$invalid; rejection_codes=$codes;
    invalid_renames=$badRenames; creator=$creator; guard_before_compile=$gateFirst; launch_finalized_before_transcript=$launchClosed;
    compiled_literal_classes=$compiled; disposition_size=$dispositionSize; disposition_byte=$dispositionByte; absence=$absence;
    parsed=$true; native_calls=0; native_entrypoint_invoked=$false }
[Console]::Out.WriteLine(($last | ConvertTo-Json -Depth 8 -Compress))
"""
        script = script.replace("__SOURCE__", str(PATH).replace("'", "''"))
        script = script.replace("__PREPARE__", str(PREPARE).replace("'", "''"))
        powershell = Path(os.environ["SystemRoot"]) / "System32/WindowsPowerShell/v1.0/powershell.exe"
        encoded = base64.b64encode(script.encode("utf-16le")).decode("ascii")
        result = subprocess.run([str(powershell), "-NoProfile", "-NonInteractive", "-EncodedCommand", encoded],
                                stdin=subprocess.DEVNULL, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                                timeout=30, check=False)
        if result.returncode or result.stderr or not 0 < len(result.stdout) <= 16384:
            raise AssertionError("pure_parser_or_function_check_failed")
        cls.value = json.loads(result.stdout)

    def test_real_hosted_guard_is_exact_and_before_compilation(self):
        self.assertEqual(self.value["guard"], [True] + [False] * 8)
        self.assertIs(self.value["guard_before_compile"], True)

    def test_final_report_is_closed_and_does_not_claim_production_acceptance(self):
        passed, unavailable, failed = self.value["reports"][:3]
        fields = {"schema_version", "scope", "result", "checks", "cleanup_complete", "tree_retained", "errors",
                  "production_application_executed", "rename_outcomes"}
        for row in (passed, unavailable, failed):
            self.assertEqual(set(row), fields)
            self.assertEqual(row["schema_version"], 2)
            self.assertEqual(set(row["rename_outcomes"]), {"source", "case", "sandbox"})
            self.assertEqual(set(row["checks"]), CHECKS)
            self.assertTrue(all(type(value) is bool for value in row["checks"].values()))
            self.assertIs(row["production_application_executed"], False)
        self.assertEqual((passed["result"], passed["errors"], passed["cleanup_complete"], passed["tree_retained"]),
                         ("passed", [], True, False))
        self.assertEqual((unavailable["result"], unavailable["errors"]), ("unavailable", ["hosted_only"]))
        self.assertEqual((failed["result"], failed["errors"], failed["cleanup_complete"], failed["tree_retained"]),
                         ("failed", ["cleanup_failed"], False, True))

    def test_malformed_inflated_or_private_report_values_refused(self):
        self.assertEqual(self.value["invalid_reports"], [True] * 7)
        self.assertNotIn("private-canary", json.dumps(self.value))

    def test_primary_rename_failure_is_preserved_alongside_cleanup_failure(self):
        combined, primary_only = self.value["reports"][3:]
        self.assertEqual(combined["errors"], ["rename_failed", "cleanup_failed"])
        self.assertEqual(combined["rename_outcomes"],
                         {"source": "moved", "case": "not_attempted", "sandbox": "not_attempted"})
        self.assertEqual(primary_only["errors"], ["rename_failed"])
        self.assertEqual(primary_only["rename_outcomes"],
                         {"source": "denied", "case": "unexpected_error", "sandbox": "not_attempted"})
        self.assertEqual(combined["result"], "failed")
        self.assertEqual(primary_only["result"], "failed")
        self.assertIs(combined["cleanup_complete"], False)
        self.assertIs(combined["tree_retained"], True)
        self.assertIs(primary_only["cleanup_complete"], True)

    def test_rename_outcomes_are_closed_and_cannot_inflate_pass(self):
        self.assertEqual(self.value["invalid_renames"], [True] * 8)
        passed, unavailable = self.value["reports"][:2]
        self.assertEqual(set(passed["rename_outcomes"].values()), {"denied"})
        self.assertEqual(set(unavailable["rename_outcomes"].values()), {"not_attempted"})

    def test_cleanup_error_cannot_hide_behind_expected_primary_rejection(self):
        self.assertEqual(self.value["rejection_codes"], [True] + [False] * 6)

    def test_only_reviewed_literal_atomic_creator_definition_is_extracted(self):
        self.assertEqual(self.value["creator"], [True] * 6)

    def test_native_session_finally_precedes_buffered_transcript_read(self):
        self.assertIs(self.value["launch_finalized_before_transcript"], True)
        self.assertIs(self.value["parsed"], True)
        self.assertEqual(self.value["compiled_literal_classes"], 2)
        self.assertIs(self.value["native_entrypoint_invoked"], False)

    def test_cleanup_abi_compiles_with_one_byte_boolean_without_native_calls(self):
        self.assertEqual(self.value["disposition_size"], 1)
        self.assertIs(self.value["disposition_byte"], True)
        self.assertEqual(self.value["native_calls"], 0)

    def test_only_exact_file_not_found_can_prove_cleanup_absence(self):
        self.assertEqual(self.value["absence"], [True] + [False] * 5)


if __name__ == "__main__":
    unittest.main()
