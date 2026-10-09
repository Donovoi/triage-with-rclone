"""Pure parser/report and in-memory compilation checks; never run either probe."""
import json
import os
from pathlib import Path
import subprocess
import tempfile
import unittest


PATH = Path(__file__).resolve().parents[1] / "application-lab/probe_launch_observer.ps1"
SOURCE_PROBE = PATH.with_name("probe_source_directory.ps1")
CHECKS = {"source_cwd", "descendant_cwd", "source_preserved", "launch_count_exact", "launch_hash_exact", "peak_one",
          "launch_only", "transient_images_deleted", "transcript_exact", "session_cleanup", "observer_cleanup"}


@unittest.skipUnless(os.name == "nt", "Windows PowerShell pure parser and compilation checks")
class LaunchObserverProbeTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        script = r"""
Set-StrictMode -Version Latest
$ErrorActionPreference='Stop'
$ProgressPreference='SilentlyContinue'
$source=[IO.File]::ReadAllText('__PROBE__')
$reference=[IO.File]::ReadAllText('__SOURCE_PROBE__')
$tokens=$null; $errors=$null
$ast=[System.Management.Automation.Language.Parser]::ParseInput($source,[ref]$tokens,[ref]$errors)
if ($errors.Count -ne 0) { throw 'parse_failed' }
foreach ($name in @('Test-LaunchHosted','Get-LaunchSupport','Test-LaunchInteger','Test-LaunchSnapshot',
    'New-LaunchDiagnostic','Convert-LaunchFailureDiagnostic','Get-LaunchFailureDiagnostic','New-LaunchChecks','New-LaunchCase','New-LaunchReport',
    'Get-LaunchSourceLimit','Read-LaunchSource')) {
    $nodes=@($ast.EndBlock.Statements | Where-Object { $_ -is [System.Management.Automation.Language.FunctionDefinitionAst] -and $_.Name -ceq $name })
    if ($nodes.Count -ne 1) { throw 'pure_function_shape' }
    . ([scriptblock]::Create($nodes[0].Extent.Text))
}
function Add-Type { throw 'compile_prohibited' }
function Start-Process { throw 'process_prohibited' }
function New-Item { throw 'filesystem_mutation_prohibited' }
function Invoke-LaunchCase { throw 'native_probe_prohibited' }
function Reject([scriptblock]$Action) { try { & $Action | Out-Null; return $false } catch { return $true } }
$sourceLimits=@()
$boundedReads=@()
foreach ($name in @('probe','source_probe','private_creator','session_helper')) {
    $sourceLimits+=Get-LaunchSourceLimit $name
    $length=$(if ($name -ceq 'session_helper') { 131072 } else { 65536 })
    $value=Read-LaunchSource (Join-Path '__FIXTURES__' ([string]$length+'.bin')) $name
    $boundedReads+=($value -is [byte[]] -and $value.Length -eq $length -and $value[0] -eq 0 -and $value[-1] -eq 255)
    $boundedReads+=Reject { Read-LaunchSource (Join-Path '__FIXTURES__' ([string]($length+1)+'.bin')) $name }
    $boundedReads+=Reject { Read-LaunchSource (Join-Path '__FIXTURES__' 'empty.bin') $name }
}
$invalidLimits=@()
foreach ($name in @('Session_helper','other','private-canary',65536,$null)) { $invalidLimits+=Reject { Get-LaunchSourceLimit $name } }
$invalidLimits+=Reject { Read-LaunchSource (Join-Path '__FIXTURES__' '65536.bin') 'other' }
function Snapshot([int]$Count) {
    return [ordered]@{ schema_version=3; ok=$true; state='finished'; app_exit_code=[uint32]0;
        runtime_image_observed=$false; runtime_sha256=$null; runtime_process_count=$null; ctrl_c_sent=$false;
        output_bytes=[long]23; output_limit_exceeded=$false; forced_termination=$false; app_exited=$true;
        observed_children_exited=$true; job_zero_confirmed=$true; reader_joined=$true; conpty_closed=$true;
        errors=[string[]]@(); observation_kind='launch_image'; launch_image_observed=$true; launch_sha256=('a'*64);
        runtime_launch_count=$Count; peak_runtime_processes=1; debug_event_count=23;
        debug_events_drained=$true; debug_pump_joined=$true; debug_handles_closed=$true }
}
function Sources { return [ordered]@{ probe=('1'*64); source_probe=('2'*64); private_creator=('3'*64); session_helper=('4'*64) } }
function Cases { return [ordered]@{
    single_fast_child=(New-LaunchCase (New-LaunchChecks $true) '' $true $false);
    two_sequential_children=(New-LaunchCase (New-LaunchChecks $true) '' $true $false) } }
$guard=@(Test-LaunchHosted 'true' 'Windows' 'github-hosted' 'Desktop' $true $true)
foreach ($row in @(@('TRUE','Windows','github-hosted','Desktop',$true,$true),@('true','Linux','github-hosted','Desktop',$true,$true),
    @('true','Windows','self-hosted','Desktop',$true,$true),@('true','Windows','github-hosted','Core',$true,$true),
    @('true','Windows','github-hosted','Desktop',$false,$true),@('true','Windows','github-hosted','Desktop',$true,$false),
    @('true','Windows','github-hosted','Desktop','true',$true),@($null,'Windows','github-hosted','Desktop',$true,$true))) { $guard+=Test-LaunchHosted @row }
$positive=@((Test-LaunchSnapshot (Snapshot 1) 1 ('a'*64)),(Test-LaunchSnapshot (Snapshot 2) 2 ('a'*64)))
# Match the C# public return type, whose Contains method is an explicit interface implementation.
$nativeDictionary=[Collections.Generic.Dictionary[string,object]]::new()
$ordered=Snapshot 1; foreach ($key in $ordered.Keys) { $nativeDictionary.Add($key,$ordered[$key]) }
$positive+=Test-LaunchSnapshot $nativeDictionary 1 ('a'*64)
$nativeDiagnostic=New-LaunchDiagnostic $nativeDictionary 1 ('a'*64)
$falseSnapshots=@()
foreach ($name in @('ok','app_exited','observed_children_exited','job_zero_confirmed','reader_joined','conpty_closed',
    'launch_image_observed','debug_events_drained','debug_pump_joined','debug_handles_closed')) {
    $v=Snapshot 1; $v[$name]=$false; $falseSnapshots+=Test-LaunchSnapshot $v 1 ('a'*64)
    $v=Snapshot 1; $v[$name]='true'; $falseSnapshots+=Test-LaunchSnapshot $v 1 ('a'*64)
}
foreach ($row in @(@('schema_version',1),@('app_exit_code',1),@('state','running'),@('observation_kind','live_image'),
    @('runtime_image_observed',$true),@('runtime_sha256',('a'*64)),@('runtime_process_count',1),@('ctrl_c_sent',$true),
    @('output_limit_exceeded',$true),@('forced_termination',$true),@('launch_sha256',('b'*64)),@('launch_sha256',('A'*64)),
    @('runtime_launch_count',0),@('runtime_launch_count',2),@('runtime_launch_count','1'),@('runtime_launch_count',$true),
    @('peak_runtime_processes',2),@('debug_event_count',3),@('debug_event_count',4097),@('output_bytes',0),@('output_bytes',65537),
    @('errors',''),@('errors',@('debug_cleanup_failed')))) {
    $v=Snapshot 1; $v[$row[0]]=$row[1]; $falseSnapshots+=Test-LaunchSnapshot $v 1 ('a'*64)
}
$v=Snapshot 1; $v.Remove('debug_handles_closed'); $falseSnapshots+=Test-LaunchSnapshot $v 1 ('a'*64)
$v=Snapshot 1; $v['private-canary']='x'; $falseSnapshots+=Test-LaunchSnapshot $v 1 ('a'*64)
$falseSnapshots+=Test-LaunchSnapshot (Snapshot 1) 3 ('a'*64)
$falseSnapshots+=Test-LaunchSnapshot (Snapshot 1) 1 'private-canary'
$diagnostics=@()
$v=Snapshot 2; $v.runtime_launch_count=1; $v.debug_handles_closed=$false; $v.errors=@('debug_launch_limit','debug_cleanup_failed')
$diagnostics+=New-LaunchDiagnostic $v 2 ('a'*64)
$v=Snapshot 1; $v.launch_sha256='b'*64; $diagnostics+=New-LaunchDiagnostic $v 1 ('a'*64)
foreach ($row in @(@('errors',@('private-canary')),@('state','private-canary'),@('debug_event_count','23'),@('debug_handles_closed','false'),
    @('launch_sha256','private-canary'),@('errors',@('debug_cleanup_failed','debug_cleanup_failed')))) {
    $v=Snapshot 1; $v[$row[0]]=$row[1]; $diagnostics+=New-LaunchDiagnostic $v 1 ('a'*64)
}
$v=Snapshot 1; $v['private-canary']='x'; $diagnostics+=New-LaunchDiagnostic $v 1 ('a'*64)
$diagnostics+=New-LaunchDiagnostic $null 1 ('a'*64)
$createDiagnostics=@()
foreach ($role in @('application_path','runtime_path','system_console_host','other','unavailable')) {
    $v=[Collections.Generic.Dictionary[string,object]]::new()
    $v.Add('schema_version',1); $v.Add('event_ordinal',57); $v.Add('image_role',$role)
    $v.Add('owned_job',$true); $v.Add('image_path_matches',$false)
    $createDiagnostics+=Convert-LaunchFailureDiagnostic $v
}
function CreateDiagnostic { return [ordered]@{schema_version=1; event_ordinal=1; image_role='unavailable'; owned_job=$null; image_path_matches=$null} }
$createDiagnostics+=Convert-LaunchFailureDiagnostic (CreateDiagnostic)
$v=CreateDiagnostic; $v.event_ordinal=4096; $v.owned_job=$false; $v.image_path_matches=$true
$createDiagnostics+=Convert-LaunchFailureDiagnostic $v
$invalidCreate=@()
foreach ($row in @(@('schema_version',2),@('schema_version','1'),@('schema_version',$true),@('schema_version',[long]1),
    @('event_ordinal',0),@('event_ordinal',4097),@('event_ordinal','57'),@('event_ordinal',[double]57),@('event_ordinal',$true),
    @('image_role','System_console_host'),@('image_role','private-canary'),@('image_role',@('runtime_path')),
    @('owned_job','false'),@('owned_job',0),@('image_path_matches','true'),@('image_path_matches',1))) {
    $v=CreateDiagnostic; $v[$row[0]]=$row[1]; $invalidCreate+=Convert-LaunchFailureDiagnostic $v
}
$v=CreateDiagnostic; $v.Remove('owned_job'); $invalidCreate+=Convert-LaunchFailureDiagnostic $v
$v=CreateDiagnostic; $v['private-canary']='private-canary'; $invalidCreate+=Convert-LaunchFailureDiagnostic $v
$invalidCreate+=Convert-LaunchFailureDiagnostic $null
$invalidCreate+=Convert-LaunchFailureDiagnostic 'private-canary'
$calls=[Collections.Generic.List[int]]::new()
$fake=[pscustomobject]@{ calls=$calls; value=(CreateDiagnostic); fail=$false }
$fake | Add-Member -MemberType ScriptMethod -Name LaunchFailureDiagnostic -Value {
    $this.calls.Add(1); if ($this.fail) { throw 'private-canary' }; return $this.value
}
$getterRecords=@((Get-LaunchFailureDiagnostic $fake))
$fake.fail=$true; $getterRecords+=Get-LaunchFailureDiagnostic $fake
$getterRecords+=Get-LaunchFailureDiagnostic $null
$fake.fail=$false; $fake.value=$null; $getterRecords+=Get-LaunchFailureDiagnostic $fake
$case=New-LaunchCase (New-LaunchChecks $false) 'observation_failed' $false $true
$cleanFailure=New-LaunchCase (New-LaunchChecks $false) 'transcript_failed' $true $false
$reports=@((New-LaunchReport (Cases) (Sources) ('a'*64) ''))
$failedCases=Cases; $failedCases.single_fast_child=$case
$failedCases.two_sequential_children=New-LaunchCase (New-LaunchChecks $false) 'not_run' $true $false
$reports+=New-LaunchReport $failedCases (Sources) ('a'*64) ''
$reports+=New-LaunchReport (Cases) (Sources) ('a'*64) 'source_changed'
$emptyCases=[ordered]@{ single_fast_child=(New-LaunchCase (New-LaunchChecks $false) 'not_run' $true $false);
    two_sequential_children=(New-LaunchCase (New-LaunchChecks $false) 'not_run' $true $false) }
$emptySources=[ordered]@{ probe=$null; source_probe=$null; private_creator=$null; session_helper=$null }
$reports+=New-LaunchReport $emptyCases $emptySources $null 'hosted_only'
$invalid=@()
$invalid+=Reject { New-LaunchCase (New-LaunchChecks $false) '' $true $false }
$invalid+=Reject { New-LaunchCase (New-LaunchChecks $true) '' $false $true }
$invalid+=Reject { New-LaunchCase (New-LaunchChecks $true) '' $true $true }
$invalid+=Reject { New-LaunchCase (New-LaunchChecks $false) 'cleanup_failed' $false $false }
$invalid+=Reject { New-LaunchCase (New-LaunchChecks $true) 'not_run' $true $false }
$invalid+=Reject { $c=New-LaunchChecks $true; $c.source_cwd='true'; New-LaunchCase $c '' $true $false }
$invalid+=Reject { $c=New-LaunchChecks $true; $c['private-canary']=1; New-LaunchCase $c '' $true $false }
$invalid+=Reject { New-LaunchCase (New-LaunchChecks $false) 'private-canary' $false $true }
$invalid+=Reject { New-LaunchReport (Cases) (Sources) $null '' }
$invalid+=Reject { $s=Sources; $s.probe=$null; New-LaunchReport (Cases) $s ('a'*64) '' }
$invalid+=Reject { $s=Sources; $s.probe='private-canary'; New-LaunchReport (Cases) $s ('a'*64) '' }
$invalid+=Reject { $s=Sources; $s.Remove('private_creator'); New-LaunchReport (Cases) $s ('a'*64) '' }
$invalid+=Reject { $c=Cases; $c.single_fast_child.errors=@('private-canary'); New-LaunchReport $c (Sources) ('a'*64) '' }
$invalid+=Reject { $c=Cases; $c.single_fast_child['path']='private-canary'; New-LaunchReport $c (Sources) ('a'*64) '' }
$invalid+=Reject { $c=Cases; $c.single_fast_child.checks.transient_images_deleted=$false; New-LaunchReport $c (Sources) ('a'*64) '' }
$invalid+=Reject { $c=Cases; $c['extra'] = $c.single_fast_child; New-LaunchReport $c (Sources) ('a'*64) '' }
$invalid+=Reject { $c=Cases; $c.single_fast_child=New-LaunchCase (New-LaunchChecks $false) 'observation_failed' $false $true;
    $c.single_fast_child.errors=@('observation_failed'); New-LaunchReport $c (Sources) ('a'*64) '' }
$support=Get-LaunchSupport $reference
$extract=@()
$extract+=Reject { Get-LaunchSupport 'if (' }
$extract+=Reject { Get-LaunchSupport '' }
$extract+=Reject { Get-LaunchSupport ($reference + "`nfunction Hash-Probe { 'private-canary' }") }
$extract+=Reject { Get-LaunchSupport ($reference.Replace('function Hash-Probe','function Missing-Probe')) }
$extract+=Reject { Get-LaunchSupport ($reference.Replace('public static class SourceProbeOwnedTree {','public static class WrongClass {')) }
$extract+=Reject { Get-LaunchSupport ($reference + "`nfunction Nested { function Hash-Probe {} }") }
$extract+=Reject { Get-LaunchSupport ($reference.Replace('Add-Type -ErrorAction Stop -WarningAction SilentlyContinue -TypeDefinition','Write-Output -ErrorAction Stop -WarningAction SilentlyContinue -TypeDefinition')) }
$t=$null; $e=$null; $referenceAst=[System.Management.Automation.Language.Parser]::ParseInput($reference,[ref]$t,[ref]$e)
$literal=@($referenceAst.FindAll({param($n) $n -is [System.Management.Automation.Language.StringConstantExpressionAst] -and $n.Value.Contains('public static class SourceProbeOwnedTree {')},$true))
$extractExact=$literal.Count -eq 1 -and $support.cleanup -ceq $literal[0].Value -and $support.functions.Count -eq 7
$compiled=0
# Compile copied cleanup and inert literals in memory. Do not call a native method or Main.
Microsoft.PowerShell.Utility\Add-Type -TypeDefinition $support.cleanup -ErrorAction Stop -WarningAction SilentlyContinue
$compiled++
$inert=@($ast.FindAll({param($n) $n -is [System.Management.Automation.Language.StringConstantExpressionAst] -and
    $n.StringConstantType -eq [System.Management.Automation.Language.StringConstantType]::SingleQuotedHereString -and
    $n.Value.Contains('public static class InertLaunchObserverProbe {')},$true))
if ($inert.Count -ne 1) { throw 'literal_shape' }
Microsoft.PowerShell.Utility\Add-Type -TypeDefinition $inert[0].Value -ErrorAction Stop -WarningAction SilentlyContinue
$compiled++
$main=[InertLaunchObserverProbe].GetMethod('Main')
$entryShape=$main.IsStatic -and $main.ReturnType -eq [int] -and $main.GetParameters().Count -eq 1 -and $main.GetParameters()[0].ParameterType -eq [string[]]
$guards=@($ast.EndBlock.Statements | Where-Object { $_ -is [System.Management.Automation.Language.IfStatementAst] -and $_.Extent.Text.Contains('Test-LaunchHosted') })
$directEffects=@($ast.EndBlock.Statements | Where-Object { $_ -isnot [System.Management.Automation.Language.FunctionDefinitionAst] -and
    ($_.Extent.Text.Contains('Read-LaunchSource $paths') -or $_.Extent.Text.Contains('::GetCurrent()') -or $_.Extent.Text.Contains('Add-Type -TypeDefinition')) })
$gateFirst=$guards.Count -eq 1 -and $directEffects.Count -eq 1 -and $directEffects[0].Extent.StartOffset -gt $guards[0].Extent.EndOffset
$launches=@($ast.FindAll({param($n) $n -is [System.Management.Automation.Language.InvokeMemberExpressionAst] -and $n.Member.Value -ceq 'StartSourceObserved'},$true))
$finalizers=@($ast.FindAll({param($n) $n -is [System.Management.Automation.Language.TryStatementAst] -and $null -ne $n.Finally -and
    $n.Finally.Extent.Text.Contains('$session.Finish(10000)')},$true))
$finalizeBeforeRead=$launches.Count -eq 1 -and $launches[0].Arguments.Count -eq 11 -and $finalizers.Count -eq 1 -and
    $finalizers[0].Body.Extent.Text.Contains('::StartSourceObserved') -and
    $finalizers[0].Finally.Extent.Text.IndexOf('$session.LaunchSnapshot()') -gt $finalizers[0].Finally.Extent.Text.IndexOf('$session.Finish(10000)') -and
    $source.IndexOf('Read-ProbeFile $transcript') -gt $finalizers[0].Finally.Extent.EndOffset
$failureBranches=@($ast.FindAll({param($n) $n -is [System.Management.Automation.Language.IfStatementAst] -and
    $n.Extent.Text.Contains("[Console]::Out.WriteLine('launch_observer_create_failure='")},$true))
$failureOnly=$failureBranches.Count -eq 1 -and
    $failureBranches[0].Clauses[0].Item1.Extent.Text -ceq '-not $sessionClosed -and $null -ne $sha' -and
    $failureBranches[0].Extent.StartOffset -gt $finalizers[0].Finally.Extent.EndOffset
$sourceReads=@($ast.FindAll({param($n) $n -is [System.Management.Automation.Language.CommandAst] -and $n.GetCommandName() -ceq 'Read-LaunchSource'},$true))
$bothReadsBound=$sourceReads.Count -eq 2
foreach ($read in $sourceReads) {
    $bothReadsBound=$bothReadsBound -and $read.CommandElements.Count -eq 3 -and
        $read.CommandElements[1].Extent.Text -ceq '$paths[$key]' -and $read.CommandElements[2].Extent.Text -ceq '$key'
}
[Console]::Out.WriteLine(([ordered]@{ guard=$guard; positive_snapshots=$positive; rejected_snapshots=$falseSnapshots;
    reports=$reports; combined_failure=$case; clean_failure=$cleanFailure; invalid_reports=$invalid; rejected_extractions=$extract; diagnostics=$diagnostics;
    exact_extraction=$extractExact; compiled_literal_classes=$compiled; inert_entry_shape=$entryShape; native_dictionary_diagnostic=$nativeDiagnostic;
    guard_before_effects=$gateFirst; finalize_before_transcript=$finalizeBeforeRead; create_diagnostics=$createDiagnostics;
    invalid_create_diagnostics=$invalidCreate; getter_records=$getterRecords; getter_calls=$calls.Count; create_diagnostic_failure_only=$failureOnly;
    source_limits=$sourceLimits; bounded_reads=$boundedReads; invalid_limits=$invalidLimits; both_source_reads_bound=$bothReadsBound;
    native_calls=0; native_entrypoint_invoked=$false
} | ConvertTo-Json -Depth 9 -Compress))
"""
        script = script.replace("__PROBE__", str(PATH).replace("'", "''"))
        script = script.replace("__SOURCE_PROBE__", str(SOURCE_PROBE).replace("'", "''"))
        powershell = Path(os.environ["SystemRoot"]) / "System32/WindowsPowerShell/v1.0/powershell.exe"
        # Only this generated pure driver is executed, never PATH/the native probe.
        # A file avoids Windows' encoded-command length ceiling as mutation cases grow.
        with tempfile.TemporaryDirectory(prefix="launch-observer-pure-") as directory:
            fixture_root = Path(directory) / "fixtures"
            fixture_root.mkdir()
            for length in (65536, 65537, 131072, 131073):
                (fixture_root / f"{length}.bin").write_bytes(bytes(range(256)) * (length // 256) + bytes(length % 256))
            (fixture_root / "empty.bin").write_bytes(b"")
            script = script.replace("__FIXTURES__", str(fixture_root).replace("'", "''"))
            driver = Path(directory) / "pure.ps1"
            driver.write_text(script, encoding="utf-8", newline="\n")
            result = subprocess.run([str(powershell), "-NoProfile", "-NonInteractive", "-File", str(driver)],
                                    stdin=subprocess.DEVNULL, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                                    timeout=40, check=False)
        if result.returncode or result.stderr or not 0 < len(result.stdout) <= 32768:
            raise AssertionError("pure_parser_or_compilation_failed")
        cls.value = json.loads(result.stdout)

    def test_guard_rejects_non_hosted_or_wrong_typed_inputs_before_effects(self):
        self.assertEqual(self.value["guard"], [True] + [False] * 8)
        self.assertIs(self.value["guard_before_effects"], True)

    def test_each_fixed_source_has_the_required_initial_and_preservation_read_bound(self):
        self.assertEqual(self.value["source_limits"], [65536, 65536, 65536, 131072])
        self.assertEqual(self.value["bounded_reads"], [True] * 12)
        self.assertEqual(self.value["invalid_limits"], [True] * 6)
        self.assertIs(self.value["both_source_reads_bound"], True)

    def test_exact_final_snapshots_for_one_and_two_short_lived_children(self):
        self.assertEqual(self.value["positive_snapshots"], [True, True, True])
        self.assertIs(self.value["native_dictionary_diagnostic"]["snapshot_valid"], True)
        self.assertGreater(len(self.value["rejected_snapshots"]), 40)
        self.assertTrue(all(value is False for value in self.value["rejected_snapshots"]))

    def test_reports_are_closed_and_never_claim_production_or_live_image_acceptance(self):
        passed, failed, changed, unavailable = self.value["reports"]
        fields = {"schema_version", "scope", "result", "cases", "source_sha256", "inert_sha256", "errors",
                  "production_application_executed", "provider_accepted", "application_accepted", "live_image_observation"}
        for report in self.value["reports"]:
            self.assertEqual(set(report), fields)
            self.assertEqual(report["schema_version"], 1)
            self.assertEqual(report["scope"], "hosted_inert_launch_observer_probe")
            self.assertEqual(set(report["cases"]), {"single_fast_child", "two_sequential_children"})
            self.assertEqual(set(report["source_sha256"]), {"probe", "source_probe", "private_creator", "session_helper"})
            for flag in ("production_application_executed", "provider_accepted", "application_accepted", "live_image_observation"):
                self.assertIs(report[flag], False)
            for case in report["cases"].values():
                self.assertEqual(set(case), {"result", "checks", "cleanup_complete", "tree_retained", "errors"})
                self.assertEqual(set(case["checks"]), CHECKS)
                self.assertTrue(all(type(value) is bool for value in case["checks"].values()))
        self.assertEqual([row["result"] for row in (passed, failed, changed, unavailable)],
                         ["passed", "failed", "failed", "unavailable"])
        self.assertEqual(changed["errors"], ["source_changed"])
        self.assertEqual(unavailable["errors"], ["hosted_only"])

    def test_primary_and_cleanup_failure_both_survive(self):
        combined = self.value["combined_failure"]
        self.assertEqual(combined["errors"], ["observation_failed", "cleanup_failed"])
        self.assertIs(combined["cleanup_complete"], False)
        self.assertIs(combined["tree_retained"], True)
        self.assertEqual(self.value["clean_failure"]["errors"], ["transcript_failed"])
        self.assertIs(self.value["clean_failure"]["cleanup_complete"], True)

    def test_failure_diagnostic_is_typed_finite_and_does_not_accept_unknown_fields_or_text(self):
        failed, wrong_hash, *invalid = self.value["diagnostics"]
        self.assertIs(failed["snapshot_valid"], True)
        self.assertEqual(failed["errors"], ["debug_launch_limit", "debug_cleanup_failed"])
        self.assertEqual((failed["expected_launches"], failed["runtime_launch_count"]), (2, 1))
        self.assertIs(failed["debug_handles_closed"], False)
        self.assertIs(wrong_hash["hash_matches"], False)
        for row in invalid:
            self.assertIs(row["snapshot_valid"], False)
            self.assertEqual(row["errors"], ["snapshot_invalid"])
            self.assertIsNone(row["runtime_launch_count"])
            self.assertIsNone(row["debug_handles_closed"])
        self.assertNotIn("private-canary", json.dumps(self.value["diagnostics"]))

    def test_create_failure_record_is_closed_with_nullable_facts_and_event_ordinal_bounds(self):
        fields = {"schema_version", "diagnostic_valid", "event_ordinal", "image_role", "owned_job", "image_path_matches"}
        rows = self.value["create_diagnostics"]
        self.assertEqual([row["image_role"] for row in rows[:5]],
                         ["application_path", "runtime_path", "system_console_host", "other", "unavailable"])
        for row in rows:
            self.assertEqual(set(row), fields)
            self.assertEqual(row["schema_version"], 1)
            self.assertIs(row["diagnostic_valid"], True)
        self.assertEqual([row["event_ordinal"] for row in rows], [57] * 5 + [1, 4096])
        self.assertIsNone(rows[5]["owned_job"])
        self.assertIsNone(rows[5]["image_path_matches"])
        self.assertIs(rows[6]["owned_job"], False)
        self.assertIs(rows[6]["image_path_matches"], True)

    def test_malformed_create_record_becomes_one_fixed_private_text_free_invalid_record(self):
        expected = {"schema_version": 1, "diagnostic_valid": False, "event_ordinal": None,
                    "image_role": "unavailable", "owned_job": None, "image_path_matches": None}
        self.assertEqual(len(self.value["invalid_create_diagnostics"]), 20)
        self.assertTrue(all(row == expected for row in self.value["invalid_create_diagnostics"]))
        self.assertNotIn("private-canary", json.dumps(self.value["invalid_create_diagnostics"]))

    def test_throwing_or_empty_getter_cannot_mask_failure_and_is_only_consumed_after_failed_finalization(self):
        records = self.value["getter_records"]
        self.assertIs(records[0]["diagnostic_valid"], True)
        self.assertTrue(all(row["diagnostic_valid"] is False for row in records[1:]))
        self.assertEqual(self.value["getter_calls"], 3)
        self.assertIs(self.value["create_diagnostic_failure_only"], True)
        self.assertNotIn("private-canary", json.dumps(records))

    def test_missing_checks_forged_fields_hashes_and_partial_cleanup_cannot_pass(self):
        self.assertGreaterEqual(len(self.value["invalid_reports"]), 17)
        self.assertTrue(all(self.value["invalid_reports"]))
        self.assertNotIn("private-canary", json.dumps(self.value))

    def test_support_extraction_copies_exact_reviewed_cleanup_and_refuses_ambiguous_source(self):
        self.assertIs(self.value["exact_extraction"], True)
        self.assertEqual(self.value["rejected_extractions"], [True] * 7)

    def test_literals_compile_but_native_probe_and_inert_main_are_never_invoked(self):
        self.assertEqual(self.value["compiled_literal_classes"], 2)
        self.assertIs(self.value["inert_entry_shape"], True)
        self.assertEqual(self.value["native_calls"], 0)
        self.assertIs(self.value["native_entrypoint_invoked"], False)

    def test_launch_is_always_finalized_before_buffered_transcript_is_read(self):
        self.assertIs(self.value["finalize_before_transcript"], True)


if __name__ == "__main__":
    unittest.main()
