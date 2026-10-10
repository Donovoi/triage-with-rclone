# Hosted-only qualification of an inert launch-image observer, never a provider test.
[CmdletBinding()]
param()
Set-StrictMode -Version Latest
$ErrorActionPreference='Stop'
$ProgressPreference='SilentlyContinue'

function Test-LaunchHosted($Actions,$Runner,$Environment,$Edition,$Windows,$Bits64) {
    return ($Actions -is [string] -and $Actions -ceq 'true' -and $Runner -is [string] -and $Runner -ceq 'Windows' -and
        $Environment -is [string] -and $Environment -ceq 'github-hosted' -and $Edition -is [string] -and $Edition -ceq 'Desktop' -and
        $Windows -is [bool] -and $Windows -and $Bits64 -is [bool] -and $Bits64)
}
function Get-LaunchSupport([string]$Source) {
    $tokens=$null; $errors=$null
    $ast=[System.Management.Automation.Language.Parser]::ParseInput($Source,[ref]$tokens,[ref]$errors)
    if ($errors.Count -ne 0 -or $Source.Length -gt 65536) { throw 'setup_failed' }
    $names=@('Get-ProbeCreator','Assert-Probe','Check-ProbeTime','New-ProbeDirectory','Write-ProbeFile','Read-ProbeFile','Hash-Probe')
    $definitions=@()
    foreach ($name in $names) {
        $all=@($ast.FindAll({param($n) $n -is [System.Management.Automation.Language.FunctionDefinitionAst] -and $n.Name -ceq $name},$true))
        $top=@($ast.EndBlock.Statements | Where-Object { $_ -is [System.Management.Automation.Language.FunctionDefinitionAst] -and $_.Name -ceq $name })
        if ($all.Count -ne 1 -or $top.Count -ne 1) { throw 'setup_failed' }
        $definitions+=$top[0].Extent.Text
    }
    $literals=@($ast.FindAll({param($n)
        $n -is [System.Management.Automation.Language.StringConstantExpressionAst] -and
        $n.StringConstantType -eq [System.Management.Automation.Language.StringConstantType]::SingleQuotedHereString -and
        $n.Value.Contains('public static class SourceProbeOwnedTree {')
    },$true))
    if ($literals.Count -ne 1 -or $literals[0].Value.Length -gt 32768) { throw 'setup_failed' }
    $command=$literals[0].Parent
    if ($command -isnot [System.Management.Automation.Language.CommandAst] -or $command.GetCommandName() -cne 'Add-Type') { throw 'setup_failed' }
    $elements=$command.CommandElements; $index=[Array]::IndexOf([object[]]$elements,$literals[0])
    if ($index -lt 2 -or $elements[$index-1] -isnot [System.Management.Automation.Language.CommandParameterAst] -or
        $elements[$index-1].ParameterName -cne 'TypeDefinition' -or $null -ne $elements[$index-1].Argument) { throw 'setup_failed' }
    return [ordered]@{ functions=$definitions; cleanup=$literals[0].Value }
}
function Test-LaunchInteger($Value,[long]$Min,[long]$Max) {
    return (($Value -is [int] -or $Value -is [long] -or $Value -is [uint32]) -and $Value -ge $Min -and $Value -le $Max)
}
function Test-LaunchSnapshot($Value,[int]$Expected,[string]$Sha256) {
    # Helper counts qualify these two inert scenarios, not a general Windows ratio.
    # The helper hash is an installed-object witness, not a signer or ancestry claim.
    $names=@('schema_version','ok','state','app_exit_code','runtime_image_observed','runtime_sha256','runtime_process_count',
        'ctrl_c_sent','output_bytes','output_limit_exceeded','forced_termination','app_exited','observed_children_exited',
        'job_zero_confirmed','reader_joined','conpty_closed','errors','observation_kind','launch_image_observed','launch_sha256',
        'runtime_launch_count','peak_runtime_processes','debug_event_count','debug_events_drained','debug_pump_joined','debug_handles_closed',
        'system_helper_image_observed','system_helper_sha256','system_helper_launch_count','peak_system_helper_processes','system_helper_reference_closed')
    if ($Expected -notin @(1,2) -or $Sha256 -cnotmatch '\A[0-9a-f]{64}\z' -or $Value -isnot [Collections.IDictionary] -or $Value.Count -ne $names.Count) { return $false }
    foreach ($name in $names) { if (-not ([Collections.IDictionary]$Value).Contains($name)) { return $false } }
    foreach ($name in @('ok','app_exited','observed_children_exited','job_zero_confirmed','reader_joined','conpty_closed',
        'launch_image_observed','debug_events_drained','debug_pump_joined','debug_handles_closed','system_helper_image_observed','system_helper_reference_closed')) {
        if ($Value[$name] -isnot [bool] -or -not $Value[$name]) { return $false }
    }
    foreach ($name in @('runtime_image_observed','ctrl_c_sent','output_limit_exceeded','forced_termination')) {
        if ($Value[$name] -isnot [bool] -or $Value[$name]) { return $false }
    }
    return ((Test-LaunchInteger $Value.schema_version 3 3) -and (Test-LaunchInteger $Value.app_exit_code 0 0) -and
        $Value.state -is [string] -and $Value.state -ceq 'finished' -and $Value.observation_kind -is [string] -and
        $Value.observation_kind -ceq 'launch_image' -and $Value.launch_sha256 -is [string] -and $Value.launch_sha256 -ceq $Sha256 -and
        $null -eq $Value.runtime_sha256 -and $null -eq $Value.runtime_process_count -and
        (Test-LaunchInteger $Value.runtime_launch_count $Expected $Expected) -and (Test-LaunchInteger $Value.peak_runtime_processes 1 1) -and
        $Value.system_helper_sha256 -is [string] -and $Value.system_helper_sha256 -cmatch '\A[0-9a-f]{64}\z' -and
        (Test-LaunchInteger $Value.system_helper_launch_count $Expected $Expected) -and
        (Test-LaunchInteger $Value.peak_system_helper_processes 1 ([Math]::Min($Expected,2))) -and
        (Test-LaunchInteger $Value.debug_event_count (2*($Expected+1)) 4096) -and (Test-LaunchInteger $Value.output_bytes 1 65536) -and
        $Value.errors -is [Array] -and $Value.errors.Count -eq 0)
}
function New-LaunchDiagnostic($Value,[int]$Expected,[string]$Sha256) {
    if ($Expected -notin @(1,2) -or $Sha256 -cnotmatch '\A[0-9a-f]{64}\z') { throw 'report_invalid' }
    $row=[ordered]@{ schema_version=1; expected_launches=$Expected; snapshot_valid=$false; errors=@('snapshot_invalid');
        launch_image_observed=$null; hash_matches=$null; legacy_fields_clear=$null; finished=$null; app_exit_code=$null;
        runtime_launch_count=$null; peak_runtime_processes=$null; debug_event_count=$null;
        app_exited=$null; observed_children_exited=$null; job_zero_confirmed=$null; reader_joined=$null; conpty_closed=$null;
        forced_termination=$null; debug_events_drained=$null; debug_pump_joined=$null; debug_handles_closed=$null;
        system_helper_image_observed=$null; system_helper_hash_present=$null; system_helper_launch_count=$null;
        peak_system_helper_processes=$null; system_helper_reference_closed=$null }
    $allowed=@('console_cleanup_failed','console_cleanup_timeout','ctrl_c_refused','deadline_exceeded','debug_cleanup_failed',
        'debug_start_failed','debug_event_failed','debug_image_invalid','debug_launch_limit','debug_exception_failed','debug_event_limit',
        'forced_termination','input_cleanup_failed','input_failed','input_timeout','job_assignment_failed','job_query_failed',
        'output_limit_exceeded','process_cleanup_failed','process_observation_failed','protocol_invalid','reader_cleanup_failed',
        'reader_failed','resize_cleanup_failed','resize_failed','runtime_observation_failed','source_directory_cleanup_failed',
        'source_directory_invalid','start_failed','termination_failed')
    $names=@('schema_version','ok','state','app_exit_code','runtime_image_observed','runtime_sha256','runtime_process_count',
        'ctrl_c_sent','output_bytes','output_limit_exceeded','forced_termination','app_exited','observed_children_exited',
        'job_zero_confirmed','reader_joined','conpty_closed','errors','observation_kind','launch_image_observed','launch_sha256',
        'runtime_launch_count','peak_runtime_processes','debug_event_count','debug_events_drained','debug_pump_joined','debug_handles_closed',
        'system_helper_image_observed','system_helper_sha256','system_helper_launch_count','peak_system_helper_processes','system_helper_reference_closed')
    if ($Value -isnot [Collections.IDictionary] -or $Value.Count -ne $names.Count) { return $row }
    foreach ($name in $names) { if (-not ([Collections.IDictionary]$Value).Contains($name)) { return $row } }
    foreach ($name in @('ok','runtime_image_observed','ctrl_c_sent','output_limit_exceeded','forced_termination','app_exited',
        'observed_children_exited','job_zero_confirmed','reader_joined','conpty_closed','launch_image_observed',
        'debug_events_drained','debug_pump_joined','debug_handles_closed','system_helper_image_observed','system_helper_reference_closed')) { if ($Value[$name] -isnot [bool]) { return $row } }
    if (-not (Test-LaunchInteger $Value.schema_version 3 3) -or $Value.state -isnot [string] -or $Value.state -cnotin @('running','finished') -or
        $Value.observation_kind -isnot [string] -or $Value.observation_kind -cne 'launch_image' -or
        -not (Test-LaunchInteger $Value.runtime_launch_count 0 32) -or -not (Test-LaunchInteger $Value.peak_runtime_processes 0 4) -or
        -not (Test-LaunchInteger $Value.system_helper_launch_count 0 32) -or -not (Test-LaunchInteger $Value.peak_system_helper_processes 0 3) -or
        -not (Test-LaunchInteger $Value.debug_event_count 0 4096) -or -not (Test-LaunchInteger $Value.output_bytes 0 65536) -or
        ($null -ne $Value.app_exit_code -and -not (Test-LaunchInteger $Value.app_exit_code 0 4294967295)) -or
        ($null -ne $Value.runtime_process_count -and -not (Test-LaunchInteger $Value.runtime_process_count 0 4)) -or
        $Value.errors -isnot [Array] -or $Value.errors.Count -gt $allowed.Count) { return $row }
    foreach ($name in @('launch_sha256','runtime_sha256','system_helper_sha256')) {
        if ($null -ne $Value[$name] -and ($Value[$name] -isnot [string] -or $Value[$name] -cnotmatch '\A[0-9a-f]{64}\z')) { return $row }
    }
    $seen=@()
    foreach ($code in $Value.errors) {
        if ($code -isnot [string] -or $code -cnotin $allowed -or $code -cin $seen) { return $row }; $seen+=@($code)
    }
    $row.snapshot_valid=$true; $row.errors=$seen
    foreach ($name in @('launch_image_observed','app_exit_code','runtime_launch_count','peak_runtime_processes','debug_event_count',
        'app_exited','observed_children_exited','job_zero_confirmed','reader_joined','conpty_closed','forced_termination',
        'debug_events_drained','debug_pump_joined','debug_handles_closed','system_helper_image_observed','system_helper_launch_count',
        'peak_system_helper_processes','system_helper_reference_closed')) { $row[$name]=$Value[$name] }
    $row.hash_matches=$Value.launch_sha256 -ceq $Sha256
    $row.legacy_fields_clear=-not $Value.runtime_image_observed -and $null -eq $Value.runtime_sha256 -and $null -eq $Value.runtime_process_count
    $row.finished=$Value.state -ceq 'finished'
    $row.system_helper_hash_present=$null -ne $Value.system_helper_sha256
    return $row
}
function Convert-LaunchFailureDiagnostic($Value) {
    # This separate diagnostic never supplies launch, acceptance or cleanup proof.
    $row=[ordered]@{ schema_version=1; diagnostic_valid=$false; event_ordinal=$null;
        image_role='unavailable'; owned_job=$null; image_path_matches=$null }
    $names=@('schema_version','event_ordinal','image_role','owned_job','image_path_matches')
    if ($Value -isnot [Collections.IDictionary] -or $Value.Count -ne $names.Count) { return $row }
    foreach ($name in $names) { if (-not ([Collections.IDictionary]$Value).Contains($name)) { return $row } }
    if ($Value.schema_version -isnot [int] -or $Value.schema_version -ne 1 -or
        $Value.event_ordinal -isnot [int] -or $Value.event_ordinal -lt 1 -or $Value.event_ordinal -gt 4096 -or
        $Value.image_role -isnot [string] -or
        $Value.image_role -cnotin @('application_path','runtime_path','system_console_host','other','unavailable')) { return $row }
    foreach ($name in @('owned_job','image_path_matches')) {
        if ($null -ne $Value[$name] -and $Value[$name] -isnot [bool]) { return $row }
    }
    $row.diagnostic_valid=$true
    foreach ($name in @('event_ordinal','image_role','owned_job','image_path_matches')) { $row[$name]=$Value[$name] }
    return $row
}
function Get-LaunchFailureDiagnostic($Session) {
    $value=$null
    if ($null -ne $Session) {
        try { $value=$Session.LaunchFailureDiagnostic() } catch { $value=$null }
    }
    return Convert-LaunchFailureDiagnostic $value
}
function New-LaunchChecks([bool]$Value) {
    $checks=[ordered]@{}
    foreach ($name in @('source_cwd','descendant_cwd','source_preserved','launch_count_exact','launch_hash_exact','peak_one',
        'launch_only','transient_images_deleted','transcript_exact','session_cleanup','observer_cleanup','system_helper_observed',
        'system_helper_hash_present','system_helper_count_exact','system_helper_peak_bounded','system_helper_reference_closed')) { $checks[$name]=$Value }
    return $checks
}
function New-LaunchCase([Collections.IDictionary]$Checks,[string]$Failure,[bool]$Cleanup,[bool]$Retained,$HelperSha=$null) {
    $names=New-LaunchChecks $false
    $allowed=@('not_run','hosted_only','setup_failed','compile_failed','launch_failed','observation_failed','transcript_failed',
        'preservation_failed','cleanup_failed','deadline_exceeded','unexpected_failure')
    if ($null -eq $Checks -or $Checks.Count -ne $names.Count -or ($Failure -cne '' -and $Failure -cnotin $allowed) -or
        ($Cleanup -and $Retained) -or (-not $Cleanup -and -not $Retained)) { throw 'report_invalid' }
    $closed=[ordered]@{}
    foreach ($name in $names.Keys) {
        if (-not $Checks.Contains($name) -or $Checks[$name] -isnot [bool]) { throw 'report_invalid' }; $closed[$name]=$Checks[$name]
    }
    if ($null -ne $HelperSha -and ($HelperSha -isnot [string] -or $HelperSha -cnotmatch '\A[0-9a-f]{64}\z')) { throw 'report_invalid' }
    if (($closed.system_helper_observed -or $closed.system_helper_hash_present) -and $null -eq $HelperSha) { throw 'report_invalid' }
    if (-not $closed.system_helper_observed -and $null -ne $HelperSha) { throw 'report_invalid' }
    $passed=$Failure -ceq '' -and $Cleanup -and @($closed.Values | Where-Object { -not $_ }).Count -eq 0
    if (-not $passed -and $Failure -ceq '') { throw 'report_invalid' }
    if ($Failure -cin @('not_run','hosted_only') -and (@($closed.Values | Where-Object { $_ }).Count -ne 0 -or -not $Cleanup)) { throw 'report_invalid' }
    $errors=@(); if ($Failure -cne '') { $errors+=@($Failure) }
    if (-not $Cleanup -and $Failure -cne 'cleanup_failed') { $errors+=@('cleanup_failed') }
    return [ordered]@{ result=$(if ($passed) { 'passed' } elseif ($Failure -ceq 'not_run') { 'not_run' } else { 'failed' });
        checks=$closed; system_helper_sha256=$HelperSha; cleanup_complete=$Cleanup; tree_retained=$Retained; errors=$errors }
}
function New-LaunchReport([Collections.IDictionary]$Cases,[Collections.IDictionary]$Sources,$InertSha,[string]$Failure) {
    if ($Cases.Count -ne 2 -or $Sources.Count -ne 4 -or $Failure -cnotin @('','hosted_only','setup_failed','compile_failed','source_changed','unexpected_failure')) { throw 'report_invalid' }
    $closed=[ordered]@{}
    foreach ($name in @('single_fast_child','two_sequential_children')) {
        if (-not $Cases.Contains($name) -or $Cases[$name] -isnot [Collections.IDictionary] -or $Cases[$name].Count -ne 6) { throw 'report_invalid' }
        $row=$Cases[$name]
        foreach ($key in @('result','checks','system_helper_sha256','cleanup_complete','tree_retained','errors')) { if (-not $row.Contains($key)) { throw 'report_invalid' } }
        if ($row.cleanup_complete -isnot [bool] -or $row.tree_retained -isnot [bool] -or $row.errors -isnot [Array] -or $row.errors.Count -gt 2) { throw 'report_invalid' }
        $error=''; if ($row.errors.Count -gt 0) { if ($row.errors[0] -isnot [string]) { throw 'report_invalid' }; $error=$row.errors[0] }
        $verified=New-LaunchCase $row.checks $error $row.cleanup_complete $row.tree_retained $row.system_helper_sha256
        if ($row.result -cne $verified.result -or ($row.errors -join ',') -cne ($verified.errors -join ',')) { throw 'report_invalid' }
        $closed[$name]=$verified
    }
    $hashes=[ordered]@{}
    foreach ($name in @('probe','source_probe','private_creator','session_helper')) {
        if (-not $Sources.Contains($name) -or ($null -ne $Sources[$name] -and ($Sources[$name] -isnot [string] -or $Sources[$name] -cnotmatch '\A[0-9a-f]{64}\z'))) { throw 'report_invalid' }
        $hashes[$name]=$Sources[$name]
    }
    if ($null -ne $InertSha -and ($InertSha -isnot [string] -or $InertSha -cnotmatch '\A[0-9a-f]{64}\z')) { throw 'report_invalid' }
    $passed=$Failure -ceq '' -and @($closed.Values | Where-Object { $_.result -cne 'passed' }).Count -eq 0
    if ($passed -and ($null -eq $InertSha -or @($hashes.Values | Where-Object { $null -eq $_ }).Count -ne 0)) { throw 'report_invalid' }
    $errors=@(); if ($Failure -cne '') { $errors=@($Failure) }
    return [ordered]@{ schema_version=2; scope='hosted_inert_launch_observer_probe'; result=$(if ($passed) { 'passed' } elseif ($Failure -ceq 'hosted_only') { 'unavailable' } else { 'failed' });
        cases=$closed; source_sha256=$hashes; inert_sha256=$InertSha; errors=$errors;
        production_application_executed=$false; provider_accepted=$false; application_accepted=$false; live_image_observation=$false }
}
function Get-LaunchSourceLimit($Name) {
    if ($Name -isnot [string]) { throw 'setup_failed' }
    if ($Name -ceq 'session_helper') { return 131072 }
    if ($Name -cin @('probe','source_probe','private_creator')) { return 65536 }
    throw 'setup_failed'
}
function Read-LaunchSource([string]$Path,$Name) {
    # Bootstrap bounded source read; the reviewed helper is extracted only afterward.
    $limit=Get-LaunchSourceLimit $Name
    if (([IO.File]::GetAttributes($Path) -band ([IO.FileAttributes]::Directory -bor [IO.FileAttributes]::ReparsePoint)) -ne 0) { throw 'setup_failed' }
    $file=[IO.FileStream]::new($Path,[IO.FileMode]::Open,[IO.FileAccess]::Read,[IO.FileShare]::Read)
    try {
        if ($file.Length -le 0 -or $file.Length -gt $limit) { throw 'setup_failed' }
        $bytes=[byte[]]::new([int]$file.Length); $offset=0
        while ($offset -lt $bytes.Length) { $n=$file.Read($bytes,$offset,$bytes.Length-$offset); if ($n -eq 0) { throw 'setup_failed' }; $offset+=$n }
        if ($file.ReadByte() -ne -1) { throw 'setup_failed' }; return ,$bytes
    } finally { $file.Dispose() }
}
function Invoke-LaunchCase([int]$Count,[string]$Parent) {
    if ($Count -notin @(1,2)) { throw 'setup_failed' }
    $checks=New-LaunchChecks $false; $failure=''; $phase='setup_failed'
    $sandbox=$null; $owned=$false; $cleanup=$false; $session=$null; $sessionClosed=$true; $compilerClosed=$true; $final=$null; $sha=$null; $helperSha=$null
    $oldTemp=$env:TEMP; $oldTmp=$env:TMP
    $identities=[Collections.Generic.Dictionary[string,string]]::new([StringComparer]::OrdinalIgnoreCase)
    try {
        Check-ProbeTime
        $sandbox=[IO.Path]::Combine($Parent,'app-filesystem-'+[Guid]::NewGuid().ToString('N'))
        New-ProbeDirectory $sandbox; $owned=$true; $identities.Add($sandbox,[SourceProbeOwnedTree]::Capture($sandbox))
        $case=[IO.Path]::Combine($sandbox,'launch-observer-probe'); New-ProbeDirectory $case
        $identities.Add($case,[SourceProbeOwnedTree]::Capture($case))
        $source=[IO.Path]::Combine($case,'source'); New-ProbeDirectory $source
        $identities.Add($source,[SourceProbeOwnedTree]::Capture($source))
        $sourceFile=[IO.Path]::Combine($source,'probe-source.txt'); $payload=[Text.Encoding]::ASCII.GetBytes("synthetic launch cwd`n")
        Write-ProbeFile $sourceFile $payload
        foreach ($name in @('temp','home','profile','appdata','localappdata')) { New-ProbeDirectory ([IO.Path]::Combine($case,$name)) }
        $env:TEMP=[IO.Path]::Combine($case,'temp'); $env:TMP=$env:TEMP
        if ($null -eq $script:inertBytes) {
            $phase='compile_failed'; $compilerClosed=$false; $compiled=[IO.Path]::Combine($case,'compiled.private.exe')
            Add-Type -OutputAssembly $compiled -OutputType ConsoleApplication -ErrorAction Stop -WarningAction SilentlyContinue -TypeDefinition @'
using System;
using System.Diagnostics;
using System.IO;
public static class InertLaunchObserverProbe {
  public static int Main(string[] args) {
    try {
      if(args.Length!=3 || (args[0]!="parent" && args[0]!="child") || (args[1]!="1" && args[1]!="2")) return 10;
      if(!String.Equals(Path.GetFullPath(Environment.CurrentDirectory),args[2],StringComparison.OrdinalIgnoreCase)) return 11;
      if(File.ReadAllText("probe-source.txt")!="synthetic launch cwd\n") return 12;
      if(args[0]=="child") return 0;
      int count=args[1]=="1"?1:2;
      for(int i=1;i<=count;i++) {
        string dir=Path.Combine(Environment.GetEnvironmentVariable("TEMP"),"rclone-triage-launch"+i);
        string image=Path.Combine(dir,"rclone.exe");
        var start=new ProcessStartInfo(image,"child "+args[1]+" \""+args[2]+"\"");
        start.UseShellExecute=false; start.CreateNoWindow=true;
        using(var child=Process.Start(start)) {
          if(child==null) return 13;
          if(!child.WaitForExit(3000)) { try { child.Kill(); child.WaitForExit(1000); } catch {} return 14; }
          if(child.ExitCode!=0) return 15;
        }
        // A retained observer image/directory pin makes either deletion fail.
        // No retries or repair: only an immediately successful deletion qualifies.
        File.Delete(image); Directory.Delete(dir,false);
      }
      Console.WriteLine(count==1?"LAUNCH_PROBE_ONE_OK":"LAUNCH_PROBE_TWO_OK"); Console.Out.Flush(); return 0;
    } catch { return 16; }
  }
}
'@ 2>$null
            $compilerClosed=$true
            $script:inertBytes=Read-ProbeFile $compiled 1048576
            [IO.File]::Delete($compiled)
        }
        $phase='setup_failed'; $sha=Hash-Probe $script:inertBytes
        $app=[IO.Path]::Combine($case,'application.exe'); Write-ProbeFile $app $script:inertBytes
        for ($i=1; $i -le $Count; $i++) {
            $directory=[IO.Path]::Combine($env:TEMP,'rclone-triage-launch'+$i); New-ProbeDirectory $directory
            Write-ProbeFile ([IO.Path]::Combine($directory,'rclone.exe')) $script:inertBytes
        }
        $environment=[Collections.Generic.Dictionary[string,string]]::new([StringComparer]::OrdinalIgnoreCase)
        $environment.Add('SYSTEMROOT',[Environment]::GetFolderPath([Environment+SpecialFolder]::Windows))
        $environment.Add('PATH',[Environment]::SystemDirectory)
        foreach ($entry in @(@('TEMP','temp'),@('TMP','temp'),@('HOME','home'),@('USERPROFILE','profile'),@('APPDATA','appdata'),@('LOCALAPPDATA','localappdata'))) {
            $environment.Add($entry[0],[IO.Path]::Combine($case,$entry[1]))
        }
        $transcript=[IO.Path]::Combine($case,'transcript.private'); $phase='launch_failed'; $sessionClosed=$false
        try {
            $session=[TriageApplicationLab.HostedConPtySession]::StartSourceObserved($app,$sha,[string[]]@('parent',[string]$Count,$source),
                $case,$environment,$transcript,65536,30000,1,$sha,$Count)
            Check-ProbeTime
        } catch {
            $failure=$phase
            $cause=$_.Exception; while ($null -ne $cause.InnerException) { $cause=$cause.InnerException }
            if ($cause.Message -ceq 'deadline_exceeded') { $failure='deadline_exceeded' }
        } finally {
            if ($null -ne $session) {
                # Normal readers flush only during Finish. Never poll transcript tokens before it.
                try {
                    $null=$session.Finish(10000)
                    $final=$session.LaunchSnapshot()
                    $sessionClosed=Test-LaunchSnapshot $final $Count $sha
                } catch { $sessionClosed=$false; if ($failure -ceq '') { $failure='cleanup_failed' } }
            }
        }
        $phase='observation_failed'; Assert-Probe $sessionClosed 'observation_failed'
        $helperSha=$final.system_helper_sha256
        foreach ($name in @('launch_count_exact','launch_hash_exact','peak_one','launch_only','session_cleanup','observer_cleanup',
            'system_helper_observed','system_helper_hash_present','system_helper_count_exact','system_helper_peak_bounded','system_helper_reference_closed')) { $checks[$name]=$true }
        $phase='transcript_failed'
        $text=[Text.Encoding]::ASCII.GetString((Read-ProbeFile $transcript 65536))
        $token=$(if ($Count -eq 1) { 'LAUNCH_PROBE_ONE_OK' } else { 'LAUNCH_PROBE_TWO_OK' })
        # ConPTY may surround the literal with controls. The sole writer is our exact inert image.
        Assert-Probe ([regex]::Matches($text,'LAUNCH_PROBE_(ONE|TWO)_OK').Count -eq 1 -and $text.Contains($token)) 'transcript_failed'
        $checks.transcript_exact=$true; $checks.source_cwd=$true; $checks.descendant_cwd=$true
        $phase='preservation_failed'
        $n=0
        foreach ($entry in [IO.Directory]::EnumerateFileSystemEntries($source)) { $n++; Assert-Probe ($n -eq 1 -and $entry -ceq $sourceFile) 'preservation_failed' }
        Assert-Probe ($n -eq 1 -and (Hash-Probe (Read-ProbeFile $sourceFile 128)) -ceq (Hash-Probe $payload)) 'preservation_failed'
        $checks.source_preserved=$true
        # After the parent's successful deletion, no runtime image/directory may remain in temp.
        # Compilation leftovers are also refused, rather than silently normalized away.
        foreach ($entry in [IO.Directory]::EnumerateFileSystemEntries($env:TEMP)) { throw 'preservation_failed' }
        $checks.transient_images_deleted=$true
    } catch {
        if ($failure -ceq '') { $failure=$phase }
        $cause=$_.Exception; while ($null -ne $cause.InnerException) { $cause=$cause.InnerException }
        if ($cause.Message -ceq 'deadline_exceeded') { $failure='deadline_exceeded' }
    } finally {
        $env:TEMP=$oldTemp; $env:TMP=$oldTmp
        if ($null -eq $sandbox) { $cleanup=$true }
        elseif ($owned -and $sessionClosed -and $compilerClosed -and $identities.Count -eq 3) {
            try { [SourceProbeOwnedTree]::Remove($sandbox,$identities); $cleanup=$true } catch { $cleanup=$false }
        }
        if (-not $cleanup -and $failure -ceq '') { $failure='cleanup_failed' }
    }
    if (-not $sessionClosed -and $null -ne $sha) {
        [Console]::Out.WriteLine('launch_observer_failure='+(New-LaunchDiagnostic $final $Count $sha | ConvertTo-Json -Depth 3 -Compress))
        [Console]::Out.WriteLine('launch_observer_create_failure='+(Get-LaunchFailureDiagnostic $session | ConvertTo-Json -Depth 3 -Compress))
    }
    return New-LaunchCase $checks $failure $cleanup ($null -ne $sandbox -and -not $cleanup) $helperSha
}

$cases=[ordered]@{ single_fast_child=(New-LaunchCase (New-LaunchChecks $false) 'not_run' $true $false);
    two_sequential_children=(New-LaunchCase (New-LaunchChecks $false) 'not_run' $true $false) }
$hashes=[ordered]@{ probe=$null; source_probe=$null; private_creator=$null; session_helper=$null }
# No source reads, identity calls, compilation or filesystem mutation before this real guard.
if (-not (Test-LaunchHosted $env:GITHUB_ACTIONS $env:RUNNER_OS $env:RUNNER_ENVIRONMENT $PSVersionTable.PSEdition ([Environment]::OSVersion.Platform -eq [PlatformID]::Win32NT) ([Environment]::Is64BitProcess))) {
    [Console]::Out.WriteLine((New-LaunchReport $cases $hashes $null 'hosted_only' | ConvertTo-Json -Depth 7 -Compress)); exit 2
}
$script:clock=[Diagnostics.Stopwatch]::StartNew(); $script:inertBytes=$null; $failure=''; $phase='setup_failed'
try {
    $paths=[ordered]@{ probe=$PSCommandPath; source_probe=(Join-Path $PSScriptRoot 'probe_source_directory.ps1');
        private_creator=(Join-Path $PSScriptRoot 'prepare_case.ps1'); session_helper=(Join-Path $PSScriptRoot 'HostedConPtySession.cs') }
    $bytes=[ordered]@{}; foreach ($key in $paths.Keys) { $bytes[$key]=Read-LaunchSource $paths[$key] $key }
    $utf8=[Text.UTF8Encoding]::new($false,$true)
    $support=Get-LaunchSupport ($utf8.GetString($bytes.source_probe))
    foreach ($definition in $support.functions) { . ([scriptblock]::Create($definition)) }
    foreach ($key in $paths.Keys) { $hashes[$key]=Hash-Probe $bytes[$key] }
    $creator=Get-ProbeCreator ($utf8.GetString($bytes.private_creator)); $phase='compile_failed'
    Add-Type -TypeDefinition $creator -ErrorAction Stop -WarningAction SilentlyContinue 2>$null
    Add-Type -TypeDefinition $support.cleanup -ErrorAction Stop -WarningAction SilentlyContinue 2>$null
    Add-Type -TypeDefinition ($utf8.GetString($bytes.session_helper)) -ErrorAction Stop -WarningAction SilentlyContinue 2>$null
    $phase='setup_failed'
    $script:userSid=[Security.Principal.WindowsIdentity]::GetCurrent().User
    $script:systemSid=[Security.Principal.SecurityIdentifier]::new('S-1-5-18')
    $parent=[IO.Path]::GetFullPath($env:RUNNER_TEMP)
    Assert-Probe ($parent.Length -gt 3 -and $parent.Length -lt 2048 -and $parent -cmatch '\A[A-Za-z]:[\\/]' -and -not $parent.StartsWith('\\')) 'setup_failed'
    $ancestors=0
    for ($node=[IO.DirectoryInfo]::new($parent); $null -ne $node; $node=$node.Parent) {
        $ancestors++; Assert-Probe ($ancestors -le 64 -and $node.Exists -and ($node.Attributes -band [IO.FileAttributes]::ReparsePoint) -eq 0) 'setup_failed'
    }
    $cases.single_fast_child=Invoke-LaunchCase 1 $parent
    if ($cases.single_fast_child.result -ceq 'passed') { $cases.two_sequential_children=Invoke-LaunchCase 2 $parent }
    $phase='source_changed'
    foreach ($key in $paths.Keys) { Assert-Probe ((Hash-Probe (Read-LaunchSource $paths[$key] $key)) -ceq $hashes[$key]) 'source_changed' }
} catch { $failure=$phase }
$inertSha=$null; if ($null -ne $script:inertBytes) { $inertSha=Hash-Probe $script:inertBytes }
$report=New-LaunchReport $cases $hashes $inertSha $failure
[Console]::Out.WriteLine(($report | ConvertTo-Json -Depth 7 -Compress))
exit $(if ($report.result -ceq 'passed') { 0 } else { 1 })
