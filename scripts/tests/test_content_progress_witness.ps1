#requires -Version 5.1
[CmdletBinding()]
param()
Set-StrictMode -Version Latest
$ErrorActionPreference='Stop'
if($env:OS -cne 'Windows_NT' -or $PSVersionTable.PSEdition -cne 'Desktop' -or -not [Environment]::Is64BitProcess){throw 'windows_desktop_x64_required'}
$source=[IO.Path]::GetFullPath((Join-Path $PSScriptRoot '../application-lab/ContentProgressWitness.cs'))
$tests=[IO.Path]::GetFullPath((Join-Path $PSScriptRoot 'ContentProgressWitnessTests.cs'))
$base=[IO.Path]::GetFullPath($env:RUNNER_TEMP)
if(-not [IO.Directory]::Exists($base)){throw 'runner_temp_required'}
$root=Join-Path $base ('content-witness-'+[guid]::NewGuid().ToString('N'))
if([IO.Directory]::Exists($root) -or [IO.File]::Exists($root)){throw 'output_exists'}
[void](New-Item -ItemType Directory -Path $root -ErrorAction Stop)
$cases=Join-Path $root 'cases';[void][IO.Directory]::CreateDirectory($cases)
$report=Join-Path $root 'result.json'
$expected=@(
 'short_read_is_pending',
 'wrong_content_is_not_progress',
 'complete_length_is_missed',
 'read_cap_is_missed',
 'invalid_read_bounds_rejected',
 'independent_hash_contract_rejected',
 'barrier_growth_and_real_release',
 'already_present_second_extent_is_missed',
 'preallocation_is_not_progress',
 'length_regression_poisoned',
 'path_and_original_clock_rejected',
 'real_multilink_rejected_and_released',
 'real_reparse_parent_rejected_and_released',
 'clock_failure_cannot_skip_release',
 'final_completed_length_removes_proof',
 'final_read_cap_removes_proof',
 'injected_post_close_budget_denial',
 'injected_close_failure_sticky_and_remaining_pins',
 'partial_construction_close_failure_attempts_all_pins'
)
$pins=@();$locks=@();$stage='sources';$ok=$false;$started=@();$completed=@()
function Hash-Stream($Stream){$sha=[Security.Cryptography.SHA256]::Create();try{$Stream.Position=0;([BitConverter]::ToString($sha.ComputeHash($Stream))).Replace('-','').ToLowerInvariant()}finally{$sha.Dispose();$Stream.Position=0}}
try{
 foreach($p in @($source,$tests)){
  $info=Get-Item -LiteralPath $p
  if($info.PSIsContainer -or ($info.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0 -or $info.Length -gt 65536){throw 'source_rejected'}
  $stream=[IO.File]::Open($p,[IO.FileMode]::Open,[IO.FileAccess]::Read,[IO.FileShare]::Read);$locks+=,$stream
  $pins+=,[pscustomobject]@{name=[IO.Path]::GetFileName($p);bytes=$stream.Length;sha256=(Hash-Stream $stream)}
 }
 $stage='compile_content_witness_only'
 Add-Type -Path @($source,$tests) -ErrorAction Stop
 $stage='synthetic_controls'
 $returned=@([ContentProgressWitnessTests]::Run($cases))
 $started=@([ContentProgressWitnessTests]::StartedCases);$completed=@([ContentProgressWitnessTests]::CompletedCases)
 if(($returned -join '|') -cne ($expected -join '|') -or ($started -join '|') -cne ($expected -join '|') -or ($completed -join '|') -cne ($expected -join '|')){throw 'case_inventory_rejected'}
 if([IO.Directory]::GetFileSystemEntries($cases).Length -ne 0){throw 'owned_cases_not_empty'}
 $ok=$true;$stage='complete'
}catch{
 if($stage -ceq 'synthetic_controls'){$started=@([ContentProgressWitnessTests]::StartedCases);$completed=@([ContentProgressWitnessTests]::CompletedCases)}
}finally{
 $unchanged=$true
 for($i=0;$i -lt $locks.Count;$i++){try{if($locks[$i].Length -ne $pins[$i].bytes -or (Hash-Stream $locks[$i]) -cne $pins[$i].sha256){$unchanged=$false}}catch{$unchanged=$false}}
 foreach($stream in $locks){try{$stream.Dispose()}catch{$unchanged=$false}}
 $ok=$ok -and $unchanged
 $value=[ordered]@{schema_version=1;result=$(if($ok){'passed'}else{'failed'});stage=$stage;expected=$expected;started=$started;completed=$completed;sources=$pins;sources_unchanged=$unchanged;powershell_version=$PSVersionTable.PSVersion.ToString();powershell_edition=$PSVersionTable.PSEdition;process_bits=([IntPtr]::Size*8);owned_cases_empty=([IO.Directory]::GetFileSystemEntries($cases).Length -eq 0);app_executed=$false;credentials_used=$false;provider_accepted=$false}
 $bytes=[Text.UTF8Encoding]::new($false).GetBytes(($value|ConvertTo-Json -Depth 5 -Compress)+[Environment]::NewLine)
 if($bytes.Length -gt 8192){throw 'report_limit'}
 $output=[IO.File]::Open($report,[IO.FileMode]::CreateNew,[IO.FileAccess]::Write,[IO.FileShare]::None)
 try{$output.Write($bytes,0,$bytes.Length);$output.Flush($true)}finally{$output.Dispose()}
 # Retain bounded sanitized IDs and source hashes in the hosted log.
 [Text.Encoding]::UTF8.GetString($bytes).TrimEnd()
}
if(-not $ok){exit 1}
exit 0
