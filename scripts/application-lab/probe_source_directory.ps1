# Hosted-only native qualification of fixed source cwd. Never invoke locally.
[CmdletBinding()]
param()
Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
$ProgressPreference = 'SilentlyContinue'

function Test-ProbeHosted($Actions, $Runner, $Environment, $Edition, $Windows, $Bits64) {
    return ($Actions -is [string] -and $Actions -ceq 'true' -and $Runner -is [string] -and $Runner -ceq 'Windows' -and
        $Environment -is [string] -and $Environment -ceq 'github-hosted' -and $Edition -is [string] -and $Edition -ceq 'Desktop' -and
        $Windows -is [bool] -and $Windows -and $Bits64 -is [bool] -and $Bits64)
}
function New-ProbeReport([System.Collections.IDictionary]$Checks, [string]$ErrorCode, [bool]$Cleanup, [bool]$Retained,
    [System.Collections.IDictionary]$RenameOutcomes) {
    $names = @('missing_rejected','file_rejected','junction_rejected','acl_rejected','rejected_leases_released',
        'lease_verified','source_rename_denied','case_rename_denied','sandbox_rename_denied','release_observed',
        'source_cwd','descendant_cwd','source_preserved','session_cleanup')
    $codes = @('hosted_only','setup_failed','compile_failed','rejection_failed','lease_failed','rename_failed',
        'launch_failed','cwd_failed','preservation_failed','cleanup_failed','deadline_exceeded','unexpected_failure')
    if ($Checks.Count -ne $names.Count -or ($ErrorCode -cne '' -and $ErrorCode -cnotin $codes)) { throw 'report_invalid' }
    $closed = [ordered]@{}
    foreach ($name in $names) {
        if (-not $Checks.Contains($name) -or $Checks[$name] -isnot [bool]) { throw 'report_invalid' }
        $closed[$name] = $Checks[$name]
    }
    $renames=[ordered]@{}
    if ($null -eq $RenameOutcomes -or $RenameOutcomes.Count -ne 3) { throw 'report_invalid' }
    foreach ($name in @('source','case','sandbox')) {
        if (-not $RenameOutcomes.Contains($name) -or $RenameOutcomes[$name] -isnot [string] -or
            $RenameOutcomes[$name] -cnotin @('not_attempted','denied','moved','unexpected_error')) { throw 'report_invalid' }
        $renames[$name]=$RenameOutcomes[$name]
    }
    if ($Cleanup -and $Retained) { throw 'report_invalid' }
    $passed = $ErrorCode -ceq '' -and $Cleanup -and -not $Retained -and @($closed.Values | Where-Object { -not $_ }).Count -eq 0 -and
        @($renames.Values | Where-Object { $_ -cne 'denied' }).Count -eq 0
    if (-not $passed -and $ErrorCode -ceq '') { throw 'report_invalid' }
    $errors=@(); if ($ErrorCode -cne '') { $errors=@($ErrorCode) }
    if (-not $Cleanup -and $ErrorCode -cne 'cleanup_failed') { $errors+=@('cleanup_failed') }
    return [ordered]@{ schema_version=2; scope='hosted_fixed_source_directory_probe';
        result=$(if ($passed) { 'passed' } elseif ($ErrorCode -ceq 'hosted_only') { 'unavailable' } else { 'failed' });
        checks=$closed; rename_outcomes=$renames; cleanup_complete=$Cleanup; tree_retained=$Retained;
        errors=$errors; production_application_executed=$false }
}
function Get-ProbeCreator([string]$Source) {
    $tokens=$null; $errors=$null
    $ast=[System.Management.Automation.Language.Parser]::ParseInput($Source,[ref]$tokens,[ref]$errors)
    if ($errors.Count -ne 0) { throw 'setup_failed' }
    $commands=@($ast.FindAll({ param($node)
        $node -is [System.Management.Automation.Language.CommandAst] -and $node.GetCommandName() -ieq 'Add-Type'
    },$true))
    if ($commands.Count -ne 1) { throw 'setup_failed' }
    $elements=$commands[0].CommandElements
    if ($elements.Count -ne 3 -or $commands[0].Redirections.Count -ne 0 -or
        $elements[1] -isnot [System.Management.Automation.Language.CommandParameterAst] -or
        $elements[1].ParameterName -cne 'TypeDefinition' -or $null -ne $elements[1].Argument -or
        $elements[2] -isnot [System.Management.Automation.Language.StringConstantExpressionAst] -or
        $elements[2].StringConstantType -ne [System.Management.Automation.Language.StringConstantType]::SingleQuotedHereString -or
        $elements[2].Value.Length -eq 0 -or $elements[2].Value.Length -gt 8192) { throw 'setup_failed' }
    return $elements[2].Value
}
function Assert-Probe([bool]$Value, [string]$Code) { if (-not $Value) { throw $Code } }
function Check-ProbeTime { if ($script:clock.ElapsedMilliseconds -gt 90000) { throw 'deadline_exceeded' } }
function New-ProbeDirectory([string]$Path) {
    Check-ProbeTime
    Assert-Probe (-not [IO.File]::Exists($Path) -and -not [IO.Directory]::Exists($Path)) 'setup_failed'
    $acl=[Security.AccessControl.DirectorySecurity]::new()
    $acl.SetOwner($script:userSid); $acl.SetAccessRuleProtection($true,$false)
    foreach ($sid in @($script:userSid,$script:systemSid)) {
        $acl.AddAccessRule([Security.AccessControl.FileSystemAccessRule]::new($sid,
            [Security.AccessControl.FileSystemRights]::FullControl,
            [Security.AccessControl.InheritanceFlags]'ContainerInherit,ObjectInherit',
            [Security.AccessControl.PropagationFlags]::None,[Security.AccessControl.AccessControlType]::Allow))
    }
    [AppLabPrivateDirectory]::Create($Path,$acl.GetSecurityDescriptorBinaryForm())
}
function Write-ProbeFile([string]$Path, [byte[]]$Bytes) {
    $acl=[Security.AccessControl.FileSecurity]::new()
    $acl.SetOwner($script:userSid); $acl.SetAccessRuleProtection($true,$false)
    foreach ($sid in @($script:userSid,$script:systemSid)) {
        $acl.AddAccessRule([Security.AccessControl.FileSystemAccessRule]::new($sid,
            [Security.AccessControl.FileSystemRights]::FullControl,[Security.AccessControl.AccessControlType]::Allow))
    }
    $stream=[IO.FileStream]::new($Path,[IO.FileMode]::CreateNew,[Security.AccessControl.FileSystemRights]::Write,
        [IO.FileShare]::None,4096,[IO.FileOptions]::None,$acl)
    try { $stream.Write($Bytes,0,$Bytes.Length); $stream.Flush($true) } finally { $stream.Dispose() }
}
function Read-ProbeFile([string]$Path, [int]$Limit) {
    Assert-Probe (([IO.File]::GetAttributes($Path) -band ([IO.FileAttributes]::ReparsePoint -bor [IO.FileAttributes]::Directory)) -eq 0) 'setup_failed'
    $stream=[IO.FileStream]::new($Path,[IO.FileMode]::Open,[IO.FileAccess]::Read,[IO.FileShare]::ReadWrite)
    try {
        Assert-Probe ($stream.Length -le $Limit) 'setup_failed'
        $buffer=[byte[]]::new($Limit+1); $count=0
        while ($count -lt $buffer.Length) {
            $n=$stream.Read($buffer,$count,$buffer.Length-$count)
            if ($n -eq 0) { break }; $count+=$n
        }
        Assert-Probe ($count -le $Limit) 'setup_failed'
        $result=[byte[]]::new($count); [Array]::Copy($buffer,$result,$count)
        return ,$result
    } finally { $stream.Dispose() }
}
function Hash-Probe([byte[]]$Bytes) {
    $hash=[Security.Cryptography.SHA256]::Create()
    try { return [BitConverter]::ToString($hash.ComputeHash($Bytes)).Replace('-','').ToLowerInvariant() }
    finally { $hash.Dispose() }
}
function Test-ProbeRejectionCodes([string[]]$Codes) {
    return ($Codes.Count -eq 1 -and $Codes[0] -ceq 'source_directory_invalid')
}
function Assert-RejectedSource([string]$Root) {
    $lease=$null; $rejected=$false
    try { $lease=[TriageApplicationLab.HostedSourceDirectory]::Acquire($Root) }
    catch {
        $codes=@([TriageApplicationLab.HostedSourceDirectory]::FailureCodes($_.Exception))
        $rejected=Test-ProbeRejectionCodes $codes
        if (-not $rejected) { $script:leaseClosed=$false }
    } finally {
        if ($null -ne $lease) {
            try { $lease.Dispose() } catch { $script:leaseClosed=$false; throw 'cleanup_failed' }
        }
    }
    Assert-Probe $rejected 'rejection_failed'
}
function Assert-RenameDenied([string]$Path, [string]$Name) {
    Assert-Probe ($Name -cin @('source','case','sandbox')) 'rename_failed'
    $script:renameOutcomes[$Name]='unexpected_error'
    $target=$Path+'-probe-moved'; $denied=$false
    Assert-Probe (-not [IO.Directory]::Exists($target) -and -not [IO.File]::Exists($target)) 'rename_failed'
    try {
        [IO.Directory]::Move($Path,$target)
        $script:renameOutcomes[$Name]='moved'
        $script:treeCertain=$false
    } catch {
        $cause=$_.Exception
        while ($null -ne $cause.InnerException) { $cause=$cause.InnerException }
        $denied=$cause -is [IO.IOException] -and (($cause.HResult -band 65535) -in @(5,32))
    }
    Assert-Probe ($denied -and [IO.Directory]::Exists($Path) -and -not [IO.Directory]::Exists($target)) 'rename_failed'
    $script:renameOutcomes[$Name]='denied'
}
function Assert-RenameReleased([string]$Path) {
    $target=$Path+'-probe-moved'
    Assert-Probe (-not [IO.Directory]::Exists($target) -and -not [IO.File]::Exists($target)) 'rename_failed'
    $script:treeCertain=$false
    [IO.Directory]::Move($Path,$target); [IO.Directory]::Move($target,$Path)
    $script:treeCertain=$true
}

$checks=[ordered]@{}
$script:renameOutcomes=[ordered]@{ source='not_attempted'; case='not_attempted'; sandbox='not_attempted' }
foreach ($name in @('missing_rejected','file_rejected','junction_rejected','acl_rejected','rejected_leases_released',
    'lease_verified','source_rename_denied','case_rename_denied','sandbox_rename_denied','release_observed',
    'source_cwd','descendant_cwd','source_preserved','session_cleanup')) { $checks[$name]=$false }
# This real guard precedes source reads, compilation, identity queries and dirs.
if (-not (Test-ProbeHosted $env:GITHUB_ACTIONS $env:RUNNER_OS $env:RUNNER_ENVIRONMENT $PSVersionTable.PSEdition ([Environment]::OSVersion.Platform -eq [PlatformID]::Win32NT) ([Environment]::Is64BitProcess))) {
    [Console]::Out.WriteLine((New-ProbeReport $checks 'hosted_only' $true $false $script:renameOutcomes | ConvertTo-Json -Depth 4 -Compress))
    exit 2
}
$script:clock=[Diagnostics.Stopwatch]::StartNew()
$failure=''; $phase='setup_failed'; $sandbox=$null; $case=$null; $source=$null; $lease=$null; $session=$null
$script:treeCertain=$true; $sandboxOwned=$false; $cleanup=$false; $sessionClosed=$true; $leaseClosed=$true
$compilerCompleted=$true; $oldTemp=$env:TEMP; $oldTmp=$env:TMP
$identities=[Collections.Generic.Dictionary[string,string]]::new([StringComparer]::OrdinalIgnoreCase)
try {
    $parent=[IO.Path]::GetFullPath($env:RUNNER_TEMP)
    Assert-Probe ($parent.Length -gt 3 -and $parent -cmatch '\A[A-Za-z]:[\\/]' -and -not $parent.StartsWith('\\')) 'setup_failed'
    for ($node=[IO.DirectoryInfo]::new($parent); $null -ne $node; $node=$node.Parent) {
        Assert-Probe ($node.Exists -and ($node.Attributes -band [IO.FileAttributes]::ReparsePoint) -eq 0) 'setup_failed'
    }
    $creatorText=[Text.UTF8Encoding]::new($false,$true).GetString((Read-ProbeFile (Join-Path $PSScriptRoot 'prepare_case.ps1') 65536))
    $creator=Get-ProbeCreator $creatorText
    $phase='compile_failed'
    Add-Type -TypeDefinition $creator -ErrorAction Stop -WarningAction SilentlyContinue 2>$null
    Add-Type -Path (Join-Path $PSScriptRoot 'HostedConPtySession.cs') -ErrorAction Stop -WarningAction SilentlyContinue 2>$null
    # Probe-only removal of validated, held objects. No pathname-delete fallback.
    Add-Type -ErrorAction Stop -WarningAction SilentlyContinue -TypeDefinition @'
using System;
using System.Collections.Generic;
using System.IO;
using System.Runtime.InteropServices;
using System.Text;
public static class SourceProbeOwnedTree {
  [StructLayout(LayoutKind.Sequential)] struct FT { public uint low,high; }
  [StructLayout(LayoutKind.Sequential)] struct Info {
    public uint attributes; public FT created,accessed,written;
    public uint volume,sizeHigh,sizeLow,links,indexHigh,indexLow;
  }
  // FILE_DISPOSITION_INFO uses BOOLEAN, not a default four-byte managed bool.
  // https://learn.microsoft.com/windows/win32/api/winbase/ns-winbase-file_disposition_info
  [StructLayout(LayoutKind.Sequential,Pack=1)] struct Disposition { public byte deleteFile; }
  [DllImport("kernel32.dll",CharSet=CharSet.Unicode,SetLastError=true)]
  static extern IntPtr CreateFileW(string p,uint access,uint share,IntPtr sa,uint mode,uint flags,IntPtr template);
  [DllImport("kernel32.dll",SetLastError=true)] static extern bool GetFileInformationByHandle(IntPtr h,out Info i);
  [DllImport("kernel32.dll",SetLastError=true)] static extern uint GetFileType(IntPtr h);
  [DllImport("kernel32.dll",CharSet=CharSet.Unicode,SetLastError=true)]
  static extern uint GetFinalPathNameByHandleW(IntPtr h,StringBuilder p,uint n,uint flags);
  [DllImport("kernel32.dll",CharSet=CharSet.Unicode,SetLastError=true)]
  static extern uint GetFileAttributesW(string path);
  [DllImport("kernel32.dll",SetLastError=true)]
  static extern bool SetFileInformationByHandle(IntPtr h,int kind,ref Disposition info,uint size);
  [DllImport("kernel32.dll",SetLastError=true)] static extern bool CloseHandle(IntPtr h);
  sealed class Pin { public string path,id; public IntPtr handle; public bool directory,closeAttempted; public int depth; }
  static void Need(bool value) { if(!value) throw new InvalidOperationException("cleanup_failed"); }
  static bool IsAbsent(uint attributes,int error) { return attributes==UInt32.MaxValue && error==2; }
  static string Canonical(string path) {
    Need(path!=null && path.Length>=3 && path.Length<4096);
    string full=Path.GetFullPath(path);
    Need(full.Length>=3 && full.Length<4096 && full[1]==':' && !full.StartsWith(@"\\") && full.IndexOf(':',2)<0);
    return full;
  }
  static Pin Open(string path,bool deleting,int depth,bool hold=false) {
    string full=Canonical(path);
    // MS-FSA 2.1.5.1.2.2 excludes metadata-only handles from sharing checks.
    // FILE_LIST_DIRECTORY participates; the pin still withholds FILE_SHARE_DELETE.
    // https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-fsa/8c0e3f4f-0729-49f4-a14d-7f7add593819
    IntPtr handle=CreateFileW(full,deleting?0x10080u:hold?0x81u:0x80u,(deleting||hold)?3u:7u,IntPtr.Zero,3,0x02200000,IntPtr.Zero);
    Need(handle!=IntPtr.Zero && handle!=new IntPtr(-1));
    try {
      Info info=new Info(); Need(GetFileType(handle)==1 && GetFileInformationByHandle(handle,out info));
      Need((info.attributes&0x400)==0 && ((info.attributes&0x10)!=0 || info.links==1));
      var final=new StringBuilder(4096); uint n=GetFinalPathNameByHandleW(handle,final,4096,0);
      Need(n>0 && n<4096); string actual=final.ToString();
      if(actual.StartsWith(@"\\?\")) actual=actual.Substring(4);
      Need(String.Equals(actual.TrimEnd('\\'),full.TrimEnd('\\'),StringComparison.OrdinalIgnoreCase));
      return new Pin {path=full,id=info.volume.ToString("x8")+info.indexHigh.ToString("x8")+info.indexLow.ToString("x8"),
        handle=handle,directory=(info.attributes&0x10)!=0,depth=depth};
    } catch { if(!CloseHandle(handle)) throw new InvalidOperationException("cleanup_failed"); throw; }
  }
  static void Close(Pin p) {
    if(p.handle!=IntPtr.Zero) { Need(!p.closeAttempted); p.closeAttempted=true; Need(CloseHandle(p.handle)); p.handle=IntPtr.Zero; }
  }
  public static string Capture(string path) {
    Pin p=Open(path,false,0); try { Need(p.directory); return p.id; } finally { Close(p); }
  }
  public static void Remove(string root,IDictionary<string,string> expected) {
    root=Canonical(root);
    Need(expected!=null && expected.Count>=1 && expected.Count<=3 && expected.ContainsKey(root));
    var ancestors=new List<Pin>(); var nodes=new List<Pin>(); var paths=new List<string>();
    try {
      for(var p=Directory.GetParent(root); p!=null; p=p.Parent) {
        Need(paths.Count<64); paths.Add(Canonical(p.FullName));
      }
      paths.Reverse();
      foreach(string path in paths) {
        // Shared ancestors are only pinned; never deleted, renamed or ACL-mutated.
        Pin p=Open(path,false,0,true); ancestors.Add(p); Need(p.directory);
      }
      Pin first=Open(root,true,0); nodes.Add(first); Need(first.directory);
      var found=new HashSet<string>(StringComparer.OrdinalIgnoreCase);
      for(int index=0; index<nodes.Count; index++) {
        Pin p=nodes[index]; Need(p.depth<=8);
        string id;
        if(expected.TryGetValue(p.path,out id)) { Need(p.id==id); found.Add(p.path); }
        if(p.directory) {
          foreach(string child in Directory.EnumerateFileSystemEntries(p.path)) {
            Need(nodes.Count<128 && child.StartsWith(root+Path.DirectorySeparatorChar,StringComparison.OrdinalIgnoreCase));
            nodes.Add(Open(child,true,p.depth+1));
          }
        }
      }
      Need(found.Count==expected.Count && Marshal.SizeOf(typeof(Disposition))==1);
      // Entire inventory is pinned and validated before the first disposition.
      for(int index=nodes.Count-1; index>=0; index--) {
        var disposition=new Disposition {deleteFile=1};
        Need(SetFileInformationByHandle(nodes[index].handle,4,ref disposition,1));
        Close(nodes[index]);
      }
      // The existing parent is still pinned: only FILE_NOT_FOUND proves absence.
      uint attributes=GetFileAttributesW(root); int error=Marshal.GetLastWin32Error();
      Need(IsAbsent(attributes,error));
    } finally {
      bool closed=true;
      for(int index=nodes.Count-1; index>=0; index--) { try { Close(nodes[index]); } catch { closed=false; } }
      for(int index=ancestors.Count-1; index>=0; index--) { try { Close(ancestors[index]); } catch { closed=false; } }
      Need(closed);
    }
  }
}
'@ 2>$null
    $script:userSid=[Security.Principal.WindowsIdentity]::GetCurrent().User
    $script:systemSid=[Security.Principal.SecurityIdentifier]::new('S-1-5-18')
    $phase='setup_failed'
    $sandbox=[IO.Path]::Combine($parent,'app-filesystem-'+[Guid]::NewGuid().ToString('N'))
    New-ProbeDirectory $sandbox; $sandboxOwned=$true
    $identities.Add($sandbox,[SourceProbeOwnedTree]::Capture($sandbox))
    $case=[IO.Path]::Combine($sandbox,'filesystem-probe'); New-ProbeDirectory $case
    $identities.Add($case,[SourceProbeOwnedTree]::Capture($case))
    $source=[IO.Path]::Combine($case,'source')
    $phase='rejection_failed'
    Assert-RejectedSource $case; $checks.missing_rejected=$true
    Write-ProbeFile $source ([byte[]]@(1,2,3)); Assert-RejectedSource $case; $checks.file_rejected=$true
    [IO.File]::Delete($source)
    $target=[IO.Path]::Combine($sandbox,'junction-target'); New-ProbeDirectory $target
    New-Item -ItemType Junction -Path $source -Target $target -ErrorAction Stop | Out-Null
    Assert-Probe (([IO.File]::GetAttributes($source) -band [IO.FileAttributes]::ReparsePoint) -ne 0) 'rejection_failed'
    Assert-RejectedSource $case; $checks.junction_rejected=$true
    [IO.Directory]::Delete($source,$false) # Delete only this owned link, never its target.
    Assert-Probe ([IO.Directory]::Exists($target)) 'rejection_failed'
    [IO.Directory]::Delete($target,$false)
    New-ProbeDirectory $source
    $bad=[IO.Directory]::GetAccessControl($source)
    foreach ($rule in $bad.GetAccessRules($true,$false,[Security.Principal.SecurityIdentifier])) {
        if ($rule.IdentityReference.Value -ceq 'S-1-5-18') { $bad.RemoveAccessRuleSpecific($rule) }
    }
    [IO.Directory]::SetAccessControl($source,$bad)
    Assert-RejectedSource $case; $checks.acl_rejected=$true
    [IO.Directory]::Delete($source,$false) # Discard the deliberate invalid node; do not repair its ACL.
    Assert-RenameReleased $case; Assert-RenameReleased $sandbox; $checks.rejected_leases_released=$true
    New-ProbeDirectory $source
    $identities.Add($source,[SourceProbeOwnedTree]::Capture($source))
    $sourceFile=[IO.Path]::Combine($source,'probe-source.txt')
    $payload=[Text.Encoding]::ASCII.GetBytes("synthetic source cwd`n")
    Write-ProbeFile $sourceFile $payload; $payloadHash=Hash-Probe $payload
    $phase='lease_failed'; $leaseClosed=$false
    $lease=[TriageApplicationLab.HostedSourceDirectory]::Acquire($case)
    Assert-Probe ($lease.Path -ceq $source) 'lease_failed'; $lease.Verify(); $checks.lease_verified=$true
    $phase='rename_failed'
    Assert-RenameDenied $source 'source'; $checks.source_rename_denied=$true
    Assert-RenameDenied $case 'case'; $checks.case_rename_denied=$true
    Assert-RenameDenied $sandbox 'sandbox'; $checks.sandbox_rename_denied=$true
    $lease.Verify(); $lease.Dispose(); $lease=$null; $leaseClosed=$true
    foreach ($path in @($source,$case,$sandbox)) { Assert-RenameReleased $path }
    $checks.release_observed=$true
    foreach ($name in @('temp','home','profile','appdata','localappdata')) { New-ProbeDirectory ([IO.Path]::Combine($case,$name)) }
    $env:TEMP=[IO.Path]::Combine($case,'temp'); $env:TMP=$env:TEMP
    $phase='compile_failed'; $compilerCompleted=$false
    $compiled=[IO.Path]::Combine($case,'compiled.private.exe')
    Add-Type -OutputAssembly $compiled -OutputType ConsoleApplication -ErrorAction Stop -WarningAction SilentlyContinue -TypeDefinition @'
using System;
using System.Diagnostics;
using System.IO;
using System.Reflection;
public static class SourceCwdProbe {
  public static int Main(string[] args) {
    try {
      if(args.Length!=2 || (args[0]!="parent" && args[0]!="child")) return 10;
      if(!String.Equals(Path.GetFullPath(Environment.CurrentDirectory),args[1],StringComparison.OrdinalIgnoreCase)) return 11;
      if(File.ReadAllText("probe-source.txt")!="synthetic source cwd\n") return 12;
      if(args[0]=="child") return 0;
      var start=new ProcessStartInfo(Assembly.GetExecutingAssembly().Location,"child \""+args[1]+"\"");
      start.UseShellExecute=false; start.CreateNoWindow=true;
      using(var child=Process.Start(start)) {
        if(child==null) return 13;
        if(!child.WaitForExit(3000)) { try { child.Kill(); child.WaitForExit(1000); } catch {} return 14; }
        if(child.ExitCode!=0) return 15;
      }
      Console.WriteLine("SOURCE_CWD_OK"); Console.WriteLine("DESCENDANT_CWD_OK"); Console.Out.Flush();
      return 0;
    } catch { return 16; }
  }
}
'@ 2>$null
    $compilerCompleted=$true
    $app=[IO.Path]::Combine($case,'application.exe')
    $appBytes=Read-ProbeFile $compiled 1048576
    Write-ProbeFile $app $appBytes; [IO.File]::Delete($compiled)
    $environment=[Collections.Generic.Dictionary[string,string]]::new([StringComparer]::OrdinalIgnoreCase)
    $environment.Add('SYSTEMROOT',[Environment]::GetFolderPath([Environment+SpecialFolder]::Windows))
    $environment.Add('PATH',[Environment]::SystemDirectory)
    foreach ($entry in @(@('TEMP','temp'),@('TMP','temp'),@('HOME','home'),@('USERPROFILE','profile'),@('APPDATA','appdata'),@('LOCALAPPDATA','localappdata'))) {
        $environment.Add($entry[0],[IO.Path]::Combine($case,$entry[1]))
    }
    $transcript=[IO.Path]::Combine($case,'transcript.private')
    $phase='launch_failed'; $sessionClosed=$false
    try {
        $session=[TriageApplicationLab.HostedConPtySession]::StartSource($app,(Hash-Probe $appBytes),
            [string[]]@('parent',$source),$case,$environment,$transcript,65536,30000,1)
        Check-ProbeTime
        $observed=$session.Poll()
        Assert-Probe ($observed.ok -eq $true -and @($observed.errors).Count -eq 0) 'launch_failed'
        # Source pins survive natural exit and remain owned until Finish.
        # Non-TUI transcript bytes need not flush until that finalization.
        $phase='rename_failed'
        Assert-RenameDenied $source 'source'
        Assert-RenameDenied $case 'case'
        Assert-RenameDenied $sandbox 'sandbox'
    } finally {
        if ($null -ne $session) {
            $final=$session.Finish(10000)
            $sessionClosed=$final.state -ceq 'finished' -and $final.ok -eq $true -and @($final.errors).Count -eq 0 -and
                $final.app_exit_code -eq 0 -and $final.app_exited -eq $true -and $final.observed_children_exited -eq $true -and
                $final.job_zero_confirmed -eq $true -and $final.reader_joined -eq $true -and $final.conpty_closed -eq $true -and
                $final.forced_termination -eq $false -and $final.runtime_image_observed -eq $false -and $null -eq $final.runtime_sha256
            $checks.session_cleanup=$sessionClosed
        }
    }
    $phase='cleanup_failed'; Assert-Probe $sessionClosed 'cleanup_failed'
    $phase='cwd_failed'
    $text=[Text.Encoding]::ASCII.GetString((Read-ProbeFile $transcript 65536))
    # ConPTY may prefix tokens with controls; this exact inert binary is their only writer.
    Assert-Probe ([regex]::Matches($text,'SOURCE_CWD_OK').Count -eq 1 -and
        [regex]::Matches($text,'DESCENDANT_CWD_OK').Count -eq 1) 'cwd_failed'
    $checks.source_cwd=$true; $checks.descendant_cwd=$true
    foreach ($path in @($source,$case,$sandbox)) { Assert-RenameReleased $path }
    $phase='preservation_failed'
    $sourceCount=0
    foreach ($entry in [IO.Directory]::EnumerateFileSystemEntries($source)) {
        $sourceCount++; Assert-Probe ($sourceCount -eq 1 -and $entry -ceq $sourceFile) 'preservation_failed'
    }
    Assert-Probe ($sourceCount -eq 1 -and (Hash-Probe (Read-ProbeFile $sourceFile 128)) -ceq $payloadHash) 'preservation_failed'
    $checks.source_preserved=$true
} catch {
    $failure=$phase
    $cause=$_.Exception
    while ($null -ne $cause.InnerException) { $cause=$cause.InnerException }
    if ($cause.Message -ceq 'deadline_exceeded') { $failure='deadline_exceeded' }
} finally {
    $env:TEMP=$oldTemp; $env:TMP=$oldTmp
    if ($null -ne $lease) {
        try { $lease.Dispose(); $leaseClosed=$true } catch {
            $leaseClosed=$false; if ($failure -ceq '') { $failure='cleanup_failed' }
        }
    }
    # No recursive deletion after uncertain construction, compilation, rename or session cleanup.
    if ($null -eq $sandbox) { $cleanup=$true }
    elseif ($sandboxOwned -and $script:treeCertain -and $leaseClosed -and $sessionClosed -and $compilerCompleted) {
        try {
            [SourceProbeOwnedTree]::Remove($sandbox,$identities)
            $cleanup=$true
        } catch { $cleanup=$false }
    }
    if (-not $cleanup -and $failure -ceq '') { $failure='cleanup_failed' }
}
# Unproved absence is retained uncertainty, never an Exists(false) success.
$retained=$null -ne $sandbox -and -not $cleanup
$report=New-ProbeReport $checks $failure $cleanup $retained $script:renameOutcomes
[Console]::Out.WriteLine(($report | ConvertTo-Json -Depth 4 -Compress))
exit $(if ($report.result -ceq 'passed') { 0 } else { 1 })
