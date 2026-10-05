# Hosted-only atomic private directory creation and bounded ACL verification.
[CmdletBinding()]
param([Parameter(Mandatory=$true)][ValidateSet('Create','Verify')][string]$Action,
      [Parameter(Mandatory=$true)][string]$Parent,
      [Parameter(Mandatory=$true)][string]$Name)
Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
function Write-SetupStage([ValidateSet('input','parent','identity','acl','compile','create','verify','complete')][string]$Stage) {
    [Console]::Out.WriteLine('{"schema_version":1,"stage":"' + $Stage + '"}')
    [Console]::Out.Flush()
}
try {
    Write-SetupStage 'input'
    if ($env:GITHUB_ACTIONS -cne 'true' -or $env:RUNNER_OS -cne 'Windows' -or $env:RUNNER_ENVIRONMENT -cne 'github-hosted' -or $PSVersionTable.PSEdition -ne 'Desktop') { throw 'hosted_only' }
    if ($Name -cnotmatch '^(app-http-[a-f0-9]{32}|listing|acquisition|mismatch|missing|denial|cancellation)$') { throw 'name_invalid' }
    Write-SetupStage 'parent'
    $parentPath = [IO.Path]::GetFullPath($Parent)
    if ($parentPath.StartsWith('\\') -or -not [IO.Directory]::Exists($parentPath)) { throw 'parent_invalid' }
    for ($item = [IO.DirectoryInfo]::new($parentPath); $null -ne $item; $item = $item.Parent) {
        if (($item.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0) { throw 'reparse' }
    }
    $path = [IO.Path]::Combine($parentPath, $Name)
    Write-SetupStage 'identity'
    $sid = [Security.Principal.WindowsIdentity]::GetCurrent().User
    $system = [Security.Principal.SecurityIdentifier]::new('S-1-5-18')
    if ($Action -ceq 'Create') {
        Write-SetupStage 'acl'
        if ([IO.Directory]::Exists($path) -or [IO.File]::Exists($path)) { throw 'exists' }
        $acl = [Security.AccessControl.DirectorySecurity]::new()
        $acl.SetOwner($sid)
        $acl.SetAccessRuleProtection($true, $false)
        $inherit = [Security.AccessControl.InheritanceFlags]'ContainerInherit,ObjectInherit'
        foreach ($principal in @($sid, $system)) {
            $acl.AddAccessRule([Security.AccessControl.FileSystemAccessRule]::new($principal,
                [Security.AccessControl.FileSystemRights]::FullControl, $inherit,
                [Security.AccessControl.PropagationFlags]::None, [Security.AccessControl.AccessControlType]::Allow))
        }
        Write-SetupStage 'compile'
        Add-Type -TypeDefinition @'
using System;
using System.Runtime.InteropServices;
public static class AppLabPrivateDirectory {
  [StructLayout(LayoutKind.Sequential)] struct SA { public int length; public IntPtr descriptor; public int inherit; }
  [DllImport("kernel32.dll", CharSet=CharSet.Unicode, SetLastError=true)]
  static extern bool CreateDirectoryW(string path, ref SA security);
  public static void Create(string path, byte[] descriptor) {
    var pin=GCHandle.Alloc(descriptor,GCHandleType.Pinned);
    try { var security=new SA {length=Marshal.SizeOf(typeof(SA)),descriptor=pin.AddrOfPinnedObject(),inherit=0};
      if(!CreateDirectoryW(path,ref security)) throw new InvalidOperationException("create_failed");
    } finally { pin.Free(); }
  }
}
'@
        Write-SetupStage 'create'
        [AppLabPrivateDirectory]::Create($path, $acl.GetSecurityDescriptorBinaryForm())
    }
    Write-SetupStage 'verify'
    $pending = [Collections.Generic.Queue[string]]::new()
    $pending.Enqueue($path)
    $count = 0
    while ($pending.Count -gt 0) {
        $current = $pending.Dequeue()
        $count++
        if ($count -gt 1024) { throw 'entry_limit' }
        $attributes = [IO.File]::GetAttributes($current)
        if (($attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0) { throw 'reparse' }
        $directory = ($attributes -band [IO.FileAttributes]::Directory) -ne 0
        if ($directory) { $observed = [IO.Directory]::GetAccessControl($current) }
        else { $observed = [IO.File]::GetAccessControl($current) }
        if ($observed.GetOwner([Security.Principal.SecurityIdentifier]).Value -cne $sid.Value) { throw 'owner_invalid' }
        if ($current -ceq $path -and -not $observed.AreAccessRulesProtected) { throw 'root_unprotected' }
        $userSeen = $false; $systemSeen = $false
        foreach ($rule in $observed.GetAccessRules($true,$true,[Security.Principal.SecurityIdentifier])) {
            $who = $rule.IdentityReference.Value
            if ($rule.AccessControlType -ne 'Allow' -or ($who -cne $sid.Value -and $who -cne 'S-1-5-18') -or
                ($rule.FileSystemRights -band [Security.AccessControl.FileSystemRights]::FullControl) -ne [Security.AccessControl.FileSystemRights]::FullControl -or
                ($rule.PropagationFlags -band [Security.AccessControl.PropagationFlags]::InheritOnly) -ne 0) { throw 'acl_invalid' }
            if ($who -ceq $sid.Value) { $userSeen=$true } else { $systemSeen=$true }
        }
        if (-not $userSeen -or -not $systemSeen) { throw 'acl_incomplete' }
        if ($directory) { foreach ($child in [IO.Directory]::EnumerateFileSystemEntries($current)) { $pending.Enqueue($child) } }
    }
    Write-SetupStage 'complete'
    [Console]::Out.WriteLine('{"schema_version":1,"ok":true}')
    [Console]::Out.Flush()
    exit 0
} catch {
    [Console]::Out.WriteLine('{"schema_version":1,"ok":false}')
    [Console]::Out.Flush()
    exit 1
}
