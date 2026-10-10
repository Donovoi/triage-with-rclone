# Hosted-only atomic private directory creation and bounded ACL verification.
[CmdletBinding()]
param([Parameter(Mandatory=$true)][ValidateSet('Create','Verify')][string]$Action,
      [Parameter(Mandatory=$true)][string]$Parent,
      [Parameter(Mandatory=$true)][string]$Name)
Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
function Test-SetupName([string]$Value) {
    if ($Value -cmatch '\Aapp-(http|webdav|filesystem)-[a-f0-9]{32}\z') { return $true }
    if ($Value -cmatch '\Afs-(local|archive)-(listing|acquisition-(readme|empty|large|binary|unicode|spaced)|mismatch|missing|directory-as-file|cancellation)\z') { return $true }
    foreach ($literal in @(
        'fs-archive-corrupt-member','fs-archive-truncated-archive',
        'listing','acquisition','mismatch','missing','denial','cancellation',
        'webdav-credential-setup','webdav-credentials','webdav-listing','webdav-acquisition','webdav-mismatch','webdav-missing',
        'webdav-wrong-credentials','webdav-accepted-a','webdav-revoked-a','webdav-replacement-b',
        'webdav-permission-denied','webdav-truncated-transfer','webdav-cancellation')) {
        if ([string]::Equals($Value, $literal, [StringComparison]::Ordinal)) { return $true }
    }
    return $false
}
function Write-SetupStage([ValidateSet('input','parent','identity','acl','compile','create','verify','complete')][string]$Stage) {
    [Console]::Out.WriteLine('{"schema_version":1,"stage":"' + $Stage + '"}')
    [Console]::Out.Flush()
}
function Get-SetupNodeCategory([string]$Root, [string]$Current) {
    if (-not $Root -or -not $Current) { return 'unknown' }
    if ($Current -ceq $Root) { return 'root' }
    $helper = [IO.Path]::Combine($Root, 'helper-env')
    if ($Current -ceq $helper) { return 'helper_root' }
    foreach ($name in @('temp','home','profile','appdata','localappdata')) {
        if ($Current -ceq [IO.Path]::Combine($Root, $name)) { return 'application_root' }
        $private = [IO.Path]::Combine($helper, $name)
        if ([string]::Equals($Current, $private, [StringComparison]::OrdinalIgnoreCase)) { return 'helper_private_root' }
        $prefix = $private + [IO.Path]::DirectorySeparatorChar
        if ($Current.StartsWith($prefix, [StringComparison]::OrdinalIgnoreCase)) {
            $relative = $Current.Substring($prefix.Length)
            if ($relative.Length -eq 0) { return 'helper_descendant' }
            if ($name -ceq 'temp') {
                if ($relative.IndexOf([IO.Path]::DirectorySeparatorChar) -lt 0) { return 'helper_temp_direct' }
                return 'helper_temp_deeper'
            }
            # Only fixed labels leave the helper; never the descendant's name.
            return 'helper_' + $name + '_descendant'
        }
    }
    if ($Current.StartsWith($helper + [IO.Path]::DirectorySeparatorChar, [StringComparison]::OrdinalIgnoreCase)) { return 'helper_descendant' }
    foreach ($name in @('bridge-stdout.private','bridge-stderr.private')) {
        if ($Current -ceq [IO.Path]::Combine($Root, $name)) { return 'bridge_log' }
    }
    # Fixed synthetic listing nodes only; no descendant names leave this function.
    $output = [IO.Path]::Combine($Root, 'output')
    $case = [IO.Path]::Combine($output, 'synthetic-case')
    $config = [IO.Path]::Combine($case, 'config')
    $nodes = @(
        @([IO.Path]::Combine($Root, 'application.exe'), 'application_binary'),
        @([IO.Path]::Combine($Root, 'source.conf'), 'source_config'),
        @([IO.Path]::Combine($Root, 'queue.csv'), 'acquisition_queue'),
        @([IO.Path]::Combine($Root, 'transcript.private'), 'session_transcript'),
        @($output, 'output_root'), @($case, 'case_root'),
        @([IO.Path]::Combine($case, 'logs'), 'case_logs'),
        @([IO.Path]::Combine($case, 'downloads'), 'case_downloads'),
        @([IO.Path]::Combine($case, 'listings'), 'case_listings'),
        @($config, 'case_config'),
        @([IO.Path]::Combine([IO.Path]::Combine($case, 'listings'), 'inventory.csv'), 'listing_inventory')
    )
    foreach ($node in $nodes) {
        if ([string]::Equals($Current, $node[0], [StringComparison]::OrdinalIgnoreCase)) { return $node[1] }
    }
    $configPrefix = $config + [IO.Path]::DirectorySeparatorChar
    if ($Current.StartsWith($configPrefix, [StringComparison]::OrdinalIgnoreCase)) {
        $leaf = $Current.Substring($configPrefix.Length)
        # Match the producer's direct-child grammar, not arbitrary config descendants.
        if ([regex]::IsMatch($leaf, '\Aworking-[A-Za-z0-9_-]+\.conf\z')) { return 'working_config' }
        if ([regex]::IsMatch($leaf, '\Aworking-[A-Za-z0-9_-]+\.provenance\.json\z')) { return 'config_provenance' }
    }
    return 'other'
}
$verificationReason = $null
$current = $null
$ownerIsUser = $null; $ownerIsTokenOwner = $null; $tokenOwnerIsUser = $null
try {
    Write-SetupStage 'input'
    if ($env:GITHUB_ACTIONS -cne 'true' -or $env:RUNNER_OS -cne 'Windows' -or $env:RUNNER_ENVIRONMENT -cne 'github-hosted' -or $PSVersionTable.PSEdition -ne 'Desktop') { throw 'hosted_only' }
    if (-not (Test-SetupName $Name)) { throw 'name_invalid' }
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
    $verificationReason = 'verification_failed'
    $pending = [Collections.Generic.Queue[string]]::new()
    $pending.Enqueue($path)
    $count = 0
    while ($pending.Count -gt 0) {
        $current = $pending.Dequeue()
        $ownerIsUser = $null; $ownerIsTokenOwner = $null; $tokenOwnerIsUser = $null
        $count++
        if ($count -gt 1024) { $verificationReason = 'entry_limit'; throw 'entry_limit' }
        $verificationReason = 'metadata_read_failed'
        $attributes = [IO.File]::GetAttributes($current)
        if (($attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0) { $verificationReason = 'reparse'; throw 'reparse' }
        $directory = ($attributes -band [IO.FileAttributes]::Directory) -ne 0
        if ($directory) { $observed = [IO.Directory]::GetAccessControl($current) }
        else { $observed = [IO.File]::GetAccessControl($current) }
        $owner = $observed.GetOwner([Security.Principal.SecurityIdentifier])
        if ($owner.Value -cne $sid.Value) {
            $verificationReason = 'owner_invalid'
            $ownerIsUser = $false
            # Failure-only comparison; no SID or account name enters the protocol.
            try {
                $tokenOwner = [Security.Principal.WindowsIdentity]::GetCurrent().Owner
                if ($null -ne $tokenOwner) {
                    $ownerIsTokenOwner = $owner.Value -ceq $tokenOwner.Value
                    $tokenOwnerIsUser = $tokenOwner.Value -ceq $sid.Value
                }
            } catch { $ownerIsTokenOwner = $null; $tokenOwnerIsUser = $null }
            throw 'owner_invalid'
        }
        if ($current -ceq $path -and -not $observed.AreAccessRulesProtected) { $verificationReason = 'root_unprotected'; throw 'root_unprotected' }
        $userSeen = $false; $systemSeen = $false
        foreach ($rule in $observed.GetAccessRules($true,$true,[Security.Principal.SecurityIdentifier])) {
            $who = $rule.IdentityReference.Value
            if ($rule.AccessControlType -ne 'Allow' -or ($who -cne $sid.Value -and $who -cne 'S-1-5-18') -or
                ($rule.FileSystemRights -band [Security.AccessControl.FileSystemRights]::FullControl) -ne [Security.AccessControl.FileSystemRights]::FullControl -or
                ($rule.PropagationFlags -band [Security.AccessControl.PropagationFlags]::InheritOnly) -ne 0) { $verificationReason = 'acl_invalid'; throw 'acl_invalid' }
            if ($who -ceq $sid.Value) { $userSeen=$true } else { $systemSeen=$true }
        }
        if (-not $userSeen -or -not $systemSeen) { $verificationReason = 'acl_incomplete'; throw 'acl_incomplete' }
        $verificationReason = 'enumeration_failed'
        if ($directory) { foreach ($child in [IO.Directory]::EnumerateFileSystemEntries($current)) { $pending.Enqueue($child) } }
    }
    $verificationReason = $null
    Write-SetupStage 'complete'
    [Console]::Out.WriteLine('{"schema_version":1,"ok":true}')
    [Console]::Out.Flush()
    exit 0
} catch {
    $terminal = '{"schema_version":1,"ok":false}'
    try {
        if ($null -ne $verificationReason) {
            $failure = [ordered]@{ reason=$verificationReason; category=(Get-SetupNodeCategory $path $current);
                owner_is_user=$ownerIsUser; owner_is_token_owner=$ownerIsTokenOwner; token_owner_is_user=$tokenOwnerIsUser }
            $terminal = [ordered]@{ schema_version=1; ok=$false; failure=$failure } | ConvertTo-Json -Compress
        }
    } catch { $terminal = '{"schema_version":1,"ok":false}' }
    [Console]::Out.WriteLine($terminal)
    [Console]::Out.Flush()
    exit 1
}
