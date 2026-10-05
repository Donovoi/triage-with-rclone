#requires -Version 5.1
<#
Actual console acceptance: launches the verified release only inside an isolated
Hyper-V Windows guest. Uses ConPTY and real keyboard input, never app test hooks.
Copy this script and ConPtyHarness.cs together. Run after guest-acceptance.ps1.
The raw VT transcript is authoritative; reconstructed text ignores colors/fonts.
#>
[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)][string]$BinaryPath,
    [Parameter(Mandatory = $true)][string]$ExpectedComputerName,
    [Parameter(Mandatory = $true)][switch]$IsolatedGuest,
    [string]$OutputRoot = 'C:\TriageAcceptance',
    [Parameter(Mandatory = $true)][ValidatePattern('^[a-fA-F0-9]{64}$')]
    [string]$ExpectedSha256,
    [ValidateRange(10, 180)][int]$StepTimeoutSeconds = 30,
    [switch]$SkipAcquisition
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
$script:Utf8 = New-Object Text.UTF8Encoding($false)
$script:Checks = New-Object 'System.Collections.Generic.List[object]'
$script:Sessions = New-Object 'System.Collections.Generic.List[object]'
$script:Inputs = New-Object 'System.Collections.Generic.List[object]'
$script:Started = [DateTime]::UtcNow
$script:Session = $null
$script:Scenario = ''
$script:RunRoot = $null
$script:SnapshotCounter = 0
$script:Guest = $null
$script:ActualSha256 = $null
$script:PickerWindowsClosed = 0

function Assert-True([bool]$Value, [string]$Message) { if (-not $Value) { throw $Message } }
function Write-Utf8([string]$Path, [string]$Content) { [IO.File]::WriteAllText($Path, $Content, $script:Utf8) }
function Add-Check([string]$Name, [string]$Status, [string]$Detail, [string]$ErrorText = '') {
    $script:Checks.Add([ordered]@{ name=$Name; status=$Status; detail=$Detail; error=$ErrorText; utc=[DateTime]::UtcNow.ToString('o') })
}
function Assert-NoReparse([string]$Path) {
    $current=[IO.Path]::GetFullPath($Path)
    while ($current) {
        if (Test-Path -LiteralPath $current) {
            $item=Get-Item -LiteralPath $current -Force
            Assert-True (($item.Attributes -band [IO.FileAttributes]::ReparsePoint) -eq 0) "Reparse path refused: $current"
        }
        $parent=[IO.Directory]::GetParent($current)
        if ($null -eq $parent) { break }
        $current=$parent.FullName
    }
}
function Save-Viewport([string]$Label) {
    $script:SnapshotCounter++
    $name='{0:D3}-{1}-{2}.txt' -f $script:SnapshotCounter,$script:Scenario,$Label
    $path=Join-Path $script:RunRoot $name
    Write-Utf8 $path $script:Session.Screen.Snapshot()
    return $path
}
function Send-Keys([string]$Label, [string]$Text, [int]$DelayMs = 180) {
    $script:Inputs.Add([ordered]@{utc=[DateTime]::UtcNow.ToString('o');scenario=$script:Scenario;label=$Label;codepoints=@($Text.ToCharArray() | ForEach-Object {[int]$_})})
    $script:Session.Send($Text)
    if ($DelayMs -gt 0) { Start-Sleep -Milliseconds $DelayMs }
}
function Wait-Screen([string]$Pattern, [int]$Seconds = $StepTimeoutSeconds, [switch]$Absent) {
    $deadline=[DateTime]::UtcNow.AddSeconds($Seconds)
    do {
        $screen=$script:Session.Screen.Snapshot()
        $matchesPattern=$screen -match $Pattern
        if (($matchesPattern -and -not $Absent) -or (-not $matchesPattern -and $Absent)) { return $screen }
        if ($script:Session.HasExited) { throw "Application exited before viewport matched '$Pattern'; code=$($script:Session.ExitCode)" }
        Start-Sleep -Milliseconds 100
    } while ([DateTime]::UtcNow -lt $deadline)
    $saved=Save-Viewport 'timeout'
    throw "Viewport timeout for '$Pattern' (absent=$Absent). Evidence: $saved"
}
function Save-Results {
    if (-not $script:RunRoot) { return }
    $failed=@($script:Checks | Where-Object {$_.status -eq 'FAIL'}).Count
    $notRun=@($script:Checks | Where-Object {$_.status -eq 'NOT_RUN'}).Count
    $result=[ordered]@{
        schema_version=1; suite='actual-console-tui'; started_utc=$script:Started.ToString('o'); completed_utc=[DateTime]::UtcNow.ToString('o')
        status=$(if($failed){'FAIL'}elseif($notRun){'PARTIAL'}else{'PASS'}); failed_checks=$failed; not_run_checks=$notRun
        machine=$env:COMPUTERNAME; guest=$script:Guest; binary_path=$BinaryPath; binary_sha256=$script:ActualSha256
        # Windows PowerShell 5.1 array-subexpression conversion of Generic.List
        # can throw ArgumentException; explicit arrays also preserve empty lists.
        checks=$script:Checks.ToArray(); sessions=$script:Sessions.ToArray(); inputs=$script:Inputs.ToArray(); picker_windows_closed=$script:PickerWindowsClosed
        limitations=@('No provider accounts/network/mounts/BitLocker/browser profile acquisition tested.', 'VT snapshots reconstruct text cells only; raw .vt bytes preserve exact output. Colors, fonts and human visual usability are not qualified.', 'Native config picker is cancelled through its own window; acceptance exercises the real TUI fallback browser.', 'Process-tree cleanup uses a Windows Job Object; forced cleanup is a failure, never a graceful-exit pass.')
        sources=@('https://learn.microsoft.com/windows/console/creating-a-pseudoconsole-session','https://learn.microsoft.com/windows/console/closepseudoconsole')
    }
    Write-Utf8 (Join-Path $script:RunRoot 'results.json') ($result | ConvertTo-Json -Depth 12)
}
function Invoke-ConsoleScenario([string]$Name, [scriptblock]$Body) {
    $script:Scenario=$Name
    $script:Session=$null
    $appOutput=Join-Path $script:RunRoot ($Name+'-case-output')
    [void][IO.Directory]::CreateDirectory($appOutput)
    $transcript=Join-Path $script:RunRoot ($Name+'.vt')
    $exitCode=$null
    try {
        $script:Session=[TriageLab.ConPtySession]::Start($BinaryPath, [string[]]@('--tui','--name',('vm-'+$Name),'--output-dir',$appOutput),$script:RunRoot,$transcript,120,34)
        & $Body $appOutput
    } catch {
        Add-Check ($Name+'-scenario') 'FAIL' 'Scenario did not complete.' ($_.Exception.ToString()+"`n"+$_.ScriptStackTrace)
        if ($script:Session) { [void](Save-Viewport 'failure') }
    } finally {
        if ($script:Session) {
            if (-not $script:Session.HasExited) {
                try { Send-Keys 'graceful-q' 'q'; [void]$script:Session.WaitForExit(5000) } catch { }
            }
            $wasExited=$script:Session.HasExited
            if ($wasExited) { $exitCode=$script:Session.ExitCode }
            $unsupported=@($script:Session.Screen.Unsupported)
            $outputBytes=$script:Session.OutputBytes
            $readerError=$script:Session.ReaderError
            $appPid=$script:Session.ProcessId
            $script:Session.Dispose()
            $script:Sessions.Add([ordered]@{scenario=$Name;process_id=$appPid;transcript=$transcript;output_bytes=$outputBytes;exit_code=$exitCode;forced_termination=$script:Session.ForcedTermination;residual_processes_at_close=$script:Session.ResidualProcessesAtClose;reader_error=$readerError;unsupported_vt=$unsupported})
            if ($wasExited -and $exitCode -eq 0 -and -not $script:Session.ForcedTermination -and $script:Session.ResidualProcessesAtClose -eq 0) {
                Add-Check ($Name+'-graceful-exit') 'PASS' 'Quit input produced exit 0 with no processes remaining in the test job.'
            } else {
                Add-Check ($Name+'-graceful-exit') 'FAIL' 'Exit or process-tree ownership check failed.' "exit=$exitCode; forced=$($script:Session.ForcedTermination); active=$($script:Session.ResidualProcessesAtClose)"
            }
            if ($readerError) { Add-Check ($Name+'-output-reader') 'FAIL' 'ConPTY output reader failed.' $readerError }
            if ($unsupported.Count -gt 0) { Add-Check ($Name+'-viewport-parser') 'FAIL' 'Unhandled VT sequences require reviewing the transcript before accepting reconstructed viewport assertions.' ($unsupported -join '; ') }
            $script:Session=$null
        }
        Save-Results
    }
}

try {
    Assert-True ([bool]$IsolatedGuest) 'Pass -IsolatedGuest only inside the disposable VM.'
    Assert-True ($env:COMPUTERNAME -ieq $ExpectedComputerName) 'Guest computer name does not match the explicitly expected target.'
    $script:Guest=Get-CimInstance Win32_ComputerSystem | Select-Object Manufacturer,Model,Name
    Assert-True ($script:Guest.Manufacturer -eq 'Microsoft Corporation' -and $script:Guest.Model -eq 'Virtual Machine') 'Refusing to run outside the expected Hyper-V guest.'
    Assert-True (@(Get-NetAdapter -ErrorAction Stop | Where-Object {$_.Status -eq 'Up'}).Count -eq 0) 'Guest network adapter is Up. Disconnect it before acceptance.'
    Assert-True (@(Get-Process -Name 'rclone-triage','rclone' -ErrorAction SilentlyContinue).Count -eq 0) 'Run CLI/TUI suites sequentially; existing app/rclone process detected.'
    $BinaryPath=(Resolve-Path -LiteralPath $BinaryPath).Path
    Assert-NoReparse $BinaryPath
    Assert-NoReparse $OutputRoot
    $script:ActualSha256=(Get-FileHash -LiteralPath $BinaryPath -Algorithm SHA256).Hash.ToLowerInvariant()
    Assert-True ($script:ActualSha256 -eq $ExpectedSha256.ToLowerInvariant()) 'Release SHA256 mismatch.'
    $script:RunRoot=Join-Path ([IO.Path]::GetFullPath($OutputRoot)) ('tui-run-'+[DateTime]::UtcNow.ToString('yyyyMMddTHHmmssZ')+'-'+[guid]::NewGuid().ToString('N').Substring(0,8))
    [void][IO.Directory]::CreateDirectory($script:RunRoot)
    Add-Check 'isolated-target-and-release' 'PASS' 'Expected Hyper-V computer, no Up NIC, no prior app process, pinned binary SHA256 verified.'
    Add-Type -Path (Join-Path $PSScriptRoot 'ConPtyHarness.cs')
    $esc=[string][char]27
    $enter=[string][char]13
    $backspace=[string][char]127
    $down=$esc+'[B'
    $up=$esc+'[A'

    Invoke-ConsoleScenario 'navigation' {
        param($appOutput)
        [void](Wait-Screen 'mission menu')
        [void](Save-Viewport 'launch-120x34')
        Add-Check 'main-menu-render' 'PASS' 'Real console launch rendered the mission menu at 120x34.'
        Send-Keys 'down-to-detect' $down
        [void](Wait-Screen 'Scan installed browsers')
        [void](Save-Viewport 'navigation-down')
        Send-Keys 'up-to-auth' $up
        [void](Wait-Screen 'Launch browser-based authentication')
        Send-Keys 'wrap-up-to-exit' $up
        [void](Wait-Screen 'Exit the application')
        [void](Save-Viewport 'navigation-wrap')
        Send-Keys 'wrap-down-to-auth' $down
        [void](Wait-Screen 'Launch browser-based authentication')
        Add-Check 'menu-navigation-and-wrap' 'PASS' 'Arrow keys changed visible selection descriptions; top/bottom wrap returned to auth.'
        Send-Keys 'enter-provider-selection-only' $enter
        [void](Wait-Screen 'Space toggle')
        Send-Keys 'open-provider-help' '?'
        # Match overlay-only content. The normal status panel itself says
        # "Press ? for provider help", so a loose case-insensitive title regex
        # cannot distinguish an open overlay from the underlying screen.
        $helpViewport=Wait-Screen 'Provider list sources'
        [void](Save-Viewport 'provider-help')
        $headingLines=@($helpViewport -split "`n" | Where-Object { $_.Contains('Provider list sources') })
        Assert-True ($headingLines.Count -eq 1) 'Expected one visible provider help heading.'
        $headingLine=$headingLines[0]
        $headingEnd=$headingLine.IndexOf('Provider list sources')+'Provider list sources'.Length
        $rightBorder=$headingLine.IndexOf([char]0x2502,$headingEnd)
        Assert-True ($rightBorder -gt $headingEnd) 'Help heading right border was not captured.'
        $afterHeading=$headingLine.Substring($headingEnd,$rightBorder-$headingEnd)
        Assert-True ($afterHeading.Trim().Length -eq 0) "Provider help overlay leaked background text after its heading: '$($afterHeading.Trim())'"
        Add-Check 'provider-help-overlay-clears-background' 'PASS' 'The actual console help heading row has blank cells through its right border; underlying provider text does not bleed through.'
        Send-Keys 'close-provider-help' $esc
        [void](Wait-Screen 'Provider list sources' -Absent)
        [void](Wait-Screen 'Space toggle')
        Add-Check 'provider-help-open-close' 'PASS' 'Help overlay opened and Esc dismissed it while the process remained alive; no authentication was started.'
        $script:Session.Resize(80,24)
        Start-Sleep -Milliseconds 700
        [void](Wait-Screen 'Backspace back')
        [void](Save-Viewport 'resized-80x24')
        $script:Session.Resize(120,34)
        Start-Sleep -Milliseconds 500
        Send-Keys 'back-to-main' $backspace
        [void](Wait-Screen 'mission menu')
        [void](Save-Viewport 'back-to-main')
        Add-Check 'console-resize-and-back' 'PASS' 'Actual ConPTY resize delivered a live 80x24 viewport; Backspace returned to the main menu after resize.'
        Send-Keys 'quit-main' 'q'
        Assert-True ($script:Session.WaitForExit(10000)) 'Main-menu q did not exit within 10 seconds.'
    }

    if ($SkipAcquisition) {
        Add-Check 'retrieve-list-and-download' 'NOT_RUN' 'Explicit -SkipAcquisition supplied; console navigation alone is not acquisition acceptance.'
    } else {
        $fixture=Join-Path $script:RunRoot 'synthetic-source'
        [void][IO.Directory]::CreateDirectory($fixture)
        $sourceHashes=@{}
        for ($i=0;$i -lt 60;$i++) {
            $name='item-{0:D3}.txt' -f $i
            $path=Join-Path $fixture $name
            Write-Utf8 $path ("Synthetic VM evidence {0:D3}`r`n" -f $i)
            $sourceHashes[$name]=(Get-FileHash -LiteralPath $path -Algorithm SHA256).Hash.ToLowerInvariant()
        }
        Invoke-ConsoleScenario 'acquisition' {
            param($appOutput)
            [void](Wait-Screen 'mission menu')
            Send-Keys 'down-to-detect' $down
            Send-Keys 'down-to-retrieve-list' $down
            [void](Wait-Screen 'List remote files using an authenticated config')
            [void](Save-Viewport 'retrieve-list-selected')
            Send-Keys 'enter-retrieve-list' $enter

            # Create only our synthetic config inside this scenario's newly created case.
            # The browser opens there; selecting '.' refreshes if the dialog failed early.
            $deadline=[DateTime]::UtcNow.AddSeconds($StepTimeoutSeconds)
            $caseConfig=$null
            do {
                $dirs=@(Get-ChildItem -LiteralPath $appOutput -Directory -Recurse -Filter 'config')
                if ($dirs.Count -eq 1) { $caseConfig=$dirs[0].FullName; break }
                Start-Sleep -Milliseconds 100
            } while ([DateTime]::UtcNow -lt $deadline)
            Assert-True ([bool]$caseConfig) 'RetrieveList did not create its case config directory.'
            $sourceConfig=Join-Path $caseConfig '00-synthetic.conf'
            Write-Utf8 $sourceConfig ("[LabRemote]`r`ntype = alias`r`nremote = {0}`r`n" -f $fixture)
            $configHash=(Get-FileHash -LiteralPath $sourceConfig -Algorithm SHA256).Hash

            # Cancel the real app-owned picker using its window close action. Never
            # inject a fake picker executable, edit app state, or kill it to fake success.
            $deadline=[DateTime]::UtcNow.AddSeconds($StepTimeoutSeconds)
            do {
                if ($script:Session.Screen.Snapshot() -match 'current directory') { break }
                $pickers=@(Get-CimInstance Win32_Process -Filter ("ParentProcessId = {0}" -f $script:Session.ProcessId) | Where-Object {$_.Name -ieq 'powershell.exe' -and $_.CommandLine -match 'OpenFileDialog'})
                foreach ($picker in $pickers) { $script:PickerWindowsClosed += [TriageLab.ConPtySession]::CloseConfigPickerWindows([int]$picker.ProcessId) }
                Start-Sleep -Milliseconds 200
            } while ([DateTime]::UtcNow -lt $deadline)
            [void](Wait-Screen 'current directory' -Seconds 2)
            Send-Keys 'refresh-config-browser' $enter
            [void](Wait-Screen '00-synthetic.conf')
            Send-Keys 'config-next-parent' $down
            Send-Keys 'config-next-fixture' $down
            [void](Wait-Screen 'LabRemote')
            [void](Save-Viewport 'synthetic-config-preview')
            Send-Keys 'load-local-alias-config' $enter
            [void](Wait-Screen '60 of 60 entries' -Seconds 60)
            [void](Wait-Screen '\[ \] item-000\.txt')
            [void](Save-Viewport 'listed-first-page')
            Add-Check 'retrieve-list-local-alias' 'PASS' 'Config browser loaded a real local alias through the release binary; all 60 fixture files reached the visible file list.'
            for($i=0;$i -lt 45;$i++) { Send-Keys 'file-down' $down 130 }
            $viewport=Wait-Screen 'item-045\.txt'
            Assert-True ($viewport -notmatch 'item-000\.txt') 'High file selection left the first page visible instead of scrolling.'
            Send-Keys 'select-one-file' ' '
            [void](Wait-Screen '\[x\] item-045\.txt')
            [void](Wait-Screen '1 selected')
            [void](Save-Viewport 'scrolled-file-selected')
            Add-Check 'file-viewport-and-selection' 'PASS' '45 real Down events moved beyond the first viewport; Space visibly selected item-045.txt and selection count is one.'
            Send-Keys 'download-selected-file' $enter
            [void](Wait-Screen 'Acquired 1/1 files' -Seconds 90)
            [void](Save-Viewport 'acquisition-complete')
            $manifests=@(Get-ChildItem -LiteralPath $appOutput -Recurse -File -Filter 'acquisition-manifest.json')
            Assert-True ($manifests.Count -eq 1) 'Expected exactly one acquisition manifest.'
            $manifest=Get-Content -LiteralPath $manifests[0].FullName -Raw | ConvertFrom-Json
            Assert-True ($manifest.complete -eq $true -and @($manifest.results).Count -eq 1 -and @($manifest.plan.files).Count -eq 1) 'Manifest is not a complete single-file acquisition.'
            Assert-True ($manifest.plan.files[0].remote_name -eq 'LabRemote' -and $manifest.plan.files[0].path -eq 'item-045.txt') 'Manifest source identity differs from the selected item.'
            $result=$manifest.results[0]
            Assert-True ($result.success -eq $true -and $result.source -eq 'LabRemote:item-045.txt') 'Manifest outcome/source incorrect.'
            $destinationFull=[IO.Path]::GetFullPath([string]$result.destination)
            $outputPrefix=[IO.Path]::GetFullPath($appOutput).TrimEnd('\')+'\'
            Assert-True ($destinationFull.StartsWith($outputPrefix,[StringComparison]::OrdinalIgnoreCase)) 'Manifest destination escaped this synthetic scenario output.'
            Assert-NoReparse $destinationFull
            $acquiredHash=(Get-FileHash -LiteralPath $result.destination -Algorithm SHA256).Hash.ToLowerInvariant()
            Assert-True ($acquiredHash -eq $sourceHashes['item-045.txt'] -and $result.local_sha256 -eq $acquiredHash) 'Acquired bytes or recorded local SHA256 differs from the independent fixture hash.'
            $downloadRoots=@(Get-ChildItem -LiteralPath $appOutput -Directory -Recurse -Filter 'downloads')
            $acquiredFiles=@($downloadRoots | ForEach-Object {Get-ChildItem -LiteralPath $_.FullName -Recurse -File})
            Assert-True ($acquiredFiles.Count -eq 1) 'Unselected files were acquired.'
            Assert-True ((Get-FileHash -LiteralPath $sourceConfig -Algorithm SHA256).Hash -eq $configHash) 'Imported source config was modified.'
            foreach($name in $sourceHashes.Keys) { Assert-True ((Get-FileHash -LiteralPath (Join-Path $fixture $name) -Algorithm SHA256).Hash.ToLowerInvariant() -eq $sourceHashes[$name]) "Source fixture mutated: $name" }
            Add-Check 'tui-acquisition-bytes-and-provenance' 'PASS' 'Exactly the selected file was acquired; its independent SHA256 matches the manifest, all sources and imported config are unchanged.'
            Send-Keys 'quit-complete' 'q'
            Assert-True ($script:Session.WaitForExit(10000)) 'Completion-screen q did not exit within 10 seconds.'
        }
    }
    Start-Sleep -Milliseconds 500
    $orphans=@(Get-Process -Name 'rclone-triage','rclone' -ErrorAction SilentlyContinue)
    Assert-True ($orphans.Count -eq 0) 'An app/rclone process remained after the sequential scenarios.'
    Add-Check 'no-orphan-app-processes' 'PASS' 'No rclone or rclone-triage process remains.'
} catch {
    Add-Check 'harness-or-target' 'FAIL' 'Harness or target prerequisite failed.' ($_.Exception.ToString()+"`n"+$_.ScriptStackTrace)
    Write-Error $_ -ErrorAction Continue
} finally { Save-Results }

if ($script:RunRoot) { Write-Output (Join-Path $script:RunRoot 'results.json') }
if (@($script:Checks | Where-Object {$_.status -eq 'FAIL'}).Count -gt 0) { exit 1 }
if (@($script:Checks | Where-Object {$_.status -eq 'NOT_RUN'}).Count -gt 0) { exit 2 }
exit 0
