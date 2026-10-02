# Windows release acceptance

These harnesses run the actual release executable against synthetic local files in a disposable, disconnected Hyper-V Windows guest. They require no Rust, Cargo, separate rclone installation, cloud account, or real evidence. VM provisioning and evidence export are the operator's responsibility.

## Prepare the guest

- Verify the downloaded executable's release checksum and GitHub attestation as described in the [repository README](../../../README.md#validation-and-releases). Retain the verified SHA256 independently; the harness checks that value but does not download or attest the binary.
- Use a clean Windows x64 Hyper-V guest with Windows PowerShell 5.1 or newer, `Get-CimInstance`, `Get-NetAdapter`, `Get-FileHash`, and ConPTY support for the TUI suite. Record the Windows edition/build and PowerShell version.
- Disconnect the guest network adapters and confirm isolation in the VM manager. The scripts also refuse an adapter whose status is `Up`; they do not change network settings.
- Copy `guest-acceptance.ps1`, `guest-tui-acceptance.ps1`, `ConPtyHarness.cs`, and the verified executable to local guest storage. Keep the TUI script and C# helper together. Use a local output directory with no reparse points or shared/redirected drives.
- Confirm the guest's computer name independently. Both scripts require that name, `-IsolatedGuest`, and an explicit 64-character `-ExpectedSha256`; they refuse a different name or a non-Hyper-V machine. Run the suites sequentially with no existing triage/rclone process.

## Run inside the guest

Replace the hash and guest name below with the independently verified values. Run each script in a separate PowerShell process so its exit code can be collected.

```powershell
$expectedSha256 = '<verified executable SHA256: 64 hexadecimal characters>'
$expectedGuestName = 'TRIAGE-LAB'
$common = @(
    '-BinaryPath', 'C:\Acceptance\Input\rclone-triage.exe',
    '-ExpectedComputerName', $expectedGuestName,
    '-IsolatedGuest',
    '-ExpectedSha256', $expectedSha256,
    '-OutputRoot', 'C:\TriageAcceptance'
)

& powershell.exe -NoProfile -File .\guest-acceptance.ps1 @common
$cliExit = $LASTEXITCODE
& powershell.exe -NoProfile -File .\guest-tui-acceptance.ps1 @common
$tuiExit = $LASTEXITCODE
@{ cli_exit = $cliExit; tui_exit = $tuiExit } | ConvertTo-Json
```

The CLI suite exercises startup, exact remote identity, source/config preservation, local hashes and manifests, inherited environment isolation, rejected paths, missing sources, hash mismatches, secret redaction, and process cleanup. Expected nonzero application exits are passing negative tests only when their output and evidence also satisfy the assertions.

The TUI suite drives real keys through ConPTY, records raw terminal output and reconstructed viewports, checks navigation/help/resize/quit, and retrieves, selects, and acquires a synthetic local file. It may dismiss its own native file dialog to exercise the fallback picker. `-SkipAcquisition` is a partial run and must not be reported as complete TUI acceptance. Viewports check text and layout; they do not validate fonts, colors, screen readers, or every terminal emulator.

## Interpret and retain results

Each invocation creates a unique run directory containing `results.json` and supporting evidence. Retain both script exit codes, stdout/stderr, the complete run directories, release identity/SHA256, and guest details. A pass requires exit code zero, all required checks passing, no timeout or skipped acquisition, and the expected manifests and payload hashes. A missing result or exit code is incomplete harness evidence, not an application pass. Classify failures using the command logs or raw terminal transcript before attributing them to the application.

Timeouts fail acceptance. The harnesses terminate only processes they launched and retain the run directory for inspection. They do not provision or shut down a VM, delete earlier evidence, or install software. Inspect exported results before disposing of the guest.

Keep raw results, terminal transcripts, synthetic canary configurations, VM disks, and provisioning credentials outside the repository. Record a concise dated result with the exact release hash and tested Windows version in [HARDENING.md](../../../HARDENING.md). Offline local aliases do not establish live-provider, OAuth/browser, vault, AP hardware, or other Windows-version acceptance; use the separate [provider validation guidance](../../../rclone-triage/tests/provider_testing.md) for that scope.
