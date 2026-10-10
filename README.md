# triage-with-rclone

**Cloud triage and acquisition CLI for Windows.**

View files in cloud storage, choose what to collect, and save copies with a record of each transfer. Use the menu mode or type commands.

## Get started

1. Open [Downloads](https://github.com/Donovoi/triage-with-rclone/releases) and choose the newest **nightly**.
2. Download the ZIP for your PC: **x64**, **x86** (32-bit), or **ARM64**. Check **Settings > System > About > System type** if unsure. Older nightlies may offer only an x64 `.exe`; run that file directly.
3. Extract the ZIP. Open PowerShell in that folder and run:

```powershell
.\rclone-triage.exe --tui --name case-001 --output-dir C:\Cases
```

4. Follow the menus to connect an account, view its files and choose what to collect. In the provider list, press **Space** to check a provider, then **Enter** to continue.

For command options, run `.\rclone-triage.exe --help`.

Keep the transfer records with the collected files. Protect the case folder: saved account settings can contain login credentials.

## Status

**Under development. Nightlies are test builds.** Provider testing is not complete. A provider appearing in the menu does not mean it has passed tests with a real account.

A new nightly is published after each merged PR passes the required checks. Builds target Windows 10/11 on x64, x86 and ARM64. A full release will wait until every supported provider has completed the required tests.

See [test status and known gaps](rclone-triage/tests/provider_testing.md) for the detailed results.

Local-file and ZIP command tests have passed, including cancellation and cleanup. Current work: record those results in the test status and finish cloud login tests.

## What comes next

- Finish tests for login, file lists, downloads, cancellation and cleanup across all providers.
- Complete Windows testing and publish a full release.
- Then work on an Android and iPhone sign-in collector to help authorise cloud access.

## More information

- [Build instructions and technical guide](docs/technical-guide.md)
- [Changes and remaining work](HARDENING.md)
- [Apache-2.0 licence](LICENSE)
