# Technical guide

Windows cloud acquisition CLI and terminal UI, built in Rust with a verified rclone runtime embedded in the executable. The current development version is **0.2.0**; [rclone-version.env](../rclone-version.env) records the embedded runtime version and hashes. Windows 10/11 are the deployment targets; Linux CI exercises the portable library, mocked integrations and isolated native protocol fixtures.

## Build and run

The app is built in Rust. Windows packages are produced for x64, x86 and ARM64. Each package embeds the matching rclone executable. This is a native application; there is no single AnyCPU executable. The x64 build runs its tests on a Windows x64 runner. The x86 build runs 32-bit tests on Windows x64. The ARM64 build runs tests on a Windows ARM64 runner. These checks do not establish real-account provider acceptance on each platform.


Install Rust with the MSVC toolchain and Visual Studio C++ build tools. CI uses Rust 1.95.0. From the repository root:

```powershell
./scripts/download-rclone.ps1
cd rclone-triage
cargo build --locked --release
./target/release/rclone-triage.exe --name investigation-001 --output-dir C:/Cases
```

For a different Windows target, prepare its matching runtime and build that target explicitly:

| PC type | Bootstrap option | Rust target |
| --- | --- | --- |
| x64 | `-Architecture x64` | `x86_64-pc-windows-msvc` |
| x86 | `-Architecture x86` | `i686-pc-windows-msvc` |
| ARM64 | `-Architecture arm64` | `aarch64-pc-windows-msvc` |

From the repository root, run `rustup target add TARGET` and `./scripts/download-rclone.ps1 -Architecture ARCH`. Then enter `rclone-triage` and run `cargo build --locked --release --target TARGET`. The output is under `target/TARGET/release`. The bootstrap defaults to x64; on ARM64, also use an explicit target when building locally. Install the matching Visual Studio C++ tools. Rust's [Windows target documentation](https://doc.rust-lang.org/rustc/platform-support/windows-msvc.html) describes the toolchain requirements. GitHub provides a [native Windows ARM64 runner](https://github.com/actions/runner-images/blob/main/README.md) for CI.

The bootstrap checks both the downloaded archive and extracted executable against [rclone-version.env](../rclone-version.env). Linux contributors must also prepare the embedded Windows asset with `bash scripts/download-rclone.sh` before compiling. A daily workflow checks the official stable release and proposes verified runtime updates; see [runtime maintenance](#runtime-maintenance).

The UI supports authentication, existing-config selection, listing, CSV/XLSX queue import, and file acquisition. Case name and output directory apply to both CLI and UI. `/` searches the inventory and `n` advances between matches. Source config files are copied into private working snapshots inside the case; originals are preserved even when rclone refreshes tokens or creates a combined listing remote.

## Acquire a queue

```powershell
./rclone-triage.exe --name investigation-001 --output-dir C:/Cases `
  --rclone-config-path C:/Configs/rclone.conf --download queue.csv
```

To limit each file's transfer speed, add `--download-bytes-per-second 65536` for 64 KiB/s per file. Use a whole number from 1 to 4294967295. Files downloaded at the same time each have this limit, so their rates add together. Leave the option out for the normal transfer speed. This option applies to command-line queue downloads.

```csv
Path,Remote,Size,Hash,HashType,IsDir
Documents/report.pdf,DriveA,1024,,,false
Documents/report.pdf,DriveB,2048,,,false
```

`Remote` resolves each row to its actual configured source. Rows without it require `--remote NAME` unless there is only one configured remote. Remote names and object paths remain distinct; output paths are recorded in the manifest, including remapping for Windows names and collisions. Relative path traversal, absolute paths, symlinks/reparse-point destinations, and ambiguous separators are rejected. Directory rows are skipped; select or list their individual files to acquire their contents. Existing acquired files are preserved under newly allocated destination names on later runs.

Windows single-letter remote names are rejected because rclone interprets them as drive letters. Configured runners ignore inherited `RCLONE_*` overrides except `RCLONE_CONFIG_PASS`; the selected config and explicit per-call settings determine the source and transfer behavior.

Every run writes a plan before transfers and final outcomes afterward. A failed source, cancellation, size discrepancy, or supported source-hash mismatch produces an incomplete manifest and a nonzero CLI exit status. Every transferred file has a local SHA256; that local digest alone does **not** establish agreement with the cloud source. `integrity` distinguishes verified, unverified, unsupported-hash, mismatched, failed, cancelled, and dry-run outcomes. Keep the manifest and original queue with the acquired files.

## Evidence and privacy

Case directories contain listings, downloads, config snapshots with source SHA256 provenance, acquisition manifests, reports, and hash-chained logs. JSON-line log records safely encode newlines; checkpoints record the final hash and entry count. Keep checkpoints separately to detect truncation: a hash chain without a trusted external checkpoint cannot detect removal of its tail or wholesale replacement. These are integrity aids, not digital signatures or a claim of legal admissibility.

**Case configs contain credentials.** Restrict access to the case directory and storage. New application-created Windows case artifacts use an explicit current-user owner and a protected user/SYSTEM ACL. Download publication copies the child-created bytes through held file handles into a secured file, verifies the copy, preserves timestamps and publishes without replacing existing evidence. Keep original evidence separately.

Existing non-private exports and logs are not repaired or overwritten. Use a fresh case or export name; old logs remain available for read-only integrity checks. Imported configs are copied into new working snapshots. Rclone can replace a working config during token refresh; secure refresh persistence and coordination between concurrent jobs remain separate unverified work. The HTTP application test does not establish OAuth refresh behavior.

Use one application instance per case folder. Replacing a saved report or manifest assumes no competing writer in that folder; the file checks do not make concurrent replacement by the same Windows user transactional.

Command-line runtime cleanup uses the original directory identity and refuses a replacement. It has no later path-only fallback. A runtime cleanup error makes the command fail, even if the transfer succeeded; an earlier operation error is preserved too. A short cleanup diagnostic contains only a fixed stage, error category and numeric system code. Menu mode still has legacy cleanup registrations; mount processes also need a retained runtime owner and a confirmed exit before cleanup. Those paths need separate fixes and acceptance tests. The HTTP CLI test does not verify them.

SQLite browser stores are opened read-only and snapshotted through SQLite's backup API into memory, including committed WAL contents; locked or inaccessible stores produce errors instead of a stale raw-file copy. OneDrive vault handling does not decrypt BitLocker volumes. System-state collection and browser access have not been validated against every endpoint protection product.

`--collect-logs` creates a local redacted diagnostic archive. It redacts environment values and structured secret settings before writing staging files, omits listing contents, and does not automatically transmit the bundle. Arbitrary log prose and paths may still contain case information: inspect the archive before sharing. Redacted logs are diagnostic copies, not the original hash-verifiable evidence.

## Provider and network limits

Backend discovery comes from the pinned runtime. A discovered backend or successful mock test is not proof of account-level provider compatibility. Consult the current [rclone backend documentation](https://rclone.org/overview/) for permissions and provider-specific limits.

New Google Drive/Photos authorization requires your own OAuth client; see [rclone's Google Drive client instructions](https://rclone.org/drive/#making-your-own-client-id). New Drive/OneDrive authorization requests read-only file access. Existing remote credentials retain the permissions previously granted by their provider. Google Photos API access is limited by Google's app-created-data policy and is not an unrestricted photo-library export.

For Google Drive, OneDrive and Dropbox, `--provider NAME --auth-only` saves authentication without SSO/profile inspection, account/drive discovery, connectivity probes, or file listing. This mode requires your own OAuth client registration; it does not borrow the bundled OneDrive registration's secret. `--no-browser` prints the authorization URL after the application has bound its loopback listener, so another browser can complete the flow. The callback still goes to `http://localhost:53682/`; opening the URL on a different machine requires a controlled relay back to that listener. OneDrive also supports `--auth-only --device-code` with a suitable registration. Google and Dropbox require browser authorization in this mode. Ordinary `--provider` behavior still authenticates and lists the remote.

OneDrive auth-only requests exactly `Files.Read offline_access` in browser and device-code flows and saves the same `access_scopes` for refresh. This is intended for reading the signed-in user's own drive: Microsoft documents `Files.Read` as sufficient for [listing](https://learn.microsoft.com/en-us/graph/api/driveitem-list-children?view=graph-rest-1.0) and [downloading](https://learn.microsoft.com/en-us/graph/api/driveitem-get-content?view=graph-rest-1.0). It does not request `Files.Read.All` or `Sites.Read.All`, and does not perform SharePoint discovery. This is not a drive or folder permission boundary: for personal accounts, [`Files.Read` also permits reading shared files](https://learn.microsoft.com/en-us/graph/permissions-reference#filesread). Ordinary OneDrive authorization retains its broader discovery permissions. A narrower request does not revoke permissions previously granted to the OAuth client.

Dropbox auth-only requests exactly `files.metadata.read files.content.read`, offline access and S256 PKCE. It rejects a grant with missing or extra scopes, missing refresh credentials, duplicate response fields or invalid expiry before saving it. Create and verify an **App Folder** registration separately: the app key and scopes alone do not prove that boundary. Existing broader grants are not revoked. This path does not request prior grants or save account metadata. Real login, refresh and file access still need vendor acceptance tests; source and local protocol tests do not establish them.

Authentication reads custom OAuth JSON from the process environment variable `RCLONE_TRIAGE_OAUTH_CONFIG`, or the platform config directory's `rclone-triage/oauth.json`. `--oauth-config-path` only selects the destination of the interactive `--set-oauth-creds` writer. For a controlled guest session, prepare a private directory and inject the credential file there without putting secrets in arguments, shell history, or transcripts:

```powershell
$env:RCLONE_TRIAGE_OAUTH_CONFIG = 'C:\PrivateCase\oauth.json'
.\rclone-triage.exe --provider drive --auth-only --no-browser --output-dir C:\PrivateCase\auth
```

The saved config is under the selected output directory's `config\rclone.conf`; Windows inherits that directory's ACL. Keep stdout/stderr private too: an authorization URL includes session state, device codes are temporary credentials, and provider errors may contain private details. Ctrl+C cancels callback/poll waits, and the application checks cancellation before saving a token response; an HTTP request already in progress can take up to its 30-second timeout to return. Preserve the authenticated config securely, then use a separate working copy for acquisition. Before listing a Drive or OneDrive task folder, set its exact `root_folder_id`; OneDrive also needs the intended `drive_id` and `drive_type`, because auth-only deliberately skips their discovery. For Dropbox App Folder access, use paths relative to the app folder and avoid account, namespace and shared-file operations. Folder-root configuration limits the requested inventory, not the OAuth token's permissions. This mode completes authorization; it does not claim the chosen drive or folder is reachable.

OAuth state remains secret and direct authorization-code flows use PKCE. Mobile callbacks require the documented matching client redirect URI; ordinary HTTP LAN callbacks do not provide transport confidentiality. Prefer loopback/desktop or device-code authorization where practical. Real OAuth, browser decryption, mounted vaults, and AP hardware behavior require controlled acceptance testing with explicit test accounts/devices.

The Windows forensic access-point controller owns its WLAN session and temporary firewall rule, refuses to take over an already active hosted network, restores saved settings on graceful stop, and does not change adapter DNS. Keep the controller process open until its timeout or Ctrl+C. Unsupported adapters fail explicitly. Forced termination or OS failure cannot guarantee graceful restoration; check host state after an abnormal stop. `--forensic-ap-stop` never force-stops another process's network.

## Validation and releases

```powershell
./scripts/run-windows-tests.ps1
```

Equivalent crate commands are `cargo fmt --all -- --check`, `cargo clippy --locked --all-targets --all-features -- -D warnings`, and `cargo test --locked --release -- --test-threads=1`. Live cloud tests are ignored by default; see [provider testing](../rclone-triage/tests/provider_testing.md) for explicit opt-in and acceptance limits.

CI checks every curated provider contract and every selectable backend in the actual pinned runtime, plus local login-protocol fixtures. It also exercises real rclone local, memory, archive, HTTP, WebDAV, FTP, SFTP, S3, Swift, B2, Azure Blob, Azure Files, Seafile, Koofr, Pixeldrain, FileFabric, Internet Archive, NetStorage, pCloud and Google Cloud Storage backends against isolated synthetic sources. Archive tests verify local ZIP members and CRC32, independent download SHA256, corruption and read-only behavior; Windows CLI regressions separately check acquisition manifests. Swift v1 and B2 native API fixtures verify token reacquisition after a forced 401 and rejection when renewal is denied. Azure Blob and Azure Files fixtures independently verify SharedKey signatures, reject invalid credentials and check download hashes against their separate REST protocols. Seafile requires observed fresh account-token acquisition before authenticated reads, with separate wrong-password and invalid-token rejection. The memory fixture verifies one-process batch results and independent readbacks without claiming persistence after exit. Koofr fixtures verify Basic-authenticated mount selection and exact member reads, separating setup failures from member denials. Pixeldrain fixtures verify configured-key filesystem reads with independent SHA256 and distinct setup, member-denial and missing-object cases. FileFabric requires separate receipts for complete cached-session reads and later-call session-token reacquisition after an injected expiry response, denied reacquisition, preserved config scope and saved-token reuse by a fresh process. That controlled protocol case does not establish fresh account login, real appliance expiry or atomic config persistence. Internet Archive pairs anonymous public-read evidence with a separate protected LOW-header fixture: generated valid credentials read a known member, wrong or absent credentials are rejected, and a content denial remains distinct from authentication failure. Both receipts are required for its bounded local protocol tier; neither establishes a live IA account or login. NetStorage checks independently verified request signatures, complete fixed-prefix reads and distinct wrong-secret, missing-member and content-denial cases; it does not establish hosted login or secret renewal. pCloud adds isolated HTTPS saved-token reads, wrong-token rejection, content denial and independent hashes; a separate Linux OAuth suite checks fresh authentication and owned process cancellation. Both receipts are required for its local protocol tier. These fixtures do not establish hosted-service acceptance. A versioned [coverage policy](../provider-coverage-policy.json) and [evidence ledger](../rclone-triage/tests/provider_testing.md#layered-provider-evidence) keep protocol tests, application acceptance and real service acceptance separate. Missing/new/changed provider plans fail CI; missing acceptance stays visible in the ledger.

Linux CI also runs an independent Samba NTLM fixture in a disposable container, checks its runtime/source identity and cleanup, and combines its fresh receipt with the baseline, FileFabric renewal, IA LOW and pCloud authentication evidence. The combined gate requires twenty-one complete local protocol profiles; the Windows gate requires nineteen and leaves SMB and fresh pCloud authentication unverified. A profile qualifies only when its current receipts pass. Kerberos, session recovery and application/real-vendor acceptance remain separate requirements. See the [SMB evidence contract](../rclone-triage/tests/provider_testing.md#linux-smb-evidence).

Nightly reports show missing credentials explicitly and can require selected-account read access for every backend. Saved-credential access tests do not establish fresh login or token refresh. The stricter evidence ledger remains incomplete until all applicable acceptance checks are verified.

For acceptance of the downloaded Windows executable in a disposable, disconnected guest, use the [CLI and TUI acceptance harnesses](../scripts/acceptance/windows/README.md). They exercise synthetic local sources and retain machine-readable results; they do not establish live-provider or physical-device compatibility.

Every successful main-branch CI run after a merged PR publishes a new nightly prerelease. PR checks alone do not publish a release. Publication requires the existing Windows/Linux checks and the x86/ARM64 Windows build and test jobs. Failed or cancelled checks prevent publication. The workflow never promotes a nightly to a stable release; a full release must wait for the provider acceptance work. Release assets include one ZIP per Windows architecture, executable SHA256 checksums, the runtime manifest, a Cargo dependency inventory, and GitHub build provenance. Each ZIP contains rclone-triage.exe and its supporting records. Verify a downloaded package with `gh attestation verify rclone-triage-windows-x64.zip --repo Donovoi/triage-with-rclone` (use the matching architecture filename) and compare the release `SHA256SUMS`. Extracted files have a separate `SHA256SUMS` inside the ZIP. A dependency inventory is not a complete SBOM for the embedded Go runtime.

See [the hardening record](../HARDENING.md) for the reviewed failures, regression coverage, and remaining acceptance work. Inventory entries remain memory-resident; million-object cases require capacity measurements before use. The legacy PowerShell coverage document is historical, not a current parity guarantee.

## Runtime maintenance

The daily `Propose latest stable rclone` workflow reads [the official stable version](https://downloads.rclone.org/version.txt), verifies Windows x64/x86/ARM64 and Linux x64 archives against the official SHA256SUMS, and pins each extracted executable's hash. It downloads candidates for verification without executing them. Checksums are trusted through the official HTTPS origin; the updater does not independently verify their PGP signature.

Updates use one guarded `automation/rclone-stable` branch and a reviewable PR. The workflow explicitly dispatches Windows/Linux CI for the exact proposed commit, including native provider-catalog checks, because bot-created PR events alone do not guarantee CI runs. Updates require passing checks and review before merge. Failed downloads, changed checksums or provider contracts keep the current pin intact. Daily scheduling and review introduce delay after an upstream release; the embedded runtime never silently self-updates.

Run `python scripts/update-rclone.py` for a dry run, or `python scripts/update-rclone.py --write` to prepare the verified manifest change locally. Use `--refresh-current` to reverify the pinned release. The full Python regression suite requires the isolated, hash-pinned [test environment](../rclone-triage/tests/provider_testing.md#python-test-environment). Both bootstraps and CI consume the same runtime manifest.

Licensed under [Apache-2.0](../LICENSE).
