# 0.2.0 hardening record

The review and implementation used separate data-correctness, security/forensics, and product-quality reviewers, followed by a round-robin challenge of the findings. Priorities reflect evidence preservation and correct acquisition before convenience and performance.

| Review issue | Implemented response | Regression evidence |
| --- | --- | --- |
| F01: vault operation decrypted caller volume | Remove Disable-BitLocker; fail closed on locked volume | Generated-command contract tests |
| F02: diagnostics leaked credentials | Redact before staging, restrictive temporary staging, local-only bundles | Secret canary unit and real CLI archive tests |
| F03: queue traversal escaped downloads | Shared path validator and no-link destination checks | Traversal/absolute-path tests and actual CLI rejection |
| F04: mixed remotes lost source identity | Shared planner keyed by remote and exact path; per-remote output namespace | CLI and TUI two-source acquisition regressions |
| F05: whitespace/case/Windows path collisions | Preserve object keys and allocate distinct deterministic mapped paths | Reordered-plan collision and exact queue roundtrip tests |
| F06: selected source config mutated | Per-case working snapshot with source SHA256 provenance and exact temporary-remote ownership | Source-config preservation tests |
| F07: RetrieveList could not download | Persistent acquisition source independent of provider-auth state | List/select/download TUI regression |
| F08: OAuth disclosed state/lacked PKCE | Generic mismatch response, constant-time comparison, PKCE for direct code flow | State/error/PKCE contract tests |
| F09: mismatch or missing source reported success | Explicit integrity status, local SHA256, plan/outcome manifests, nonzero CLI failure | Actual wrong-hash/missing-source CLI tests |
| F10: unknown negative sizes failed parsing | Optional size and explicit unknown display | Negative/missing size fixtures |
| F11: multiline logs broke chain | Canonical JSON-line records and hash/count checkpoints; legacy reader | Multiline, mutation, truncation, append-corruption tests |
| F12: SQLite copies lost WAL rows | Read-only SQLite backup into in-memory connection | Active WAL fixture |
| F13: copied browser DB persisted | Eliminate plaintext disk snapshot | Repeated extraction fixture and ownership checks |
| F14: background executable deleted too early | Worker owns extracted binary for full child lifetime | Background listing tests |
| F15: cancellation blocked behind reads/transfers | Independently polled child lifecycle, kill/wait and responsive owned UI workers | Quiet-process cancellation/timeout and queue outcome tests |
| F16: directory rows copied unreported descendants | Skip directory rows, stat file source, single-file operation | Directory rejection and per-file outcome tests |
| F17: UI ignored case CLI settings | Pass name/output directory into App | App initialization test |
| F18: provider CI missing embedded asset | Bootstrap pinned embedded and native runtimes; explicit ignored live test | Workflow build gates |
| F19: combine names with spaces failed | Quoted upstream entries and unique owned temporary names | Combine/config tests |
| F20: AP timeout lost when CLI exited | Process-owned native WLAN handle; keep controller alive; restore prior settings | Structural/unit checks; hardware acceptance pending |
| F21: UTF-8 case truncation panicked | Truncate only on character boundary | Boundary tests for accented/CJK/emoji names |

Additional changes include spreadsheet-formula-safe exports with explicit lossless encoding, visible-row UI rendering and indexed selection, read-only scopes for new supported OAuth flows, current pinned rclone, dependency updates, strict formatting/Clippy CI, SHA-pinned Actions, reduced workflow permissions, release checksums and provenance, and accurate version/license metadata.

The follow-up authentication correction in commit `22eff66866c367a7cd4c5e2c5eaeb45af2902cc9` propagates credential-loading errors, prevents a custom device-code client from borrowing another client's bundled secret, and applies the Google own-client migration guard before device authorization. Synthetic credential tests cover the isolation and migration decisions; they do not authenticate a real account.

## Release acceptance (2026-10-02)

The CLI harness reported **10 passed, 0 failed** for release `nightly-36989792783-1`, built from commit `22eff66866c367a7cd4c5e2c5eaeb45af2902cc9`. The executable SHA256 was `98ba4ad7e4f3bae5361fbe13083436465ffe5b9018ca0a059b0fea554dde907a`. It ran in a disposable Hyper-V Windows Server 2025 evaluation guest (OS build 26100, Windows PowerShell 5.1.26100.7462), with no active network adapters.

The checks covered startup, two local remotes with identical relative filenames, inherited rclone environment overrides, traversal rejection, missing-source and hash-mismatch failures, diagnostic secret redaction, source/config preservation, and process cleanup. Each application invocation recorded its exit code and completed without timeout. Independent inspection of the exported artifacts confirmed payload hashes, source-config provenance, retained mismatch evidence, and redacted diagnostic contents. The guest checked log-checkpoint presence and shape; cryptographic chain verification remains covered by repository tests.

Guest TUI inspection exposed provider-list text showing through the help popup. The rendering fix clears the popup area before drawing help. The local release candidate containing that fix, SHA256 `8552a536ca8b75fbd1793b15c5b6e5bf082c50d8a78eb8d6442a5f0df12e90df`, passed **10 CLI checks and 12 actual-console checks** on the same guest, with both harness exits zero. Console checks covered menu navigation, help background clearing and dismissal, resize, file-list scrolling, selecting and acquiring exactly one of 60 synthetic files, independent payload hashes, source preservation, and graceful process cleanup. No required check was skipped or timed out. Follow the [reusable guest harness instructions](scripts/acceptance/windows/README.md) to reproduce acceptance with a separately verified release; CI also parses the PowerShell scripts and compiles their native console helper.

A physical Samsung running Android 16 passed synthetic browser callback checks through an ADB reverse connection: missing/wrong state returned HTTP 400 without exposing state, and the correct Unicode code/state was accepted. A direct LAN request from the phone's existing curl also reached the actual OAuth listener and returned HTTP 200 with the exact payload accepted. Direct browser navigation over LAN still timed out, so that handoff remains unverified. These tests did not sign in to a cloud provider. The Server 2025 guest does not establish Windows 10/11, browser credential extraction, vault, or AP hardware acceptance.

## Live provider acceptance (2026-10-03)

Google Drive personal My Drive and Workspace My Drive each passed a ten-file CLI acquisition from a dedicated synthetic folder in the Windows Server 2025 guest. The tested executable was built from `c348e5a697e063173f2bfefb37335f44913bd4a8`, SHA256 `8fe7e30d626889b51023f0f44d1b144b47479b1fa52a21af3c2711f3ecff5f39`. Both runs exited zero; all twenty exported files independently matched the expected sizes and SHA256 hashes. The cases included empty files, Unicode, spaces, punctuation and duplicate basenames in different directories. Original configurations were preserved, with no timeout, forced termination or residual owned process.

Both Google account types also completed a real refresh grant and acquired a synthetic file with verified bytes. The personal-account worker completed successfully, but host remoting timed out while returning its result. Its completion record and matching protected configuration were recovered without another provider request, and the file was independently rehashed; the worker's original token-response comparison was retained rather than independently repeated. The Workspace run returned the complete result normally. These grants used read-only Drive scope.

Two additional personal-Drive cases verified cancellation while an authentication request was held locally and failure after locally injected `invalid_grant` responses. Both produced the expected nonzero exit and manifest status, no final file and clean process teardown. They made no upstream refresh request; they do not establish cancellation during a cloud download or actual provider-side revocation.

OneDrive personal passed the same ten-file baseline using the executable from `e2cf7853813cef02eb480125753e17caaccdca03`, SHA256 `52b0e0671c906cc1e978522fbc61b600197e588fcd57fac7e065362d63292d11`, with `Files.Read offline_access`. All ten exported files independently matched their expected sizes and SHA256 hashes; the app exited zero, preserved the source configuration and left no owned process, timeout or forced termination. Initial top-level stat failures were traced to the acceptance setup's raw folder ID. Qualifying it with the verified drive ID corrected those failures without an application code change; the [provider testing guide](rclone-triage/tests/provider_testing.md#restrict-a-onedrive-personal-acceptance-case-to-its-synthetic-folder) records the required setup. The failed run was retained separately.

OneDrive also passed an instrumented refresh-and-read case. A successful Microsoft refresh response was observed, the saved access/refresh token pair matched that response with future expiry, and the synthetic file's hash and manifest were verified. The original scoped config was preserved; the app, console and local observer finished cleanly, and the resulting configuration passed protected transport and storage roundtrip checks.

Account identifiers, cloud root identifiers, credentials and raw transcripts are excluded from this repository. Dedicated client credentials and successful working configurations are retained in the operator's credential vault. These results apply to the explicitly identified binaries and account types; Workspace My Drive does not establish Shared Drive compatibility. No before/after remote inventory or version comparison was collected to independently establish remote-source preservation.

## Live CLI acquisition and failure cases (2026-10-04)

The executable from commit `260f9878142c4818b960f801cecd6a46c54cc00b`, SHA256 `5b5f4bd4ff851cedb8b298f36e7afcdf2594095f4c91953ee6196b721baa112a`, passed **nine scenario checks** using rclone **1.75.1** in the Windows guest. Google Drive personal My Drive, Workspace My Drive and OneDrive personal each ran a ten-file baseline, a deliberately wrong expected SHA256, and a controlled missing-object case. Existing imported credentials and dedicated synthetic folders restricted the scope.

All three baselines exited zero and verified ten files each. Each hash-mismatch case exited one, marked acquisition incomplete with `Mismatch`, and retained the correct downloaded bytes. Each missing-object case exited one, marked acquisition incomplete with `Failed`, and produced no output; the harness required the exact missing-item preflight diagnostic. Independent export validation checked the queues, manifests, exact output inventories and all **33 retained files** against the synthetic fixture. All nine checks preserved the original input configuration and completed without timeout, forced termination or residual owned process. The lab was stopped and disconnected afterward.

The [sanitized aggregate](scripts/acceptance/windows/evidence/cloud-cli-2026-10-04.json) records case outcomes and application, runtime-pin, harness, validator and fixture provenance. It contains no account or cloud-root identifiers, credentials, private paths or raw transcripts. This batch does not establish fresh login, full inventory listing, refresh, authentication denial, revocation, cancellation, remote-source preservation by before/after comparison, or live TUI acceptance. Earlier refresh results apply to their separately identified binaries. Provider policy and application/vendor ledger statuses remain unchanged; these selected cases are not complete provider qualification.

### Koofr partial live acceptance (2026-10-04)

Koofr free native storage was tested in the isolated Windows lab with the same `260f9878142c4818b960f801cecd6a46c54cc00b` executable identified above. Application-password authentication worked, and listing verified ten dedicated synthetic files against their expected sizes and MD5 hashes. The application baseline **failed**: its manifest reported seven verified files and three failures, with exit code one and incomplete acquisition. This failed run did not produce a successful export receipt, so its downloaded bytes have not been independently revalidated.

Two binary-extension files received HTTP 403 `FileBlocked`. Koofr [documents restrictions on free-account access through nonofficial applications](https://koofr.eu/help/share-files-and-folders/i-have-a-free-account-and-cannot-share-certain-files-why/). Those files remain restricted and were not retried or counted as passes. The third failure exposed a Windows publication bug: a temporary staging path exceeded `MAX_PATH` while the final destination was shorter. [The fix](https://github.com/Donovoi/triage-with-rclone/pull/36) preserves the no-clobber move and passed four filesystem regressions plus required Windows/Linux CI. Its live retest remains pending.

The [sanitized partial result](scripts/acceptance/windows/evidence/koofr-cli-partial-2026-10-04.json) preserves the failed outcome and tested-build identity. The lab was stopped and disconnected, with no owned acquisition processes after diagnosis. The dedicated synthetic folder is retained for future tests; remote deletion, negative acquisition cases, refresh, revocation, cancellation and full provider acceptance remain unverified. No provider policy or ledger status was promoted.

## Provider coverage and runtime maintenance (2026-10-03)

Provider enumeration and exhaustive independent schema contracts now cover every curated provider. Windows/Linux CI also inspects the hash-verified native rclone catalog with an empty config, including newly discovered backends and their manual setup schemas. Synthetic login fixtures exercise the production loopback callback, state checks, PKCE and token exchange for every supported generic OAuth route. Auth-only tests verify successful persistence and failure rollback. These are protocol tests, not vendor login acceptance.

Review removed seven incompatible generic OAuth routes in favor of manual setup/config import, including pCloud's regional-host requirements and Zoho's region/root setup. Google device-code authorization is unavailable because its permitted scopes do not include the required read-only Drive/Photos access. Custom OAuth config errors now fail closed, credentials stay out of rclone arguments, and callback/token failures suppress provider-supplied private diagnostics.

Nightly access checks report every discovered backend, including missing credentials, and optionally require selected-account read access for every backend. Reports contain only backend categories, counts and statuses; they never treat saved-credential listing as proof of fresh login or refresh. The daily runtime updater verifies official release archives and extracted executables before proposing a manifest-only PR, then dispatches CI for that exact commit. Updates remain reviewable and do not change the running application's embedded runtime automatically. See [provider testing](rclone-triage/tests/provider_testing.md) and [runtime maintenance](README.md#runtime-maintenance).

Coverage plans now bind every selectable backend to its actual option contract. New, changed or removed backend plans fail the CI plan gate until reviewed. A separate evidence ledger distinguishes local protocol, application and hosted-service acceptance; current-runtime fixture receipts cannot satisfy the latter two layers. Expired, future, changed-runtime/harness or inconsistent receipts fail validation, and unresolved authentication-renewal applicability prevents full qualification.

The account-free lab exercises real local, HTTP, WebDAV, FTP, SFTP and S3 backends using loopback-only services, synthetic data and isolated configuration. It requires independent payload hashes, missing-file rejection, source preservation and cleanup; the independent HTTP/WebDAV/FTP fixtures also reject credential and write probes. SFTP/S3 use rclone's own servers, limiting those results to interoperability regressions. HTTP/WebDAV truncation and forced-process cancellation cases do not replace actual application cancellation or real vendor acceptance.

## Runtime and menu cleanup

Each extracted runtime now tracks the commands that use it. Cleanup closes admission to new commands and requires confirmed child exit, joined output readers and closed process handles. An uncertain shutdown keeps the runtime for inspection and reports failure. It does not retry deletion by path.

Mount and Web GUI owners keep their runtime until shutdown. Menu actions stop workers and services before changing account settings or resetting the flow. Worker, operation and cleanup errors remain visible together. Cancelling sign-in cannot return credentials from a process that already exited successfully.

Regression tests cover ownership, reader limits, cancellation and configuration retention, including panic paths. Full mount, Web GUI and menu acceptance still requires the isolated Windows lab; these changes do not add real-provider coverage.

On Linux and macOS, failed mount startup can retain the runtime if the unmount helper cannot confirm cleanup, even when the path was never mounted. This conservative limitation needs a separate OS mount-state check. Child exit alone is not proof that a mount is gone. Windows remains the deployment target.

## Acceptance still required

The provider results above cover only the named account types and scenarios. For remaining providers, run configured Test remotes using the explicit smoke workflow, then verify auth, listing, sample download, token refresh, and cleanup. Live cloud TUI acquisition, Shared Drives, actual grant revocation and mid-download cloud cancellation remain unverified. AP hardware, real browser encryption, and vault accessibility need dedicated Windows lab acceptance. Abrupt process/OS termination is not equivalent to graceful cleanup; retain manifests and inspect partial files after interruption.

The acquisition plan protects against observed path/collision mistakes and existing symlinks/reparse points. It is not a filesystem sandbox against a privileged process concurrently replacing destination components. Use an access-controlled output directory. Providers may mutate objects during acquisition; source version IDs/object snapshots would be the next step for stronger temporal consistency.

Inventory storage remains O(number of entries) in memory. Before making million-object capacity claims, benchmark peak memory, cancellation latency, export time, and viewport latency. A persistent inventory with resumable checkpoints and bounded query windows is the next substantial scalability improvement; it requires format/migration and crash-recovery design.

## Reference material used

- [rclone 1.75.1 release](https://github.com/rclone/rclone/releases/tag/v1.75.1) and its official SHA256SUMS.
- [rclone Drive](https://rclone.org/drive/), [OneDrive](https://rclone.org/onedrive/), and [Google Photos](https://rclone.org/googlephotos/) provider requirements.
- [SQLite Online Backup API](https://www.sqlite.org/backup.html) for consistent snapshots, including WAL state.
- [OAuth native-app recommendations](https://www.rfc-editor.org/rfc/rfc8252) and [PKCE](https://www.rfc-editor.org/rfc/rfc7636).
- [GitHub artifact attestations](https://docs.github.com/en/actions/how-tos/secure-your-work/use-artifact-attestations/use-artifact-attestations).

The automated suite is the executable acceptance specification. This record does not substitute for inspecting the manifest, source permissions, or physical test environment.
