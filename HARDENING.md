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

## Acceptance still required

Offline tests and local aliases do not prove live cloud compatibility. Run configured Test remotes using the explicit smoke workflow, then verify auth, listing, sample download, token refresh, and cleanup on each supported provider. AP hardware, real browser encryption, and vault accessibility need dedicated Windows lab acceptance. Abrupt process/OS termination is not equivalent to graceful cleanup; retain manifests and inspect partial files after interruption.

The acquisition plan protects against observed path/collision mistakes and existing symlinks/reparse points. It is not a filesystem sandbox against a privileged process concurrently replacing destination components. Use an access-controlled output directory. Providers may mutate objects during acquisition; source version IDs/object snapshots would be the next step for stronger temporal consistency.

Inventory storage remains O(number of entries) in memory. Before making million-object capacity claims, benchmark peak memory, cancellation latency, export time, and viewport latency. A persistent inventory with resumable checkpoints and bounded query windows is the next substantial scalability improvement; it requires format/migration and crash-recovery design.

## Reference material used

- [rclone 1.75.1 release](https://github.com/rclone/rclone/releases/tag/v1.75.1) and its official SHA256SUMS.
- [rclone Drive](https://rclone.org/drive/), [OneDrive](https://rclone.org/onedrive/), and [Google Photos](https://rclone.org/googlephotos/) provider requirements.
- [SQLite Online Backup API](https://www.sqlite.org/backup.html) for consistent snapshots, including WAL state.
- [OAuth native-app recommendations](https://www.rfc-editor.org/rfc/rfc8252) and [PKCE](https://www.rfc-editor.org/rfc/rfc7636).
- [GitHub artifact attestations](https://docs.github.com/en/actions/how-tos/secure-your-work/use-artifact-attestations/use-artifact-attestations).

The automated suite is the executable acceptance specification. This record does not substitute for inspecting the manifest, source permissions, or physical test environment.
