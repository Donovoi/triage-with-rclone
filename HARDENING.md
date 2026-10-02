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
