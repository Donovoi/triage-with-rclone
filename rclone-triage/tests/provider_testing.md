# Provider testing

## Coverage enforced in CI

The pinned runtime supplies the complete backend catalog. The curated provider enum and `CloudProvider::all()` are generated together; adding a variant also requires an exhaustive, independently asserted schema contract in `tests/provider_matrix.rs`.

Every Windows and Linux CI run checks:

- Contracts for all 58 curated providers: backend identity, required options, authentication classification, OAuth parameters, configuration and hashes.
- The verified native rclone executable's actual `config providers` output: currently 69 schemas and 61 selectable backends. Eight wrapper backends are intentionally excluded. Newly discovered backends use manual configuration until their authentication route is explicitly supported.
- Local synthetic login protocols, credential parsing, callback state validation, PKCE and token exchange. All nine generic OAuth routes use the actual callback and exchange code against local fixtures. Drive/OneDrive auth-only tests also verify persistence and failure rollback. These tests do not establish vendor acceptance of a login or refresh grant.
- Existing integration tests for inventory parsing, queues, downloads, reporting, config isolation and integrity checks, plus updater regression tests.

Run the normal suite with `cargo test --locked --release -- --test-threads=1` from the crate directory. For the metadata-only runtime check, bootstrap the native runtime and set `RCLONE_PROVIDER_SCHEMA_BINARY` to its absolute path, then run:

```powershell
$env:RCLONE_PROVIDER_SCHEMA_BINARY = (Resolve-Path ./assets/rclone.exe).Path
cargo test --locked --release --test provider_matrix pinned_rclone_catalog_matches_provider_contracts -- --ignored --exact --test-threads=1
```

The runtime's SHA256 is checked before execution, its version must match the build, and discovery uses an empty isolated config. Linux CI prepares its native binary using `scripts/download-rclone.sh --linux <absolute-output-path>`.

## Authentication boundaries

Generic OAuth coverage applies to Drive, OneDrive, Dropbox, Box, Google Photos, HiDrive, Premiumize, Putio and Yandex. Mailru, PikPak, SugarSync, Jottacloud and ShareFile require provider-specific protocols. pCloud additionally needs its regional hostname, while Zoho requires region, token-type and root configuration. These seven providers use manual setup or import of a complete rclone config, instead of the application's generic OAuth exchange. Unknown discovered providers also use manual setup.

Device-code authorization is exposed for OneDrive only. Google's limited-input device flow does not support the read-only Drive/Photos scopes this application needs; use browser authorization with an appropriate client registration. See the [Google scope restrictions](https://developers.google.com/identity/protocols/oauth2/limited-input-device#allowedscopes).

Malformed or ambiguous custom OAuth JSON fails closed. Custom secrets are passed to child rclone processes through their environment, not command arguments. Test configurations, tokens, account identities and raw service responses must stay outside the repository and public CI artifacts.

## Explicit live access checks

`tests/provider_smoke.rs` is ignored by default. It requires an explicit config and an absolute, hash-verified native rclone path. It reads only remotes whose names begin with the exact prefix `Test`; every selected backend must exist in the discovered catalog. Duplicate or case-aliased Test names fail. No default credential store is used.

The test performs `listremotes` and one shallow `lsjson --max-depth 1 --hash` per selected remote. It issues no remote write commands. Use dedicated synthetic folders and a disposable private copy of the config, because rclone may refresh tokens in that copy. Scope the remote before running: an unrestricted remote would list the account root. A successful listing verifies existing-credential read access only; it does not prove a new login, a refresh grant, downloads or remote-source preservation.

```powershell
$env:RCLONE_PROVIDER_SMOKE_CONFIG = 'C:/PrivateTests/working-rclone.conf'
$env:RCLONE_PROVIDER_SMOKE_RCLONE = (Resolve-Path ./assets/rclone.exe).Path
$env:RCLONE_PROVIDER_SMOKE_BACKENDS = 'drive,onedrive'
$env:RCLONE_PROVIDER_SMOKE_REPORT = 'C:/PrivateTests/provider-coverage-new.json'
cargo test --locked --release --test provider_smoke test_configured_provider_remotes_smoke -- --ignored --exact --nocapture --test-threads=1
```

Optional controls:

| Variable | Behavior |
|---|---|
| `RCLONE_PROVIDER_SMOKE_BACKENDS` | Comma-separated backend IDs, curated short names or Test remote names. Blank selects all Test remotes. Every requested item must match; typos, partially met filters and comma-only filters fail. |
| `RCLONE_PROVIDER_SMOKE_REQUIRE_ALL` | `true` or `1` requires a selected account for every discovered backend. `false`, `0` or unset permits partial coverage. Other values fail. |
| `RCLONE_PROVIDER_SMOKE_REPORT` | A new JSON output path; existing files are never overwritten. |
| `RCLONE_PROVIDER_SMOKE_REPORT_ONLY` | `true` or `1` produces the complete missing-coverage inventory without reading any account config. It makes no live-access claim. Combined with `REQUIRE_ALL`, it writes the inventory and then fails because full live coverage was not run. |

Every discovered backend gets a row: `not_configured`, `not_requested`, `not_run`, `passed` or `failed`. One successful account cannot hide another account's failure. The report contains backend IDs, authentication categories, counts and statuses; it omits remote names, account identities, filenames, credentials and raw provider errors. `fresh_login_verified` and `refresh_grant_verified` remain false in this harness. `all_discovered_providers_passed` becomes true only when every row passed and there were no errors.

## Scheduled checks

`.github/workflows/provider-smoke.yml` runs nightly and on manual dispatch. It always checks offline contracts, login regressions and the actual runtime catalog. Without test credentials it publishes the full `not_configured` inventory and explicitly states that live access did not run. The sanitized JSON is retained for 14 days. Missing prerequisites are reported as unavailable coverage, never as a live pass.

To opt in to cloud access on GitHub-hosted runners, provision a dedicated synthetic-test config through the repository secret `RCLONE_PROVIDER_SMOKE_CONFIG`. Keep the source credentials in the operator's vault; do not commit them. The workflow creates a private temporary config and removes it after the run. Refreshed tokens in that temporary copy are not exported or written back to the secret; providers that rotate refresh tokens may require deliberate credential renewal.

Scheduled runs use repository variables `RCLONE_PROVIDER_SMOKE_BACKENDS` and `RCLONE_PROVIDER_SMOKE_REQUIRE_ALL`. Manual inputs override those defaults, including explicit false or an empty filter. `require_all` fails when credentials are absent or any backend lacks selected coverage. Pull-request CI never requires cloud secrets.

## Restrict a OneDrive personal acceptance case to its synthetic folder

For the pinned rclone 1.75.1 runtime, retain the verified drive ID and raw folder item ID separately in private test approvals, then set the working configuration's `root_folder_id` to `<drive-id>#<folder-item-id>`. A raw item ID alone can make top-level file metadata lookup fall back to the drive root, even when nested files work. This follows the pinned backend's [path resolution](https://github.com/rclone/rclone/blob/v1.75.1/backend/onedrive/onedrive.go#L2951-L3027) and [item ID normalization](https://github.com/rclone/rclone/blob/v1.75.1/backend/onedrive/api/types.go#L436-L442). Verify the exact approved drive/folder pair; reject aliases, mismatched prefixes and extra separators. Preserve the original authenticated configuration.

Set `delta = false`: [OneDrive delta listing](https://rclone.org/onedrive/#onedrive-delta) traverses from the drive root even for a subfolder request. Start with one known synthetic file directly under the configured folder, then verify both root and nested file acquisitions against independent expected hashes. Do not treat a successful nested-file download as proof that the root is configured correctly. Folder selection controls these test requests; the OAuth grant remains account-wide.

## New providers and release acceptance

For a curated provider, update metadata, its independent schema contract, configuration and authentication tests. A new backend appearing in rclone automatically enters discovery and the live coverage report; it does not automatically acquire a tested login implementation or credentials.

For each real account type, separately verify browser/MFA login, listing, sample acquisition and independent hashes, refresh, denial/cancellation and cleanup. Enterprise variants, Shared Drives and Google Photos restrictions need their own cases. Record the exact tested binary, scope and outcome without account information. See [HARDENING.md](../../HARDENING.md) for completed live acceptance and outstanding gaps. Synthetic tests and schema checks do not replace those account-level results.
