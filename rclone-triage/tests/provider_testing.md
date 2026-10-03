# Provider testing

## Coverage enforced in CI

The pinned runtime supplies the complete backend catalog. The curated provider enum and `CloudProvider::all()` are generated together; adding a variant also requires an exhaustive, independently asserted schema contract in `tests/provider_matrix.rs`.

Every Windows and Linux CI run checks:

- Contracts for all 58 curated providers: backend identity, required options, authentication classification, OAuth parameters, configuration and hashes.
- The verified native rclone executable's actual `config providers` output: currently 69 schemas and 61 selectable backends. Eight wrapper backends are intentionally excluded. Newly discovered backends use manual configuration until their authentication route is explicitly supported.
- Local synthetic login protocols, credential parsing, callback state validation, PKCE and token exchange. All nine generic OAuth routes use the actual callback and exchange code against local fixtures. Drive/OneDrive auth-only tests also verify persistence and failure rollback. These tests do not establish vendor acceptance of a login or refresh grant.
- Existing integration tests for inventory parsing, queues, downloads, reporting, config isolation and integrity checks, plus updater regression tests.
- Eight real-backend protocol fixtures and a current-runtime coverage plan for every selectable backend. New backends, removed backends and changed option contracts require an explicit policy review.

Run the normal suite with `cargo test --locked --release -- --test-threads=1` from the crate directory. For the metadata-only runtime check, bootstrap the native runtime and set `RCLONE_PROVIDER_SCHEMA_BINARY` to its absolute path, then run:

```powershell
$env:RCLONE_PROVIDER_SCHEMA_BINARY = (Resolve-Path ./assets/rclone.exe).Path
cargo test --locked --release --test provider_matrix pinned_rclone_catalog_matches_provider_contracts -- --ignored --exact --test-threads=1
```

The runtime's SHA256 is checked before execution, its version must match the build, and discovery uses an empty isolated config. Linux CI prepares its native binary using `scripts/download-rclone.sh --linux <absolute-output-path>`.

## Layered provider evidence

`provider-coverage-policy.json` records the reviewed baseline plan and option-contract hash for each selectable backend. It is a plan, not a table of successful logins. The default baseline does not cover every enterprise account type, deployment, authentication mode, region or backend option. Add distinct acceptance cases before broadening those claims. Eight non-selectable wrapper backends remain outside this catalog.

The contract hash covers canonical name/prefix and option names, generated types, provider selectors, required/password/advanced/exclusive flags. A type-only change (such as string to Boolean or duration) therefore requires review. Help text, examples and defaults are excluded because they can include platform-specific paths. Explicit platform hashes cover reviewed structural differences: the pinned local backend marks `nounc` advanced on Linux but ordinary on Windows. An unreviewed platform cannot inherit another platform's hash. A runtime change still invalidates fixture receipts through the executable hash; a matching plan hash does not establish unchanged service behavior or permissions.

Each plan must include its authentication category, renewal applicability, structured authentication/renewal modes with lifecycle scenarios, primary-source links, and an application evidence tier. The validator checks these fields against the profile's required capabilities and unresolved reviews. Deleting the supporting metadata, assigning inconsistent renewal decisions, or dropping the application tier cannot make a plan pass.

`scripts/provider_coverage.py` queries the verified native runtime with an empty private config and produces these separate layers:

| Layer | Evidence needed |
|---|---|
| `local_protocol` | Real rclone against a synthetic local filesystem or loopback service, including independent download hashes and applicable negative cases. |
| `application` | The actual application build, its setup/login path, inventory, acquisition and manifest, source preservation, cancellation and cleanup. |
| `vendor` | An approved synthetic dataset on the actual hosted service, fresh authentication where applicable, downloads, source before/after checks, denial/revocation and applicable renewal. |

Local-protocol and vendor layers may be N/A only through the reviewed policy; application acceptance is always required. Providers without a login (for example local storage and public DOI sources) do not need invented account credentials. Unknown renewal applicability appears as `capability_applicability_review_required` and prevents complete qualification. A reviewed plan may retain this explicit research task while its application/vendor evidence remains unverified.

Policy version 2 separates `refresh` (replacement credentials or service authorization, including OAuth grants, library authorization and SDK credential reacquisition) from `reauthentication` (authentication of a newly established connection/session). For example, B2 exchanges a static application key for a temporary authorization token; FTP authenticates each new connection using configured credentials. The source-backed `renewal_modes` record both requirements separately. Unknown applicability in either dimension prevents complete qualification. These records are research findings, not executed results. Credentials without automatic renewal still need expiry/revocation denial and explicit recovery checks. Never infer N/A solely from an API-key or password field.

HDFS and SMB Kerberos modes require service-ticket renewal/reacquisition tests as well as connection authentication tests. Their external ticket-granting-ticket limitations do not waive the pinned client's service-ticket renewal path; valid-TGT recovery and expired-TGT failure/recovery are separate cases.

The current importer accepts **protocol fixture receipts only**. Application and vendor layers stay `not_verified`; saved-config smoke output and historical acceptance notes cannot promote them. Adding an importer for those layers requires build/runtime identity, account-variant scope, fixture identity, actual auth/renewal/cancellation evidence and privacy review. The current protocol receipts are harness reports, not signed third-party attestations. Consume only receipts from a trusted local run or the checked CI job.

Fixture receipts bind to runtime version and executable SHA256, operating system, harness SHA256, fixture manifest and UTC execution time. The default maximum age is 24 hours (explicitly configurable from 1 to 168). Future, expired, mismatched or malformed receipts are rejected; an observed failure cannot be hidden by another successful receipt in the same batch. Reports are create-new and contain no account names, remote names, endpoints, file paths, credentials or raw provider diagnostics.

Run the account-free lab and ledger with Python 3.11 or newer, from the repository root:

```powershell
$runtime = (Resolve-Path ./rclone-triage/assets/rclone.exe).Path
$fixtures = Join-Path $env:TEMP ('provider-fixtures-' + [guid]::NewGuid() + '.json')
$evidence = Join-Path $env:TEMP ('provider-evidence-' + [guid]::NewGuid() + '.json')
python -B scripts/provider-lab/run_lab.py --rclone $runtime --report $fixtures
if ($LASTEXITCODE -ne 0) { throw 'Protocol fixtures failed; inspect the sanitized receipt' }
python -B scripts/provider_coverage.py --rclone $runtime --report $evidence `
  --fixture-receipt $fixtures --require-plans --require-fixtures local,archive,http,webdav,ftp,sftp,s3,swift
```

`--require-plans` fails for missing, unreviewed, changed or retired backend plans. `--require-fixtures` requires current passing local-protocol evidence for each supplied backend ID. `--require-complete` requires every applicable layer and all applicability reviews; it is expected to fail while acceptance work remains. The report is written before a gate failure is returned. Do not replace this strict gate with a count of discovered providers or selected accounts.

The lab runs only the pinned native rclone, never the triage application. It uses fresh temporary config, home, cache and synthetic credentials; inherited cloud/proxy/SSH settings are excluded. All network listeners bind to `127.0.0.1` and ephemeral ports. It stops only its owned children and removes its temporary fixtures. HTTP, WebDAV, FTP and Swift use independent Python fixture servers; FTP active connections are disabled and passive listeners also bind loopback. SFTP and S3 use rclone's own read-only servers, so these are interoperability regressions between two rclone instances, not independent server conformance tests. SFTP uses the fixture's pinned host keys and no external hash commands.

All eight cases require recursive listing, independent SHA256 after downloads, missing-object rejection, source preservation and cleanup. Network cases also reject incorrect credentials. SFTP separately tests correct credentials with a mismatched known host key and requires an explicit host-key rejection with no returned bytes or accepted file. The independent HTTP/WebDAV/FTP services reject authenticated write probes and compare the bytes actually served with a snapshot captured before requests. HTTP and WebDAV additionally reject truncated transfers and terminate a stalled download before checking cleanup. That process-termination test does not prove the application's interactive cancellation behavior. Run socket-free and fixture-server unit regressions with `python -B -m unittest discover -s scripts/tests -p 'test_*.py'`.

Swift fixtures exercise v1 authentication against an independent loopback service. In a single rclone copy process, the service rejects the first token with a body-free 401, issues a different token and accepts the retried download only with that replacement. The harness requires the ordered authentication/rejection/replacement/download sequence and an independent SHA256. A separate renewal-denial case must fail without accepting an output. Wrong credentials, missing objects and authenticated writes are rejected; served bytes and the private config must remain unchanged. These tests cover small Swift v1 objects and forced authorization rejection only. They do not establish wall-clock expiry, OAuth refresh, Keystone v2/v3, application credentials, large objects, TLS, general session reauthentication or real vendor acceptance.

Archive fixtures use an exact synthetic local ZIP with deterministic entries. Inventory CRC32 values are checked independently, and explicit file-only acquisition is checked against independent SHA256 and size expectations. Missing entries, directory-as-file requests, corrupted members, truncated ZIP metadata and writes must be rejected while the original container and config remain unchanged. This covers a local ZIP upstream only; other archive formats and cloud-hosted upstreams need separate evidence. The Windows `cli_acquisition` tests also run the actual application against a separate fixed ZIP, checking CRC32 verification, SHA256, manifests and negative acquisition outcomes. Those narrow CLI regressions do not establish the complete application lifecycle or promote the ledger's application layer.

For a local ZIP upstream on Windows, use a slash-separated rclone archive setting such as `remote = C:/Synthetic/source.zip`. The pinned backend rejects backslash spelling. Acquisition preserves the configured filesystem root when checking an individual member: `operations/stat` and `operations/copyfile` both receive the root and object separately through in-process loopback RC. A missing/null item, directory, malformed stat response or failed stat cannot begin a transfer. The protocol fixtures exercise the same stat interface on all eight backends.

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

`.github/workflows/provider-smoke.yml` runs nightly and on manual dispatch. It always checks offline contracts, login regressions, actual runtime catalog, the eight protocol fixtures and current coverage plans. Without test credentials it publishes the full `not_configured` inventory and explicitly states that live access did not run. The sanitized smoke inventory, fixture receipt and evidence ledger are retained for 14 days. Missing prerequisites are reported as unavailable coverage, never as a live pass. Runs are serialized to avoid overlapping use of rotating credentials.

To opt in to cloud access on GitHub-hosted runners, provision a dedicated synthetic-test config through the repository secret `RCLONE_PROVIDER_SMOKE_CONFIG`. Keep the source credentials in the operator's vault; do not commit them. The workflow creates a private temporary config and removes it after the run. Refreshed tokens in that temporary copy are not exported or written back to the secret; providers that rotate refresh tokens may require deliberate credential renewal.

Scheduled runs use repository variables `RCLONE_PROVIDER_SMOKE_BACKENDS` and `RCLONE_PROVIDER_SMOKE_REQUIRE_ALL`. Manual inputs override those defaults, including explicit false or an empty filter. `require_all` fails when credentials are absent or any backend lacks selected coverage. Pull-request CI never requires cloud secrets.

## Restrict a OneDrive personal acceptance case to its synthetic folder

For the pinned rclone 1.75.1 runtime, retain the verified drive ID and raw folder item ID separately in private test approvals, then set the working configuration's `root_folder_id` to `<drive-id>#<folder-item-id>`. A raw item ID alone can make top-level file metadata lookup fall back to the drive root, even when nested files work. This follows the pinned backend's [path resolution](https://github.com/rclone/rclone/blob/v1.75.1/backend/onedrive/onedrive.go#L2951-L3027) and [item ID normalization](https://github.com/rclone/rclone/blob/v1.75.1/backend/onedrive/api/types.go#L436-L442). Verify the exact approved drive/folder pair; reject aliases, mismatched prefixes and extra separators. Preserve the original authenticated configuration.

Set `delta = false`: [OneDrive delta listing](https://rclone.org/onedrive/#onedrive-delta) traverses from the drive root even for a subfolder request. Start with one known synthetic file directly under the configured folder, then verify both root and nested file acquisitions against independent expected hashes. Do not treat a successful nested-file download as proof that the root is configured correctly. Folder selection controls these test requests; the OAuth grant remains account-wide.

## New providers and release acceptance

For a curated provider, update metadata, its independent schema contract, configuration and authentication tests. A new backend appearing in rclone automatically enters discovery and both coverage reports; it does not automatically acquire a tested login implementation or credentials. The current-plan gate fails until its canonical identity, option contract, auth applicability, evidence layers, renewal behavior and primary source links have a reviewed policy entry. Do not bulk-rehash policy entries just to make a runtime-update PR pass. Removed backends also require deliberate policy retirement.

Continue acceptance by the highest-impact feasible case, preserving a private checkpoint of blockers and the next action. Reuse approved accounts, store all credentials in a private vault, and keep only sanitized evidence in shared artifacts. Check current API entitlements before creating an account: free storage does not necessarily grant free API access. The pinned documentation for [1Fichier](https://rclone.org/fichier/), [Gofile](https://rclone.org/gofile/) and [Pixeldrain filesystem](https://rclone.org/pixeldrain/) describes paid prerequisites; missing paid access stays a blocker, not a pass or permission to purchase. [Memory](https://rclone.org/memory/) is process-local, so the application's separate child processes need a supported source lifecycle before this backend can qualify. A local archive baseline does not qualify a remotely hosted archive's upstream provider.

For each real account type, separately verify browser/MFA login, listing, sample acquisition and independent hashes, refresh, denial/cancellation and cleanup. Enterprise variants, Shared Drives and Google Photos restrictions need their own cases. Record the exact tested binary, scope and outcome without account information. See [HARDENING.md](../../HARDENING.md) for completed live acceptance and outstanding gaps. Synthetic tests and schema checks do not replace those account-level results.
