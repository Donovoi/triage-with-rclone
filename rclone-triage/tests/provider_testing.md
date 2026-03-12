# Provider Testing Strategy

## Overview

`rclone-triage` should follow the same broad pattern as upstream rclone:

- keep **always-on contract tests** for every provider known to the program
- run **mock and emulator-backed integration tests** in normal CI
- run **credentialed smoke tests** only for explicitly configured test remotes
- reserve **manual/release validation** for the providers with the hardest auth flows

The source of truth for supported providers is `src/providers/mod.rs` via
`CloudProvider::all()`, not this document.

## Testing Layers

### 1. Provider contract tests (always on)

These tests run without credentials or network access and should cover **every**
provider in `CloudProvider::all()`.

Current coverage lives in:

- `tests/provider_matrix.rs`
- `src/providers/mod.rs` unit tests
- `src/providers/config.rs` unit tests

These checks validate things like:

- unique `rclone_type`, `short_name`, and display names
- default auth classification (`OAuth`, `KeyBased`, `UserPass`)
- OAuth config completeness for OAuth-capable backends
- hash type normalization and uniqueness
- `ProviderEntry::from_known(...)` consistency

This layer is the minimum safety net for every pull request.

### 2. Mock integration tests (always on)

These tests exercise the app’s rclone wrapper logic with a fake rclone binary.

Current coverage lives in:

- `tests/integration.rs`
- `tests/provider_integration.rs`

These validate:

- `lsjson` parsing
- download queue behavior
- report generation
- connectivity checks
- config handling
- hash verification workflows

This layer ensures the wrapper logic works even when a real cloud account is not available.

### 3. Live provider smoke tests (opt-in)

These are lightweight, read-only tests against **explicitly named test remotes**.

Current coverage lives in:

- `tests/provider_smoke.rs`

The live smoke test intentionally only uses remotes that:

- exist in the chosen rclone config
- have names starting with `Test`
- use a backend type that maps to a known `CloudProvider`

This mirrors rclone’s upstream convention of `TestDrive`, `TestOneDrive`, etc.

The smoke test performs:

- `rclone listremotes`
- shallow connectivity (`lsjson --max-depth 1`)
- shallow top-level `lsjson`
- `--hash` on providers that advertise hash support

It does **not** create, modify, or delete remote data.

### 4. Release validation (manual)

Some providers still need manual or semi-manual verification before release,
especially when they depend on:

- MFA or interactive browser flows
- cookies or session reuse
- enterprise-only account variants
- brittle/rate-limited vendor APIs

Examples include iCloud, Google Photos, OneDrive Business variants, and any provider
whose upstream rclone backend needs provider-specific ignores or workarounds.

## How the live smoke test is configured

`tests/provider_smoke.rs` resolves configuration in this order:

1. `RCLONE_PROVIDER_SMOKE_CONFIG`
2. `RCLONE_CONFIG`
3. default rclone config path (`~/.config/rclone/rclone.conf` on Linux)

Optional environment variables:

- `RCLONE_PROVIDER_SMOKE_RCLONE` — path to the rclone binary to use
- `RCLONE_PROVIDER_SMOKE_BACKENDS` — comma-separated backend filter such as `drive,s3,onedrive`

For GitHub Actions, the easiest setup is to store the full contents of an
`rclone.conf` file in a repository secret named `RCLONE_PROVIDER_SMOKE_CONFIG`.
That single secret can contain many `Test*` remotes, so you do **not** need one
workflow input per account.

Recommended naming convention for live test remotes:

- `TestDrive`
- `TestOneDrive`
- `TestDropbox`
- `TestS3`
- `TestAzureBlob`

Keep these remotes small and disposable. The smoke tests are read-only, but small remotes keep
nightly runs fast and predictable.

## Recommended CI split

### Pull requests

Run:

- provider contract tests
- all existing mock/unit/integration tests

Do **not** require real provider credentials for PR validation.

### Nightly / scheduled

Run:

- the full Rust test suite
- the live smoke test against configured `Test*` remotes

The repository workflow for this is:

- `.github/workflows/provider-smoke.yml`

It runs on a nightly schedule and via manual dispatch.

Optional repository variable:

- `RCLONE_PROVIDER_SMOKE_BACKENDS` — default backend filter for the workflow

Suggested nightly provider set:

- Google Drive
- OneDrive
- Dropbox
- Box
- Google Photos
- pCloud
- S3
- Backblaze B2
- Azure Blob
- Google Cloud Storage
- WebDAV
- SFTP

Expand gradually; do not try to light up every provider on day one.

### Release gate

Before release, manually validate:

- OAuth/browser auth flows still complete
- config-browser import works for representative providers
- list/download/hash verification works end-to-end
- error messages remain informative on failed auth/list operations

## Why not test every provider on every PR?

Because upstream rclone doesn’t do that either.

Real provider testing has unavoidable constraints:

- credentials and secret rotation
- rate limits
- provider-specific feature gaps
- eventual consistency
- unstable or region-specific APIs
- business/personal account differences

Upstream rclone handles this with a dedicated backend test harness, configured `Test*`
remotes, per-provider ignores, and daily integration runs. `rclone-triage` should keep
the same philosophy while focusing on the parts this application owns.

## Adding or updating a provider

When a provider is added or changed:

1. Update `CloudProvider` metadata in `src/providers/mod.rs`
2. Update `ProviderConfig` in `src/providers/config.rs`
3. Add or update contract assertions in `tests/provider_matrix.rs`
4. Add mock/integration coverage if the wrapper behavior changed
5. Add a `Test*` remote and nightly smoke coverage if the provider matters for production use
6. Update this document if the workflow changed

## Practical goal

The realistic goal is **broad automated confidence plus targeted live validation**.

That means:

- every declared provider is checked structurally
- major provider families are tested behaviorally
- live remotes are validated safely and repeatedly
- the app stays reliable without pretending we can fully emulate the entire cloud industry in CI
