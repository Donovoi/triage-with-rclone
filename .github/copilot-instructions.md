# Project Guidelines — rclone-triage

Forensic cloud triage tool wrapping rclone. Rust TUI (ratatui/crossterm) that produces a single statically-linked Windows executable with rclone.exe embedded via `rust-embed`.

## Build and Test

All commands run from `rclone-triage/`.

```bash
cargo build --release          # ~60 MB exe, LTO + strip enabled
cargo test -- --test-threads=1 # REQUIRED: tests mutate RCLONE_CONFIG env var
cargo clippy                   # CI enforces warnings-as-errors
```

- **213 tests** (178 unit + 8 bin + 9 integration + 18 provider_integration)
- CI runs on Linux + Windows cross-compile — see [.github/workflows/ci.yml](../.github/workflows/ci.yml)
- Windows cross-compile uses `x86_64-pc-windows-gnu` with static CRT linking (see `.cargo/config.toml`)

## Architecture

### Module Map

| Module       | Purpose                                                                                     |
| ------------ | ------------------------------------------------------------------------------------------- |
| `ui/`        | TUI state machine — `AppState` enum drives screens, `runner.rs` is the event loop           |
| `providers/` | Cloud provider definitions, OAuth config, auth flows (device code, browser, mobile)         |
| `rclone/`    | rclone process spawning, config management, OAuth redirect capture, mount                   |
| `files/`     | File listing (lsjson), download queue with hash verification, CSV/XLSX export               |
| `forensics/` | Hash-chained logger, system state snapshots, change tracking, WiFi AP, OneDrive vault       |
| `case/`      | Case directory structure (`logs/`, `downloads/`, `config/`, `listings/`), report generation |
| `embedded/`  | rclone.exe extraction from binary, SHA256 verification at runtime                           |
| `utils/`     | Path sanitization, HTTP helpers, time/formatting, Windows API wrappers                      |

### TUI State Flow

```
MainMenu → ProviderSelect → BrowserSelect → Authenticating
  → PostAuthChoice → FileList → Downloading → Complete → Cleanup
```

`ui/mod.rs` holds the monolithic `App` struct (~40 fields). `ui/runner.rs` (2459 lines) contains the event loop with business logic mixed in — a known issue tracked for refactoring.

### Supported Providers

`CloudProvider` enum covers all ~60 rclone providers including: GoogleDrive, OneDrive, Dropbox, Box, ICloud, GooglePhotos, PCloud, AzureBlob, AzureFiles, B2, S3, Mega, Sftp, WebDav, and more. Each has config in `providers/config.rs`; OAuth-capable providers have full OAuth config, others use `no_oauth()` for key-based/manual auth.

## Conventions

### Error Handling

- Use `anyhow::Result<T>` — not custom error types
- Add context: `.with_context(|| format!("Failed to {action}"))`
- Bail on unrecoverable: `bail!("message")`
- Non-fatal errors: `.ok()` to discard

### Naming

- Types: `PascalCase` (`RcloneConfig`, `OAuthFlow`)
- Functions: `snake_case` (`list_path`, `authenticate_with_device_code`)
- Modules: `snake_case` filenames

### Logging

- Use `tracing` macros: `tracing::info!()`, `tracing::warn!()`, `tracing::debug!()`
- Minimal logging — primarily in auth flows and error paths

### Testing

- Unit tests at bottom of each file in `#[cfg(test)]` module
- Mock data as inline JSON via `serde_json::from_str`
- Unix-only mock processes via shell scripts (see `tests/integration.rs`)
- Simple assertions: `assert_eq!`, `assert!`, `.unwrap()` for expected-success paths

### Forensic Integrity

- Hash-chained logs: `SHA256(prev_hash || timestamp || event)` — format: `{timestamp}|{hash[0:16]}|{prev_hash[0:16]}|{event}`
- System state: before/after snapshots with diff tracking
- Cleanup struct tracks temp files/dirs/env vars; unrevertable changes documented in final report

## Security Notes

- OAuth error pages in `rclone/oauth.rs` need XSS mitigation
- Config files should be `chmod 600` — currently stored plaintext
- JWT signature and CSRF state parameter validation are incomplete
- Never log tokens or credentials — use `tracing` field redaction if needed

## Key Files

- [Cargo.toml](../rclone-triage/Cargo.toml) — dependencies, release profile
- [build.rs](../rclone-triage/build.rs) — Windows PE manifest, DPI-aware, version info
- [scripts/collect-logs.sh](../scripts/collect-logs.sh) — bundles logs (secrets redacted) for troubleshooting
- [IMPLEMENTATION_ROADMAP.md](../rclone-triage/IMPLEMENTATION_ROADMAP.md) — 4-phase completion plan
- [POWERSHELL_COVERAGE.md](../rclone-triage/POWERSHELL_COVERAGE.md) — Rust vs PowerShell parity (~55%)
