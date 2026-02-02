# rclone-triage Implementation Roadmap

## Overview

This roadmap wires up existing unused code and adds missing features.
Each phase has verification steps to ensure quality.

## Current State (2026-02-02)

- ✅ 118 tests passing (100 unit + 18 integration)
- ✅ Windows cross-compilation working (60MB exe)
- ✅ Basic TUI flow: auth → list → download
- ✅ Case management wired (directories, state tracking)
- ✅ Forensic logging active (hash-chained)
- ✅ System state snapshots (before/after diff)
- ✅ Change tracker wired to TUI
- ✅ Report generation with forensic data
- ✅ SSO/Silent authentication (reuse browser sessions)

---

## Phase 1: Wire Case Management (Priority: HIGH)

**Goal:** Session creates proper directory structure and tracks state.

### Step 1.1: Wire CaseDirectories to TUI

**Files:** `src/ui/runner.rs`, `src/case/directory.rs`

**Tasks:**

1. After CaseSetup screen, call `create_case_directories()`
2. Store `CaseDirectories` in `App` struct
3. Use `directories.downloads` for file downloads
4. Use `directories.config` for rclone config

**Verification:**

```bash
cargo test case::directory
./target/release/rclone-triage --tui
# After entering session name, check directory created
ls -la ./test-session/
# Should see: logs/, downloads/, listings/, config/
```

### Step 1.2: Wire Case State Tracking

**Files:** `src/ui/runner.rs`, `src/case/mod.rs`

**Tasks:**

1. Call `case.add_provider()` after successful auth
2. Call `case.add_download()` for each downloaded file
3. Call `case.finalize()` before Complete screen

**Verification:**

```bash
cargo test case::tests
# Manual: complete full TUI flow, verify case state populated
```

---

## Phase 2: Wire Forensic Logging (Priority: HIGH)

**Goal:** All actions logged with hash-chained integrity.

### Step 2.1: Initialize ForensicLogger

**Files:** `src/main.rs`, `src/ui/runner.rs`, `src/forensics/logger.rs`

**Tasks:**

1. Create logger in `main.rs` after case setup
2. Pass logger to TUI or store globally
3. Log: session start, provider auth, file listing, downloads

**Verification:**

```bash
cargo test forensics::logger
# Manual: run TUI, check logs/rclone-triage.log
cat ./test-session/logs/rclone-triage.log
# Verify hash chain: each line has prev_hash
```

### Step 2.2: Wire System State Snapshots

**Files:** `src/main.rs`, `src/forensics/state.rs`

**Tasks:**

1. Capture initial state before any operations
2. Capture final state before exit
3. Compute diff for forensic report

**Verification:**

```bash
cargo test forensics::state
# Manual: verify state captured (temp files, env vars)
```

### Step 2.3: Wire Change Tracker

**Files:** `src/ui/runner.rs`, `src/forensics/changes.rs`

**Tasks:**

1. Track each file created (rclone.exe, config, downloads)
2. Track env vars modified
3. Include in forensic report

**Verification:**

```bash
cargo test forensics::changes
```

---

## Phase 3: Wire Report Generation (Priority: HIGH)

**Goal:** Generate forensic report at session end.

### Step 3.1: Wire Report Writer

**Files:** `src/ui/runner.rs`, `src/case/report.rs`

**Tasks:**

1. After downloads complete, call `generate_report()`
2. Write to `directories.report` path
3. Display summary in Complete screen

**Verification:**

```bash
cargo test case::report
# Manual: complete TUI flow
cat ./test-session/forensic_report.txt
# Verify: header, file list, hashes, timestamps
```

---

## Phase 4: Wire CSV Export (Priority: MEDIUM)

**Goal:** Export file listings to CSV for analysis.

### Step 4.1: Wire export_listing

**Files:** `src/ui/runner.rs`, `src/files/export.rs`

**Tasks:**

1. After file listing, call `export_listing()`
2. Write to `directories.listings/{provider}_files.csv`
3. Include in forensic report

**Verification:**

```bash
cargo test files::export
# Manual: check CSV created
cat ./test-session/listings/gdrive_files.csv
# Verify: headers, UTF-8 BOM, all files listed
```

---

## Phase 5: SSO/Silent Authentication (Priority: HIGH) ✅ COMPLETE

**Goal:** Detect and reuse existing browser sessions for faster re-authentication.

### Step 5.1: Detect Browser Sessions

**Files:** `src/providers/auth.rs`, `src/providers/session.rs`

**Tasks:**

1. Add `SsoStatus` struct to track browser sessions per provider
2. Add `detect_sso_sessions()` to find browsers with valid sessions
3. Add `get_sso_summary()` for TUI display

**Verification:**

```bash
cargo test providers::auth::tests::test_sso_status
# Manual: check SSO detection for logged-in browser
```

### Step 5.2: Smart Authentication

**Files:** `src/providers/auth.rs`

**Tasks:**

1. Add `authenticate_with_sso()` for silent auth via existing session
2. Add `smart_authenticate()` that tries SSO first, falls back to interactive
3. Add `was_silent` flag to `AuthResult` to track auth type

**Verification:**

```bash
cargo test providers::auth
# Manual: login to Google in browser, then run TUI - should detect session
```

### Step 5.3: Wire to TUI

**Files:** `src/ui/mod.rs`, `src/ui/runner.rs`

**Tasks:**

1. Add `sso_status` field to App struct
2. Add `update_sso_status()`, `sso_summary()`, `has_sso_available()` methods
3. Use `smart_authenticate()` in auth flow
4. Display SSO status before authentication

**Verification:**

```bash
cargo test --release -- --test-threads=1
# All 118 tests pass
```

---

## Phase 6: Improve Download Flow (Priority: MEDIUM)

**Goal:** Better progress tracking and hash verification.

### Step 6.1: Wire DownloadQueue

**Files:** `src/ui/runner.rs`, `src/files/download.rs`

**Tasks:**

1. Replace simple loop with `DownloadQueue`
2. Add progress callback to update TUI
3. Verify hashes after download

**Verification:**

```bash
cargo test files::download
# Manual: download files, verify hashes match listing
```

---

## Phase 7: Custom OAuth (Priority: LOW)

**Goal:** Support custom OAuth credentials to avoid rate limits.

### Step 7.1: Wire ProviderConfig OAuth

**Files:** `src/providers/config.rs`, `src/providers/auth.rs`

**Tasks:**

1. Load custom client_id/secret from config
2. Pass to rclone config create command
3. Support config file for credentials

**Verification:**

```bash
cargo test providers::config
# Manual: test with custom OAuth credentials
```

---

## Phase 8: Enhanced Cleanup (Priority: MEDIUM)

**Goal:** Ensure all temp files removed, document what can't be reverted.

### Step 8.1: Wire Full Cleanup

**Files:** `src/cleanup.rs`, `src/main.rs`

**Tasks:**

1. Track all temp files created
2. Track env vars modified
3. Execute cleanup on exit (normal or Ctrl+C)
4. Document unrevertable changes in report

**Verification:**

```bash
cargo test cleanup
# Manual: run TUI, exit, verify no temp files remain
ls /tmp/rclone*  # Should be empty
```

---

## Phase 9: Testing Infrastructure (Priority: HIGH)

**Goal:** Automated testing for all workflows.

### Step 9.1: Integration Tests

**Files:** `tests/integration.rs`

**Tasks:**

1. Test full flow with mock rclone
2. Test each provider type
3. Test error handling

**Verification:**

```bash
cargo test --release -- --test-threads=1
# All tests pass, no regressions
```

### Step 8.2: CI Pipeline

**Files:** `.github/workflows/ci.yml`

**Tasks:**

1. Run tests on push/PR
2. Build Linux and Windows
3. Run clippy lints

---

## Verification Checklist Per Phase

Before marking a phase complete:

- [ ] All related unit tests pass
- [ ] Manual TUI test works as expected
- [ ] No new compiler warnings introduced
- [ ] Code follows existing patterns
- [ ] Functions have doc comments

---

## Definition of Done

A feature is complete when:

1. **Tests pass:** `cargo test --release -- --test-threads=1`
2. **Builds clean:** `cargo build --release 2>&1 | grep -c warning` decreases
3. **TUI works:** Manual walkthrough works
4. **Cross-compile:** `cargo build --release --target x86_64-pc-windows-gnu`

---

## Command Reference

```bash
# Test
cargo test --release -- --test-threads=1

# Build Linux
cargo build --release

# Build Windows
cargo build --release --target x86_64-pc-windows-gnu

# Run TUI
./target/release/rclone-triage --tui

# Check warnings
cargo build --release 2>&1 | grep warning | wc -l

# Run specific test
cargo test case::directory --release
```

---

## Progress Tracking

| Phase                | Status      | Tests | Warnings |
| -------------------- | ----------- | ----- | -------- |
| 1. Case Management   | ✅ Complete | 118   | 10       |
| 2. Forensic Logging  | ✅ Complete | 118   | 10       |
| 3. Report Generation | ✅ Complete | 118   | 10       |
| 4. CSV Export        | ✅ Complete | 118   | 10       |
| 5. SSO/Silent Auth   | ✅ Complete | 118   | 10       |
| 6. Download Flow     | Not Started | -     | -        |
| 7. Custom OAuth      | Not Started | -     | -        |
| 8. Cleanup           | Not Started | -     | -        |
| 9. Testing           | Not Started | -     | -        |

---

## Notes

- Do NOT add features not in this plan without discussion
- Do NOT refactor existing working code unless necessary
- Each phase should take 1-2 focused sessions
- Commit after each phase passes verification
