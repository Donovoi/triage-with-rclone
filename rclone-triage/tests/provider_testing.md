# Provider Testing Strategy

## Overview

This document outlines the testing strategy for cloud providers in rclone-triage.
The goal is to ensure reliable authentication, file listing, and download for all
supported providers, with a clear process for adding new providers.

## Current Providers (v0.1.0)

| Provider     | rclone type   | Auth Method        | Hash Types        |
| ------------ | ------------- | ------------------ | ----------------- |
| Google Drive | `drive`       | OAuth 2.0          | md5, sha1, sha256 |
| OneDrive     | `onedrive`    | OAuth 2.0          | quickxorhash      |
| Dropbox      | `dropbox`     | OAuth 2.0          | dropbox           |
| Box          | `box`         | OAuth 2.0          | sha1              |
| iCloud Drive | `iclouddrive` | Apple ID (cookies) | none              |

## Testing Levels

### Level 1: Unit Tests (Automated)

Tests that run without network or credentials:

- `CloudProvider` enum parsing and serialization
- Provider config generation
- rclone command building
- File entry parsing from mock JSON
- Hash selection logic

**Run with:** `cargo test --release -- --test-threads=1`

### Level 2: Integration Tests (Mock Server)

Tests using a mock HTTP server:

- OAuth redirect capture
- JSON response parsing
- Error handling for failed auth

**Run with:** `cargo test --release integration`

### Level 3: Sandbox Tests (Real Provider, Test Account)

Manual tests with real providers using test accounts:

```bash
# Create test config
rclone config create test-gdrive drive

# Run listing test
./target/release/rclone-triage --provider gdrive --name sandbox-test

# Verify in TUI mode
./target/release/rclone-triage --tui
```

### Level 4: Production Validation (Real Data)

Final validation before release with real user scenarios.

## Test Fixtures

### Mock lsjson Response

```json
[
  {
    "Path": "Documents",
    "Size": 0,
    "ModTime": "2024-01-01T00:00:00Z",
    "IsDir": true
  },
  {
    "Path": "Documents/report.pdf",
    "Size": 1024,
    "ModTime": "2024-01-15T10:30:00Z",
    "IsDir": false,
    "Hashes": { "MD5": "abc123" }
  },
  {
    "Path": "Photos/vacation.jpg",
    "Size": 2048,
    "ModTime": "2024-02-01T15:45:00Z",
    "IsDir": false,
    "Hashes": { "SHA1": "def456" }
  }
]
```

### Mock about Response

```json
{
  "total": 15000000000,
  "used": 5000000000,
  "free": 10000000000,
  "trashed": 100000000
}
```

## Adding a New Provider

### Step 1: Research

1. Check rclone supports it: `rclone config providers | jq '.[] | select(.Name == "newprovider")'`
2. Check auth method (OAuth, API key, username/password)
3. Check hash types: `rclone backend features newprovider --json`
4. Note any special requirements

### Step 2: Add to CloudProvider enum

```rust
// In src/providers/mod.rs
pub enum CloudProvider {
    // ... existing
    NewProvider,
}

impl CloudProvider {
    pub fn rclone_type(&self) -> &'static str {
        match self {
            // ...
            CloudProvider::NewProvider => "newprovider",
        }
    }
    // Update all match arms
}
```

### Step 3: Add Provider Config

```rust
// In src/providers/config.rs
fn for_provider(provider: CloudProvider) -> ProviderConfig {
    match provider {
        CloudProvider::NewProvider => ProviderConfig {
            rclone_type: "newprovider",
            // ...
        },
    }
}
```

### Step 4: Test

1. Run unit tests: `cargo test cloudprovider`
2. Run integration tests: `cargo test integration`
3. Manual sandbox test: `./target/release/rclone-triage --provider newprovider`

### Step 5: Document

Update README.md with provider-specific notes if any.

## Provider-Specific Notes

### Google Drive

- Requires OAuth scope selection (full access vs read-only)
- Supports team drives (shared drives)
- Has file versioning

### OneDrive

- Microsoft account vs work/school account
- Different auth URLs for personal vs business
- Supports SharePoint sites

### Dropbox

- Uses content hash (dropbox hash algorithm)
- Supports team folders
- Has paper documents (special handling)

### Box

- Enterprise vs personal accounts
- Supports webhooks for real-time sync
- Has metadata templates

### iCloud Drive

- No OAuth - uses Apple ID cookies
- Requires 2FA handling
- Limited API compared to others

## Automated CI Testing

```yaml
# .github/workflows/test.yml
name: Tests
on: [push, pull_request]
jobs:
  test:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: dtolnay/rust-toolchain@stable
      - run: cargo test --release -- --test-threads=1
```

## Manual Test Checklist

For each provider release:

- [ ] OAuth flow completes successfully
- [ ] File listing returns correct entries
- [ ] File download preserves content
- [ ] Hash verification passes
- [ ] Large file (>100MB) downloads correctly
- [ ] Unicode filenames handled correctly
- [ ] Empty directories listed
- [ ] Error messages are informative
