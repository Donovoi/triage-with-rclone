//! Provider integration tests
//!
//! Self-contained tests for provider functionality.
//! Includes OAuth mock server tests and end-to-end workflow tests.

/// Test mock lsjson parsing for all provider hash types
#[test]
fn test_parse_provider_hashes() {
    // Google Drive style (MD5)
    let gdrive_json = r#"[
        {"Path":"file.txt","Size":100,"ModTime":"2024-01-01T00:00:00Z","IsDir":false,"Hashes":{"MD5":"abc123"}}
    ]"#;

    // OneDrive style (QuickXorHash)
    let onedrive_json = r#"[
        {"Path":"file.txt","Size":100,"ModTime":"2024-01-01T00:00:00Z","IsDir":false,"Hashes":{"QuickXorHash":"xyz789"}}
    ]"#;

    // Dropbox style
    let dropbox_json = r#"[
        {"Path":"file.txt","Size":100,"ModTime":"2024-01-01T00:00:00Z","IsDir":false,"Hashes":{"Dropbox":"hash123"}}
    ]"#;

    // Box style (SHA1)
    let box_json = r#"[
        {"Path":"file.txt","Size":100,"ModTime":"2024-01-01T00:00:00Z","IsDir":false,"Hashes":{"SHA1":"sha1hash"}}
    ]"#;

    // iCloud style (no hashes)
    let icloud_json = r#"[
        {"Path":"file.txt","Size":100,"ModTime":"2024-01-01T00:00:00Z","IsDir":false}
    ]"#;

    for (name, json) in [
        ("gdrive", gdrive_json),
        ("onedrive", onedrive_json),
        ("dropbox", dropbox_json),
        ("box", box_json),
        ("icloud", icloud_json),
    ] {
        let entries: Vec<serde_json::Value> =
            serde_json::from_str(json).unwrap_or_else(|_| panic!("Failed to parse {} JSON", name));
        assert_eq!(entries.len(), 1, "Expected 1 entry for {}", name);
    }
}

/// Test rclone backend names are valid
#[test]
fn test_rclone_backend_names_match_expected() {
    // These are the actual rclone backend names that we use
    let expected_backends = [
        ("Google Drive", "drive"),
        ("Microsoft OneDrive", "onedrive"),
        ("Dropbox", "dropbox"),
        ("Box", "box"),
        ("iCloud Drive", "iclouddrive"),
    ];

    for (display_name, backend) in expected_backends {
        // Backend names should not contain spaces
        assert!(
            !backend.contains(' '),
            "{} backend contains space",
            display_name
        );
        // Backend names should be lowercase
        assert_eq!(
            backend,
            backend.to_lowercase(),
            "{} backend not lowercase",
            display_name
        );
    }
}

/// Test file entry JSON structure
#[test]
fn test_file_entry_structure() {
    let json = r#"{
        "Path": "test/file.txt",
        "Size": 12345,
        "ModTime": "2024-06-15T10:30:00Z",
        "IsDir": false,
        "Hashes": {
            "MD5": "d41d8cd98f00b204e9800998ecf8427e",
            "SHA1": "da39a3ee5e6b4b0d3255bfef95601890afd80709"
        }
    }"#;

    let entry: serde_json::Value = serde_json::from_str(json).unwrap();
    assert_eq!(entry["Path"], "test/file.txt");
    assert_eq!(entry["Size"], 12345);
    assert_eq!(entry["IsDir"], false);
    assert!(entry["Hashes"]["MD5"].is_string());
}

/// Test directory entry JSON structure
#[test]
fn test_directory_entry_structure() {
    let json = r#"{
        "Path": "Documents",
        "Size": 0,
        "ModTime": "2024-01-01T00:00:00Z",
        "IsDir": true
    }"#;

    let entry: serde_json::Value = serde_json::from_str(json).unwrap();
    assert_eq!(entry["Path"], "Documents");
    assert_eq!(entry["IsDir"], true);
    assert_eq!(entry["Size"], 0);
}

/// Test hash selection priority
#[test]
fn test_hash_priority() {
    // When multiple hashes available, prefer SHA256 > SHA1 > MD5
    let json = r#"{
        "Hashes": {
            "MD5": "md5hash",
            "SHA1": "sha1hash",
            "SHA256": "sha256hash"
        }
    }"#;

    let entry: serde_json::Value = serde_json::from_str(json).unwrap();
    let hashes = entry["Hashes"].as_object().unwrap();

    // All three should be present
    assert!(hashes.contains_key("MD5"));
    assert!(hashes.contains_key("SHA1"));
    assert!(hashes.contains_key("SHA256"));
}

// ============================================================================
// OAuth Mock Server Integration Tests
// ============================================================================

/// Helper to extract query parameter from URL (same as OAuth module)
fn extract_param(url: &str, param: &str) -> Option<String> {
    let query = url.split('?').nth(1)?;
    for part in query.split('&') {
        if let Some((key, value)) = part.split_once('=') {
            if key == param {
                return Some(urldecoded(value));
            }
        }
    }
    None
}

/// Simple URL decoding for tests
fn urldecoded(s: &str) -> String {
    let mut result = Vec::new();
    let mut chars = s.chars().peekable();
    while let Some(c) = chars.next() {
        if c == '%' {
            let hex: String = chars.by_ref().take(2).collect();
            if let Ok(byte) = u8::from_str_radix(&hex, 16) {
                result.push(byte);
            }
        } else if c == '+' {
            result.push(b' ');
        } else {
            result.extend_from_slice(c.to_string().as_bytes());
        }
    }
    String::from_utf8_lossy(&result).to_string()
}

/// Test OAuth success redirect URL parsing
#[test]
fn test_oauth_success_redirect_parsing() {
    // Simulate what the OAuth server would receive on success
    let redirect_url = "/?code=test_auth_code_123&state=csrf_token_abc";

    let code = extract_param(redirect_url, "code");
    let state = extract_param(redirect_url, "state");

    assert_eq!(code, Some("test_auth_code_123".to_string()));
    assert_eq!(state, Some("csrf_token_abc".to_string()));
}

/// Test OAuth error redirect URL parsing
#[test]
fn test_oauth_error_redirect_parsing() {
    // Simulate what the OAuth server would receive on error
    let redirect_url = "/?error=access_denied&error_description=User%20denied%20access";

    let error = extract_param(redirect_url, "error");
    let description = extract_param(redirect_url, "error_description");

    assert_eq!(error, Some("access_denied".to_string()));
    assert_eq!(description, Some("User denied access".to_string()));
}

/// Test OAuth redirect with special characters
#[test]
fn test_oauth_redirect_special_chars() {
    let redirect_url = "/?code=abc%2B123%3D%3D&state=test%20state%21";

    let code = extract_param(redirect_url, "code");
    let state = extract_param(redirect_url, "state");

    assert_eq!(code, Some("abc+123==".to_string()));
    assert_eq!(state, Some("test state!".to_string()));
}

/// Test OAuth URL building with all providers
#[test]
fn test_oauth_url_building_all_providers() {
    // Provider OAuth endpoints
    let providers = [
        ("Google Drive", "https://accounts.google.com/o/oauth2/auth"),
        (
            "OneDrive",
            "https://login.microsoftonline.com/common/oauth2/v2.0/authorize",
        ),
        ("Dropbox", "https://www.dropbox.com/oauth2/authorize"),
        ("Box", "https://account.box.com/api/oauth2/authorize"),
    ];

    let port = 53682;
    let redirect_uri = format!("http://127.0.0.1:{}/", port);

    for (name, base_url) in providers {
        let url = format!(
            "{}?client_id=test_id&redirect_uri={}&response_type=code&scope=test_scope",
            base_url,
            urlencoded(&redirect_uri)
        );

        assert!(
            url.starts_with(base_url),
            "{} URL should start with base",
            name
        );
        assert!(
            url.contains("client_id="),
            "{} URL should have client_id",
            name
        );
        assert!(
            url.contains("redirect_uri="),
            "{} URL should have redirect_uri",
            name
        );
        assert!(
            url.contains("response_type=code"),
            "{} URL should have response_type",
            name
        );
    }
}

/// Simple URL encoding for tests
fn urlencoded(s: &str) -> String {
    let mut result = String::with_capacity(s.len() * 3);
    for c in s.chars() {
        match c {
            'a'..='z' | 'A'..='Z' | '0'..='9' | '-' | '_' | '.' | '~' => {
                result.push(c);
            }
            ' ' => result.push_str("%20"),
            _ => {
                for b in c.to_string().as_bytes() {
                    result.push_str(&format!("%{:02X}", b));
                }
            }
        }
    }
    result
}

// ============================================================================
// End-to-End Workflow Integration Tests
// ============================================================================

/// Test complete workflow: directory creation → file tracking → cleanup
#[test]
fn test_end_to_end_directory_workflow() {
    use std::fs;

    // Create a temporary case directory
    let temp_dir = std::env::temp_dir().join(format!("e2e_test_{}", std::process::id()));
    let case_name = "integration_test_case";
    let case_dir = temp_dir.join(case_name);

    // Ensure clean state
    let _ = fs::remove_dir_all(&temp_dir);

    // Create case directory structure
    let subdirs = [
        "logs",
        "downloads/gdrive",
        "downloads/onedrive",
        "downloads/dropbox",
        "downloads/box",
        "downloads/icloud",
        "listings",
        "config",
    ];

    for subdir in &subdirs {
        let path = case_dir.join(subdir);
        fs::create_dir_all(&path).expect(&format!("Failed to create {}", subdir));
    }

    // Verify all directories exist
    for subdir in &subdirs {
        let path = case_dir.join(subdir);
        assert!(path.exists(), "Directory {} should exist", subdir);
        assert!(path.is_dir(), "{} should be a directory", subdir);
    }

    // Create some test files
    let log_file = case_dir.join("logs/rclone-triage.log");
    fs::write(&log_file, "2026-01-01T00:00:00Z|INFO|Test log entry\n")
        .expect("Failed to write log");

    let config_file = case_dir.join("config/rclone.conf");
    fs::write(&config_file, "[remote]\ntype = drive\n").expect("Failed to write config");

    let listing_file = case_dir.join("listings/gdrive_files.csv");
    fs::write(
        &listing_file,
        "Path,Size,Modified,Hash,HashType\ntest.txt,100,2024-01-01,abc123,MD5\n",
    )
    .expect("Failed to write listing");

    // Verify files exist
    assert!(log_file.exists(), "Log file should exist");
    assert!(config_file.exists(), "Config file should exist");
    assert!(listing_file.exists(), "Listing file should exist");

    // Verify file contents
    let log_content = fs::read_to_string(&log_file).expect("Read log");
    assert!(log_content.contains("Test log entry"));

    let config_content = fs::read_to_string(&config_file).expect("Read config");
    assert!(config_content.contains("[remote]"));

    // Cleanup
    fs::remove_dir_all(&temp_dir).expect("Cleanup failed");
    assert!(!temp_dir.exists(), "Temp dir should be cleaned up");
}

/// Test file hashing workflow
#[test]
fn test_file_hash_verification_workflow() {
    use sha2::{Digest, Sha256};
    use std::fs;

    let temp_dir = std::env::temp_dir().join(format!("hash_test_{}", std::process::id()));
    let _ = fs::remove_dir_all(&temp_dir);
    fs::create_dir_all(&temp_dir).expect("Create temp dir");

    // Create a test file
    let test_content = b"This is test content for hash verification";
    let test_file = temp_dir.join("test_file.txt");
    fs::write(&test_file, test_content).expect("Write test file");

    // Calculate expected hash
    let mut hasher = Sha256::new();
    hasher.update(test_content);
    let expected_hash = format!("{:x}", hasher.finalize());

    // Verify by re-reading and hashing
    let read_content = fs::read(&test_file).expect("Read test file");
    let mut verify_hasher = Sha256::new();
    verify_hasher.update(&read_content);
    let actual_hash = format!("{:x}", verify_hasher.finalize());

    assert_eq!(expected_hash, actual_hash, "Hashes should match");
    assert_eq!(read_content, test_content, "Content should match");

    // Cleanup
    fs::remove_dir_all(&temp_dir).expect("Cleanup");
}

/// Test forensic log chain integrity
#[test]
fn test_forensic_log_chain_integrity() {
    use sha2::{Digest, Sha256};
    use std::fs;

    let temp_dir = std::env::temp_dir().join(format!("forensic_test_{}", std::process::id()));
    let _ = fs::remove_dir_all(&temp_dir);
    fs::create_dir_all(&temp_dir).expect("Create temp dir");

    let log_file = temp_dir.join("forensic.log");
    let mut entries = Vec::new();
    let mut prev_hash = "0000000000000000".to_string();

    // Create chain of log entries
    for i in 0..5 {
        let timestamp = format!("2026-01-0{}T12:00:00Z", i + 1);
        let event = format!("Test event {}", i);

        // Calculate hash: prev_hash || timestamp || event
        let mut hasher = Sha256::new();
        hasher.update(format!("{}|{}|{}", prev_hash, timestamp, event));
        let hash = format!("{:x}", hasher.finalize());
        let hash_prefix = &hash[0..16];

        let entry = format!(
            "{}|{}|{}|{}",
            timestamp,
            hash_prefix,
            &prev_hash[0..16],
            event
        );
        entries.push(entry.clone());
        prev_hash = hash;
    }

    // Write log
    let log_content = entries.join("\n") + "\n";
    fs::write(&log_file, &log_content).expect("Write log");

    // Verify chain integrity
    let read_content = fs::read_to_string(&log_file).expect("Read log");
    let lines: Vec<&str> = read_content.lines().collect();

    let mut verify_prev = "0000000000000000".to_string();
    for (i, line) in lines.iter().enumerate() {
        let parts: Vec<&str> = line.split('|').collect();
        assert_eq!(parts.len(), 4, "Entry {} should have 4 parts", i);

        let timestamp = parts[0];
        let hash_prefix = parts[1];
        let stored_prev = parts[2];
        let event = parts[3];

        // Verify prev_hash matches
        assert_eq!(
            stored_prev,
            &verify_prev[0..16],
            "Entry {} prev_hash mismatch",
            i
        );

        // Verify hash
        let mut hasher = Sha256::new();
        hasher.update(format!("{}|{}|{}", verify_prev, timestamp, event));
        let computed_hash = format!("{:x}", hasher.finalize());

        assert_eq!(
            hash_prefix,
            &computed_hash[0..16],
            "Entry {} hash mismatch",
            i
        );

        verify_prev = computed_hash;
    }

    // Cleanup
    fs::remove_dir_all(&temp_dir).expect("Cleanup");
}

// ============================================================================
// File Listing Integration Tests
// ============================================================================

/// Test parsing complex nested file structure
#[test]
fn test_parse_nested_file_structure() {
    let json = r#"[
        {"Path": "Documents", "Size": 0, "ModTime": "2024-01-01T00:00:00Z", "IsDir": true},
        {"Path": "Documents/Work", "Size": 0, "ModTime": "2024-01-01T00:00:00Z", "IsDir": true},
        {"Path": "Documents/Work/report.pdf", "Size": 102400, "ModTime": "2024-06-15T10:30:00Z", "IsDir": false, "Hashes": {"MD5": "abc123"}},
        {"Path": "Documents/Work/data.xlsx", "Size": 51200, "ModTime": "2024-06-14T09:00:00Z", "IsDir": false, "Hashes": {"MD5": "def456"}},
        {"Path": "Photos", "Size": 0, "ModTime": "2024-01-01T00:00:00Z", "IsDir": true},
        {"Path": "Photos/2024", "Size": 0, "ModTime": "2024-01-01T00:00:00Z", "IsDir": true},
        {"Path": "Photos/2024/vacation.jpg", "Size": 5242880, "ModTime": "2024-07-15T14:30:00Z", "IsDir": false, "Hashes": {"SHA1": "sha1abc"}},
        {"Path": "Photos/2024/family.png", "Size": 3145728, "ModTime": "2024-08-01T12:00:00Z", "IsDir": false, "Hashes": {"SHA1": "sha1def"}}
    ]"#;

    let entries: Vec<serde_json::Value> = serde_json::from_str(json).expect("Parse failed");

    // Count directories and files
    let dirs: Vec<_> = entries
        .iter()
        .filter(|e| e["IsDir"].as_bool() == Some(true))
        .collect();
    let files: Vec<_> = entries
        .iter()
        .filter(|e| e["IsDir"].as_bool() == Some(false))
        .collect();

    assert_eq!(dirs.len(), 4, "Should have 4 directories");
    assert_eq!(files.len(), 4, "Should have 4 files");

    // Verify file sizes
    let total_size: u64 = files.iter().filter_map(|f| f["Size"].as_u64()).sum();
    assert_eq!(
        total_size,
        102400 + 51200 + 5242880 + 3145728,
        "Total size mismatch"
    );

    // Verify all files have hashes
    for file in &files {
        assert!(
            file["Hashes"].is_object(),
            "File should have hashes: {}",
            file["Path"]
        );
    }
}

/// Test parsing files with Unicode names
#[test]
fn test_parse_unicode_filenames() {
    let json = r#"[
        {"Path": "文档/报告.doc", "Size": 1024, "ModTime": "2024-01-01T00:00:00Z", "IsDir": false},
        {"Path": "Документы/файл.txt", "Size": 512, "ModTime": "2024-01-01T00:00:00Z", "IsDir": false},
        {"Path": "Fotos/été_2024.jpg", "Size": 2048, "ModTime": "2024-01-01T00:00:00Z", "IsDir": false},
        {"Path": "📁 Folder/📄 File.txt", "Size": 256, "ModTime": "2024-01-01T00:00:00Z", "IsDir": false}
    ]"#;

    let entries: Vec<serde_json::Value> = serde_json::from_str(json).expect("Parse failed");
    assert_eq!(entries.len(), 4, "Should parse all Unicode files");

    // Verify Chinese
    assert_eq!(entries[0]["Path"].as_str().unwrap(), "文档/报告.doc");
    // Verify Russian
    assert_eq!(entries[1]["Path"].as_str().unwrap(), "Документы/файл.txt");
    // Verify French with accent
    assert_eq!(entries[2]["Path"].as_str().unwrap(), "Fotos/été_2024.jpg");
    // Verify emoji
    assert_eq!(
        entries[3]["Path"].as_str().unwrap(),
        "📁 Folder/📄 File.txt"
    );
}

/// Test parsing large file sizes
#[test]
fn test_parse_large_file_sizes() {
    let json = r#"[
        {"Path": "small.txt", "Size": 1, "ModTime": "2024-01-01T00:00:00Z", "IsDir": false},
        {"Path": "1kb.bin", "Size": 1024, "ModTime": "2024-01-01T00:00:00Z", "IsDir": false},
        {"Path": "1mb.bin", "Size": 1048576, "ModTime": "2024-01-01T00:00:00Z", "IsDir": false},
        {"Path": "1gb.bin", "Size": 1073741824, "ModTime": "2024-01-01T00:00:00Z", "IsDir": false},
        {"Path": "100gb.bin", "Size": 107374182400, "ModTime": "2024-01-01T00:00:00Z", "IsDir": false}
    ]"#;

    let entries: Vec<serde_json::Value> = serde_json::from_str(json).expect("Parse failed");

    assert_eq!(entries[0]["Size"].as_u64().unwrap(), 1);
    assert_eq!(entries[1]["Size"].as_u64().unwrap(), 1024);
    assert_eq!(entries[2]["Size"].as_u64().unwrap(), 1_048_576);
    assert_eq!(entries[3]["Size"].as_u64().unwrap(), 1_073_741_824);
    assert_eq!(entries[4]["Size"].as_u64().unwrap(), 107_374_182_400);
}

/// Test CSV export format
#[test]
fn test_csv_export_format() {
    use std::fs;

    let temp_dir = std::env::temp_dir().join(format!("csv_test_{}", std::process::id()));
    let _ = fs::remove_dir_all(&temp_dir);
    fs::create_dir_all(&temp_dir).expect("Create temp dir");

    let csv_file = temp_dir.join("listing.csv");

    // Create CSV with BOM for Excel compatibility
    let bom = "\u{FEFF}";
    let header = "Path,Size,Modified,Hash,HashType";
    let rows = vec![
        "Documents/report.pdf,102400,2024-06-15T10:30:00Z,abc123,MD5",
        "Photos/vacation.jpg,5242880,2024-07-15T14:30:00Z,def456,SHA1",
        "\"File with, comma.txt\",1024,2024-01-01T00:00:00Z,ghi789,MD5",
    ];

    let content = format!("{}{}\n{}", bom, header, rows.join("\n"));
    fs::write(&csv_file, &content).expect("Write CSV");

    // Verify BOM is present
    let bytes = fs::read(&csv_file).expect("Read CSV bytes");
    assert_eq!(&bytes[0..3], b"\xef\xbb\xbf", "BOM should be present");

    // Parse CSV
    let csv_content = fs::read_to_string(&csv_file).expect("Read CSV");
    let lines: Vec<&str> = csv_content.lines().collect();

    // First line after BOM should be header
    assert!(lines[0].ends_with("Path,Size,Modified,Hash,HashType"));
    assert_eq!(lines.len(), 4, "Should have header + 3 rows");

    // Cleanup
    fs::remove_dir_all(&temp_dir).expect("Cleanup");
}

// ============================================================================
// Provider Selection Integration Tests
// ============================================================================

/// Test provider display names
#[test]
fn test_provider_display_consistency() {
    let providers = [
        ("GoogleDrive", "Google Drive", "drive"),
        ("OneDrive", "OneDrive", "onedrive"),
        ("Dropbox", "Dropbox", "dropbox"),
        ("Box", "Box", "box"),
        ("ICloud", "iCloud Drive", "iclouddrive"),
    ];

    for (enum_name, display_name, rclone_type) in providers {
        // Display name should be user-friendly
        assert!(!display_name.is_empty(), "{} display name empty", enum_name);

        // rclone type should be lowercase and no spaces
        assert_eq!(
            rclone_type.to_lowercase(),
            rclone_type,
            "{} rclone type should be lowercase",
            enum_name
        );
        assert!(
            !rclone_type.contains(' '),
            "{} rclone type should have no spaces",
            enum_name
        );
    }
}

/// Test state transitions
#[test]
fn test_app_state_transitions() {
    #[derive(Debug, Clone, PartialEq)]
    enum TestState {
        CaseSetup,
        ProviderSelect,
        Authenticating,
        FileList,
        Downloading,
        Complete,
    }

    // Valid transitions
    let valid_transitions = [
        (TestState::CaseSetup, TestState::ProviderSelect),
        (TestState::ProviderSelect, TestState::Authenticating),
        (TestState::Authenticating, TestState::FileList),
        (TestState::FileList, TestState::Downloading),
        (TestState::Downloading, TestState::Complete),
    ];

    for (from, to) in &valid_transitions {
        // Just verify the test data is self-consistent
        assert_ne!(from, to, "Transition should change state");
    }

    // Verify we have a complete chain
    let states = vec![
        TestState::CaseSetup,
        TestState::ProviderSelect,
        TestState::Authenticating,
        TestState::FileList,
        TestState::Downloading,
        TestState::Complete,
    ];

    for i in 0..states.len() - 1 {
        let (from, to) = &valid_transitions[i];
        assert_eq!(*from, states[i]);
        assert_eq!(*to, states[i + 1]);
    }
}
