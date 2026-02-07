#![cfg(unix)]

use rclone_triage::case::directory::create_case_directories;
use rclone_triage::case::report::{generate_report, write_report};
use rclone_triage::case::{AuthenticatedProvider, Case, DownloadedFile};
use rclone_triage::files::{
    export_listing, list_path, DownloadPhase, DownloadQueue, DownloadRequest, ListPathOptions,
};
use rclone_triage::rclone::{start_web_gui, RcloneConfig, RcloneRunner};
use sha2::{Digest, Sha256};
use std::fs;
use std::os::unix::fs::PermissionsExt;
use std::path::PathBuf;
use tempfile::TempDir;

fn write_mock_rclone(script: &str) -> (TempDir, PathBuf) {
    let dir = tempfile::tempdir().expect("create temp dir");
    let path = dir.path().join("rclone-mock");
    fs::write(&path, script).expect("write mock rclone");
    let mut perms = fs::metadata(&path).expect("read permissions").permissions();
    perms.set_mode(0o755);
    fs::set_permissions(&path, perms).expect("set executable");
    (dir, path)
}

#[test]
fn test_list_path_with_mock_rclone() {
    let script = r#"#!/bin/sh
set -eu

if [ "${1-}" = "--config" ]; then
  shift 2
fi

cmd="${1-}"
if [ $# -gt 0 ]; then
  shift
fi

case "$cmd" in
  lsjson)
    cat <<'JSON'
[
  {"Path":"file.txt","Size":5,"ModTime":"2024-01-01T00:00:00Z","IsDir":false,"Hashes":{"MD5":"abc","SHA1":"def"}},
  {"Path":"folder","Size":0,"ModTime":"2024-01-02T00:00:00Z","IsDir":true}
]
JSON
    ;;
  *)
    echo "unexpected command: $cmd" >&2
    exit 1
    ;;
esac
"#;

    let (_dir, mock_path) = write_mock_rclone(script);
    let runner = RcloneRunner::new(&mock_path);

    let entries = list_path(&runner, "mock:", ListPathOptions::with_hashes())
        .expect("list_path should succeed");
    assert_eq!(entries.len(), 2);
    assert_eq!(entries[0].path, "file.txt");
    assert_eq!(entries[0].hash.as_deref(), Some("def"));
    assert_eq!(entries[0].hash_type.as_deref(), Some("sha1"));
    assert!(!entries[0].is_dir);
    assert!(entries[1].is_dir);
}

#[test]
fn test_download_copyto_verified_with_mock_rclone() {
    let script = r#"#!/bin/sh
set -eu

if [ "${1-}" = "--config" ]; then
  shift 2
fi

cmd="${1-}"
if [ $# -gt 0 ]; then
  shift
fi

if [ "$cmd" = "copyto" ]; then
  src="${1-}"
  dest="${2-}"
  mkdir -p "$(dirname "$dest")"
  cp "$src" "$dest"
  exit 0
fi

echo "unexpected command: $cmd" >&2
exit 1
"#;

    let (_dir, mock_path) = write_mock_rclone(script);
    let runner = RcloneRunner::new(&mock_path);

    let src_dir = tempfile::tempdir().expect("src tempdir");
    let dst_dir = tempfile::tempdir().expect("dst tempdir");
    let src_file = src_dir.path().join("source.txt");
    let dst_file = dst_dir.path().join("dest.txt");

    let content = b"hello integration test";
    fs::write(&src_file, content).expect("write source");

    let mut hasher = Sha256::new();
    hasher.update(content);
    let expected_hash = format!("{:x}", hasher.finalize());

    let request = DownloadRequest::new_copyto(
        src_file.to_string_lossy(),
        dst_file.to_string_lossy(),
    )
    .with_hash(Some(expected_hash.clone()), Some("sha256".to_string()));

    let queue = DownloadQueue::new();
    let result = queue.download_one_verified(&runner, &request);

    assert!(result.success, "download should succeed: {:?}", result.error);
    assert_eq!(result.hash_verified, Some(true));
    assert_eq!(result.hash.as_deref(), Some(expected_hash.as_str()));
    assert_eq!(result.size, Some(content.len() as u64));
    assert!(dst_file.exists());
    let copied = fs::read(&dst_file).expect("read dest");
    assert_eq!(copied, content);
}

#[test]
fn test_list_remotes_requires_config() {
    let script = r#"#!/bin/sh
set -eu

if [ "${1-}" = "--config" ]; then
  config="${2-}"
  shift 2
else
  echo "missing --config" >&2
  exit 2
fi

if [ ! -f "$config" ]; then
  echo "config not found" >&2
  exit 3
fi

cmd="${1-}"
if [ $# -gt 0 ]; then
  shift
fi

if [ "$cmd" != "listremotes" ]; then
  echo "unexpected command: $cmd" >&2
  exit 4
fi

echo "alpha:"
echo "beta:"
"#;

    let (_dir, mock_path) = write_mock_rclone(script);
    let temp_dir = tempfile::tempdir().expect("temp config dir");
    let config_path = temp_dir.path().join("rclone.conf");
    fs::write(&config_path, "# mock config").expect("write config");

    let runner = RcloneRunner::new(&mock_path).with_config(&config_path);
    let remotes = runner.list_remotes().expect("list_remotes should succeed");

    assert_eq!(remotes, vec!["alpha".to_string(), "beta".to_string()]);
}

#[test]
fn test_connectivity_success_with_mock_rclone() {
    let script = r#"#!/bin/sh
set -eu

if [ "${1-}" = "--config" ]; then
  shift 2
fi

cmd="${1-}"
if [ $# -gt 0 ]; then
  shift
fi

if [ "$cmd" = "lsjson" ]; then
  echo "[]"
  exit 0
fi

echo "unexpected command: $cmd" >&2
exit 1
"#;

    let (_dir, mock_path) = write_mock_rclone(script);
    let runner = RcloneRunner::new(&mock_path);

    let result = rclone_triage::rclone::test_connectivity(&runner, "mock").unwrap();
    assert!(result.ok);
}

#[test]
fn test_start_web_gui_builds_expected_args() {
    let temp_dir = tempfile::tempdir().expect("temp dir");
    let log_path = temp_dir.path().join("args.txt");
    let config_path = temp_dir.path().join("rclone.conf");
    fs::write(&config_path, "# mock config").expect("write config");

    let script = format!(
        r#"#!/bin/sh
set -eu
echo "$@" > "{log}"
"#,
        log = log_path.display()
    );

    let (_dir, mock_path) = write_mock_rclone(&script);
    let mut process = start_web_gui(
        &mock_path,
        Some(&config_path),
        5590,
        Some("alice"),
        Some("secret"),
    )
    .expect("start_web_gui should succeed");

    for _ in 0..20 {
        if log_path.exists() {
            break;
        }
        std::thread::sleep(std::time::Duration::from_millis(25));
    }
    let _ = process.stop();

    let args = fs::read_to_string(&log_path).expect("read args");
    let parts: Vec<&str> = args.split_whitespace().collect();
    let config_str = config_path.to_string_lossy().to_string();

    assert!(parts.contains(&"rcd"));
    assert!(parts.contains(&"--rc-web-gui"));
    assert!(parts.contains(&"--rc-addr"));
    assert!(parts.contains(&"127.0.0.1:5590"));
    assert!(parts.contains(&"--config"));
    assert!(parts.contains(&config_str.as_str()));
    assert!(parts.contains(&"--rc-user"));
    assert!(parts.contains(&"alice"));
    assert!(parts.contains(&"--rc-pass"));
    assert!(parts.contains(&"secret"));
}

#[test]
fn test_full_flow_with_mock_rclone() {
    let temp_root = tempfile::tempdir().expect("temp root");
    let mut case = Case::new("integration-case", temp_root.path().to_path_buf()).unwrap();
    let dirs = create_case_directories(&case).unwrap();

    let source_dir = tempfile::tempdir().expect("source dir");
    let source_file = source_dir.path().join("file.txt");
    let content = b"hello integration flow";
    fs::write(&source_file, content).expect("write source");

    let mut hasher = Sha256::new();
    hasher.update(content);
    let expected_hash = format!("{:x}", hasher.finalize());
    let expected_size = content.len() as u64;
    let half_size = expected_size / 2;

    let script = format!(
        r#"#!/bin/sh
set -eu

if [ "${{1-}}" = "--config" ]; then
  shift 2
fi

cmd="${{1-}}"
if [ $# -gt 0 ]; then
  shift
fi

case "$cmd" in
  lsjson)
    cat <<'JSON'
[
  {{"Path":"file.txt","Size":{size},"ModTime":"2024-01-01T00:00:00Z","IsDir":false,"Hashes":{{"SHA256":"{hash}"}}}}
]
JSON
    ;;
  copyto)
    src="${{1-}}"
    dest="${{2-}}"
    echo "Transferred: {half} B / {size} B, 50%, 1 B/s, ETA 1s" 1>&2
    echo "Transferred: {size} B / {size} B, 100%, 1 B/s, ETA 0s" 1>&2
    mkdir -p "$(dirname "$dest")"
    cp "$src" "$dest"
    ;;
  listremotes)
    echo "mock:"
    ;;
  *)
    echo "unexpected command: $cmd" >&2
    exit 1
    ;;
esac
"#,
        size = expected_size,
        half = half_size,
        hash = expected_hash
    );

    let (_dir, mock_path) = write_mock_rclone(&script);
    let config = RcloneConfig::for_case(&dirs.config).unwrap();
    let runner = RcloneRunner::new(&mock_path).with_config(config.path());

    let entries = list_path(&runner, "mock:", ListPathOptions::with_hashes()).expect("list_path");
    assert_eq!(entries.len(), 1);

    let csv_path = dirs.listings.join("mock_files.csv");
    export_listing(&entries, &csv_path).expect("export listing");
    assert!(csv_path.exists());

    let dest_dir = dirs.downloads.join("mock");
    fs::create_dir_all(&dest_dir).expect("create dest dir");
    let dest_file = dest_dir.join("file.txt");

    let mut queue = DownloadQueue::new();
    queue.set_verify_hashes(true);
    queue.add(
        DownloadRequest::new_copyto(
            source_file.to_string_lossy(),
            dest_file.to_string_lossy(),
        )
        .with_hash(Some(expected_hash.clone()), Some("sha256".to_string()))
        .with_size(Some(expected_size)),
    );

    let mut phases = Vec::new();
    let results = queue.download_all_with_progress(&runner, |p| phases.push(p.phase));

    assert!(phases.contains(&DownloadPhase::InProgress));
    assert_eq!(results.len(), 1);
    assert!(results[0].success);
    assert_eq!(results[0].hash_verified, Some(true));
    assert!(dest_file.exists());

    case.add_provider(AuthenticatedProvider {
        provider_id: "drive".to_string(),
        provider_name: "Google Drive".to_string(),
        remote_name: "mock".to_string(),
        user_info: Some("test@example.com".to_string()),
    });
    case.add_download(DownloadedFile {
        path: "file.txt".to_string(),
        size: results[0].size.unwrap_or(0),
        hash: results[0].hash.clone(),
        hash_type: results[0].hash_type.clone(),
        hash_verified: results[0].hash_verified,
        hash_error: results[0].hash_error.clone(),
    });
    case.finalize();

    let report = generate_report(&case, None, None, None, Some("loghash"));
    write_report(&dirs.report, &report).expect("write report");

    let report_contents = fs::read_to_string(&dirs.report).expect("read report");
    assert!(report_contents.contains("rclone-triage Report"));
    assert!(report_contents.contains(case.session_id()));
    assert!(report_contents.contains("file.txt"));
}

#[test]
fn test_list_path_failure_with_mock_rclone() {
    let script = r#"#!/bin/sh
set -eu

if [ "${1-}" = "--config" ]; then
  shift 2
fi

cmd="${1-}"
if [ $# -gt 0 ]; then
  shift
fi

if [ "$cmd" = "lsjson" ]; then
  echo "lsjson failed" >&2
  exit 2
fi

echo "unexpected command: $cmd" >&2
exit 1
"#;

    let (_dir, mock_path) = write_mock_rclone(script);
    let runner = RcloneRunner::new(&mock_path);

    let err = list_path(&runner, "mock:", ListPathOptions::with_hashes())
        .expect_err("expected failure");
    assert!(err.to_string().contains("lsjson failed"));
}

#[test]
fn test_download_failure_with_mock_rclone() {
    let script = r#"#!/bin/sh
set -eu

if [ "${1-}" = "--config" ]; then
  shift 2
fi

cmd="${1-}"
if [ $# -gt 0 ]; then
  shift
fi

if [ "$cmd" = "copyto" ]; then
  echo "copy failed" >&2
  exit 3
fi

echo "unexpected command: $cmd" >&2
exit 1
"#;

    let (_dir, mock_path) = write_mock_rclone(script);
    let runner = RcloneRunner::new(&mock_path);

    let src_dir = tempfile::tempdir().expect("src tempdir");
    let dst_dir = tempfile::tempdir().expect("dst tempdir");

    let src_file = src_dir.path().join("test.txt");
    let dst_file = dst_dir.path().join("test.txt");
    fs::write(&src_file, "hello").unwrap();

    let request =
        DownloadRequest::new_copyto(src_file.to_string_lossy(), dst_file.to_string_lossy());
    let queue = DownloadQueue::new();
    let result = queue.download_one_verified(&runner, &request);

    assert!(!result.success);
    assert!(result.error.unwrap_or_default().contains("copy failed"));
}

#[test]
fn test_hash_mismatch_detected_with_mock_rclone() {
    let script = r#"#!/bin/sh
set -eu

if [ "${1-}" = "--config" ]; then
  shift 2
fi

cmd="${1-}"
if [ $# -gt 0 ]; then
  shift
fi

if [ "$cmd" = "copyto" ]; then
  src="${1-}"
  dest="${2-}"
  mkdir -p "$(dirname "$dest")"
  cp "$src" "$dest"
  exit 0
fi

echo "unexpected command: $cmd" >&2
exit 1
"#;

    let (_dir, mock_path) = write_mock_rclone(script);
    let runner = RcloneRunner::new(&mock_path);

    let src_dir = tempfile::tempdir().expect("src tempdir");
    let dst_dir = tempfile::tempdir().expect("dst tempdir");

    let src_file = src_dir.path().join("test.txt");
    let dst_file = dst_dir.path().join("test.txt");
    fs::write(&src_file, "hello").unwrap();

    let request = DownloadRequest::new_copyto(
        src_file.to_string_lossy(),
        dst_file.to_string_lossy(),
    )
    .with_hash(Some("deadbeef".to_string()), Some("sha256".to_string()))
    .with_size(Some(5));

    let queue = DownloadQueue::new();
    let result = queue.download_one_verified(&runner, &request);

    assert!(result.success);
    assert_eq!(result.hash_verified, Some(false));
}
