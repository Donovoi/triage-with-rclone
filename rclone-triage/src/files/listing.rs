//! File listing utilities

use anyhow::{bail, Context, Result};
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;

use crate::rclone::RcloneRunner;

/// File entry returned by rclone listing
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FileEntry {
    pub path: String,
    pub size: u64,
    pub modified: Option<DateTime<Utc>>,
    pub is_dir: bool,
    pub hash: Option<String>,
    pub hash_type: Option<String>,
}

/// Internal representation of rclone lsjson output
#[derive(Debug, Clone, Deserialize)]
struct RcloneLsJsonEntry {
    #[serde(rename = "Path")]
    path: String,
    #[serde(rename = "Size")]
    size: u64,
    #[serde(rename = "ModTime")]
    mod_time: Option<DateTime<Utc>>,
    #[serde(rename = "IsDir")]
    is_dir: bool,
    #[serde(rename = "Hashes")]
    hashes: Option<HashMap<String, String>>,
}

impl From<RcloneLsJsonEntry> for FileEntry {
    fn from(entry: RcloneLsJsonEntry) -> Self {
        let (hash, hash_type) = select_hash(entry.hashes.as_ref());
        Self {
            path: entry.path,
            size: entry.size,
            modified: entry.mod_time,
            is_dir: entry.is_dir,
            hash,
            hash_type,
        }
    }
}

/// List files for a given rclone path (remote or local)
///
/// Example:
/// - Remote: "mydrive:" or "mydrive:/folder"
/// - Local: "/tmp"
pub fn list_path(rclone: &RcloneRunner, target: &str) -> Result<Vec<FileEntry>> {
    let output = rclone.run(&["lsjson", "--hash", "--recursive", target])?;
    if !output.success() {
        bail!("rclone lsjson failed: {}", output.stderr_string());
    }

    let entries = parse_lsjson_entries(&output.stdout_string())
        .with_context(|| "Failed to parse rclone lsjson output")?;

    Ok(entries.into_iter().map(FileEntry::from).collect())
}

/// List files for a given rclone path, reporting progress as entries are seen.
pub fn list_path_with_progress<F>(
    rclone: &RcloneRunner,
    target: &str,
    mut on_progress: F,
) -> Result<Vec<FileEntry>>
where
    F: FnMut(usize),
{
    let mut count = 0usize;
    let mut last_emit = 0usize;
    let output = rclone.run_streaming(&["lsjson", "--hash", "--recursive", target], |line| {
        if line.contains("\"Path\"") {
            count += 1;
            if count - last_emit >= 100 {
                on_progress(count);
                last_emit = count;
            }
        }
    })?;

    if !output.success() {
        bail!("rclone lsjson failed: {}", output.stderr_string());
    }

    if count != last_emit {
        on_progress(count);
    }

    let entries = parse_lsjson_entries(&output.stdout_string())
        .with_context(|| "Failed to parse rclone lsjson output")?;

    Ok(entries.into_iter().map(FileEntry::from).collect())
}

fn parse_lsjson_entries(raw: &str) -> Result<Vec<RcloneLsJsonEntry>> {
    let trimmed = raw.trim();
    if trimmed.is_empty() {
        bail!("rclone lsjson returned empty output");
    }

    if let Ok(entries) = serde_json::from_str::<Vec<RcloneLsJsonEntry>>(trimmed) {
        return Ok(entries);
    }

    if let Some(payload) = extract_json_payload(trimmed) {
        if let Ok(entries) = serde_json::from_str::<Vec<RcloneLsJsonEntry>>(payload) {
            return Ok(entries);
        }
    }

    let preview = trimmed.lines().take(3).collect::<Vec<_>>().join(" ");
    bail!(
        "Failed to parse rclone lsjson output. Output started with: {}",
        preview
    );
}

fn extract_json_payload(raw: &str) -> Option<&str> {
    if let (Some(start), Some(end)) = (raw.find('['), raw.rfind(']')) {
        if end > start {
            return Some(&raw[start..=end]);
        }
    }

    if let (Some(start), Some(end)) = (raw.find('{'), raw.rfind('}')) {
        if end > start {
            return Some(&raw[start..=end]);
        }
    }

    None
}

fn select_hash(hashes: Option<&HashMap<String, String>>) -> (Option<String>, Option<String>) {
    let hashes = match hashes {
        Some(h) => h,
        None => return (None, None),
    };

    let preferred = ["sha256", "sha1", "md5", "quickxorhash", "dropbox"];
    for key in preferred.iter() {
        if let Some(value) = hashes
            .iter()
            .find(|(k, _)| k.eq_ignore_ascii_case(key))
            .map(|(_, v)| v)
        {
            return (Some(value.clone()), Some(key.to_string()));
        }
    }

    // Fallback to first hash if available
    if let Some((k, v)) = hashes.iter().next() {
        return (Some(v.clone()), Some(k.clone()));
    }

    (None, None)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_lsjson() {
        let data = r#"[
            {"Path":"file1.txt","Size":12,"ModTime":"2024-01-01T00:00:00Z","IsDir":false,"Hashes":{"MD5":"abc"}},
            {"Path":"folder","Size":0,"ModTime":"2024-01-01T00:00:00Z","IsDir":true}
        ]"#;

        let entries: Vec<RcloneLsJsonEntry> = serde_json::from_str(data).unwrap();
        let files: Vec<FileEntry> = entries.into_iter().map(FileEntry::from).collect();

        assert_eq!(files.len(), 2);
        assert_eq!(files[0].path, "file1.txt");
        assert_eq!(files[0].hash_type.as_deref(), Some("md5"));
        assert_eq!(files[0].hash.as_deref(), Some("abc"));
        assert!(files[1].is_dir);
    }

    #[test]
    fn test_select_hash_preferred() {
        let mut hashes = HashMap::new();
        hashes.insert("MD5".to_string(), "md5val".to_string());
        hashes.insert("SHA1".to_string(), "sha1val".to_string());

        let (hash, hash_type) = select_hash(Some(&hashes));
        assert_eq!(hash, Some("sha1val".to_string()));
        assert_eq!(hash_type, Some("sha1".to_string()));
    }

    #[test]
    fn test_parse_lsjson_with_noise_prefix() {
        let data = r#"2024/01/01 00:00:00 INFO  : some log
        [
          {"Path":"file1.txt","Size":12,"ModTime":"2024-01-01T00:00:00Z","IsDir":false}
        ]"#;

        let entries = parse_lsjson_entries(data).unwrap();
        assert_eq!(entries.len(), 1);
        assert_eq!(entries[0].path, "file1.txt");
    }

    #[test]
    fn test_parse_lsjson_with_noise_suffix() {
        let data = r#"[
          {"Path":"file1.txt","Size":12,"ModTime":"2024-01-01T00:00:00Z","IsDir":false}
        ]
        2024/01/01 00:00:00 INFO  : done"#;

        let entries = parse_lsjson_entries(data).unwrap();
        assert_eq!(entries.len(), 1);
        assert_eq!(entries[0].path, "file1.txt");
    }
}
