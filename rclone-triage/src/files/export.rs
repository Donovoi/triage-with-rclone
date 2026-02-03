//! CSV export for file listings

use anyhow::{Context, Result};
use csv::WriterBuilder;
use serde::Serialize;
use std::fs::OpenOptions;
use std::io::Write;
use std::path::Path;

use super::listing::FileEntry;

#[derive(Debug, Serialize)]
struct CsvFileEntry {
    path: String,
    size: u64,
    modified: Option<String>,
    is_dir: bool,
    hash: Option<String>,
    hash_type: Option<String>,
}

impl From<&FileEntry> for CsvFileEntry {
    fn from(entry: &FileEntry) -> Self {
        let modified = entry.modified.map(|dt| dt.to_rfc3339());
        Self {
            path: entry.path.clone(),
            size: entry.size,
            modified,
            is_dir: entry.is_dir,
            hash: entry.hash.clone(),
            hash_type: entry.hash_type.clone(),
        }
    }
}

/// Export a listing to CSV with UTF-8 BOM for Excel compatibility
pub fn export_listing(entries: &[FileEntry], path: impl AsRef<Path>) -> Result<()> {
    let path = path.as_ref();
    let mut file = OpenOptions::new()
        .create(true)
        .truncate(true)
        .write(true)
        .open(path)
        .with_context(|| format!("Failed to create CSV: {:?}", path))?;

    // Write UTF-8 BOM for Excel
    file.write_all(&[0xEF, 0xBB, 0xBF])?;

    let mut writer = WriterBuilder::new().has_headers(true).from_writer(file);

    for entry in entries {
        let record = CsvFileEntry::from(entry);
        writer.serialize(record)?;
    }

    writer.flush()?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::{DateTime, Utc};
    use tempfile::tempdir;

    #[test]
    fn test_export_listing_with_bom() {
        let dir = tempdir().unwrap();
        let csv_path = dir.path().join("listing.csv");

        let entry = FileEntry {
            path: "file.txt".to_string(),
            size: 123,
            modified: Some(DateTime::<Utc>::from(std::time::SystemTime::UNIX_EPOCH)),
            is_dir: false,
            hash: Some("abc".to_string()),
            hash_type: Some("md5".to_string()),
        };

        export_listing(&[entry], &csv_path).unwrap();

        let bytes = std::fs::read(&csv_path).unwrap();
        assert!(bytes.starts_with(&[0xEF, 0xBB, 0xBF]));
    }
}
