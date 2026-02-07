//! CSV export for file listings

use anyhow::{Context, Result};
use csv::WriterBuilder;
use rust_xlsxwriter::Workbook;
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

/// Streaming CSV writer for large listings.
pub(crate) struct ListingCsvWriter {
    writer: csv::Writer<std::fs::File>,
}

impl ListingCsvWriter {
    pub(crate) fn create(path: impl AsRef<Path>) -> Result<Self> {
        let path = path.as_ref();
        let mut file = OpenOptions::new()
            .create(true)
            .truncate(true)
            .write(true)
            .open(path)
            .with_context(|| format!("Failed to create CSV: {:?}", path))?;

        // Write UTF-8 BOM for Excel
        file.write_all(&[0xEF, 0xBB, 0xBF])?;

        let writer = WriterBuilder::new().has_headers(true).from_writer(file);
        Ok(Self { writer })
    }

    pub(crate) fn write_entry(&mut self, entry: &FileEntry) -> Result<()> {
        let record = CsvFileEntry::from(entry);
        self.writer.serialize(record)?;
        Ok(())
    }

    pub(crate) fn flush(mut self) -> Result<()> {
        self.writer.flush()?;
        Ok(())
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

/// Export a listing to Excel (.xlsx)
pub fn export_listing_xlsx(entries: &[FileEntry], path: impl AsRef<Path>) -> Result<()> {
    let path = path.as_ref();
    let path_str = path
        .to_str()
        .ok_or_else(|| anyhow::anyhow!("Invalid XLSX path: {:?}", path))?;

    let mut workbook = Workbook::new();
    let worksheet = workbook
        .add_worksheet()
        .set_name("Listing")
        .context("Failed to add worksheet")?;

    let headers = ["Path", "Size", "Modified", "IsDir", "Hash", "HashType"];
    for (col, header) in headers.iter().enumerate() {
        worksheet
            .write_string(0, col as u16, *header)
            .context("Failed to write header")?;
    }

    for (row, entry) in entries.iter().enumerate() {
        let row = (row + 1) as u32;
        worksheet
            .write_string(row, 0, &entry.path)
            .context("Failed to write path")?;
        worksheet
            .write_number(row, 1, entry.size as f64)
            .context("Failed to write size")?;

        if let Some(modified) = entry.modified {
            worksheet
                .write_string(row, 2, modified.to_rfc3339())
                .context("Failed to write modified")?;
        }

        worksheet
            .write_boolean(row, 3, entry.is_dir)
            .context("Failed to write is_dir")?;

        if let Some(hash) = &entry.hash {
            worksheet
                .write_string(row, 4, hash)
                .context("Failed to write hash")?;
        }
        if let Some(hash_type) = &entry.hash_type {
            worksheet
                .write_string(row, 5, hash_type)
                .context("Failed to write hash type")?;
        }
    }

    workbook
        .save(path_str)
        .context("Failed to save workbook")?;
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

    #[test]
    fn test_export_listing_xlsx() {
        let dir = tempdir().unwrap();
        let xlsx_path = dir.path().join("listing.xlsx");

        let entry = FileEntry {
            path: "file.txt".to_string(),
            size: 123,
            modified: Some(DateTime::<Utc>::from(std::time::SystemTime::UNIX_EPOCH)),
            is_dir: false,
            hash: Some("abc".to_string()),
            hash_type: Some("md5".to_string()),
        };

        export_listing_xlsx(&[entry], &xlsx_path).unwrap();
        assert!(xlsx_path.exists());
    }
}
