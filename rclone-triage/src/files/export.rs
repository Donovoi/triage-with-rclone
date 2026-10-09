//! CSV export for file listings

use anyhow::{Context, Result};
use csv::WriterBuilder;
use rust_xlsxwriter::Workbook;
use serde::Serialize;
use std::fs::File;
use std::io::Write;
use std::path::{Path, PathBuf};

use super::listing::FileEntry;

#[derive(Debug, Serialize)]
struct CsvFileEntry {
    path_encoding: &'static str,
    remote: Option<String>,
    path: String,
    size: Option<u64>,
    modified: Option<String>,
    is_dir: bool,
    hash: Option<String>,
    hash_type: Option<String>,
}

impl From<&FileEntry> for CsvFileEntry {
    fn from(entry: &FileEntry) -> Self {
        let modified = entry.modified.map(|dt| dt.to_rfc3339());
        Self {
            path_encoding: "excel-safe-v1",
            remote: entry.remote_name.as_deref().map(excel_safe_text),
            path: excel_safe_text(&entry.path),
            size: entry.size,
            modified,
            is_dir: entry.is_dir,
            hash: entry.hash.clone(),
            hash_type: entry.hash_type.clone(),
        }
    }
}

fn excel_safe_text(value: &str) -> String {
    if value.starts_with(['=', '+', '-', '@', '\t', '\r', '\n', '\'']) {
        format!("'{value}")
    } else {
        value.to_string()
    }
}

/// Streaming CSV writer for large listings.
pub(crate) struct ListingCsvWriter {
    writer: csv::Writer<File>,
    publication: Option<(tempfile::NamedTempFile, PathBuf)>,
}

impl ListingCsvWriter {
    pub(crate) fn create(path: impl AsRef<Path>) -> Result<Self> {
        let path = path.as_ref();
        crate::utils::path::ensure_no_link_components(path)?;
        let parent = path
            .parent()
            .filter(|p| !p.as_os_str().is_empty())
            .unwrap_or(Path::new("."));
        let staged = crate::utils::private_fs::tempfile_in(parent, ".listing-", ".tmp")
            .with_context(|| format!("Failed to create CSV: {:?}", path))?;
        let mut writer = Self::from_file(staged.as_file().try_clone()?)?;
        writer.publication = Some((staged, path.to_owned()));
        Ok(writer)
    }

    /// Use the already-created file; the caller retains publication ownership.
    pub(crate) fn from_file(mut file: File) -> Result<Self> {
        if file.metadata()?.len() != 0 {
            anyhow::bail!("Listing output handle must be empty");
        }
        file.write_all(&[0xEF, 0xBB, 0xBF])?;
        Ok(Self {
            writer: WriterBuilder::new().has_headers(true).from_writer(file),
            publication: None,
        })
    }

    pub(crate) fn write_entry(&mut self, entry: &FileEntry) -> Result<()> {
        let record = CsvFileEntry::from(entry);
        self.writer.serialize(record)?;
        Ok(())
    }

    pub(crate) fn flush(mut self) -> Result<()> {
        self.writer.flush()?;
        self.writer.get_ref().sync_all()?;
        // Drop the duplicate handle before the atomic replacement. A failed
        // enumeration never reaches this point and preserves an old export.
        drop(self.writer);
        if let Some((staged, destination)) = self.publication {
            crate::utils::private_fs::persist(staged, &destination)?;
        }
        Ok(())
    }
}

/// Export a listing to CSV with UTF-8 BOM for Excel compatibility
pub fn export_listing(entries: &[FileEntry], path: impl AsRef<Path>) -> Result<()> {
    let mut writer = ListingCsvWriter::create(path)?;
    for entry in entries {
        writer.write_entry(entry)?;
    }

    writer.flush()?;
    Ok(())
}

/// Export a listing to Excel (.xlsx)
pub fn export_listing_xlsx(entries: &[FileEntry], path: impl AsRef<Path>) -> Result<()> {
    let path = path.as_ref();
    crate::utils::path::ensure_no_link_components(path)?;

    let mut workbook = Workbook::new();
    let worksheet = workbook
        .add_worksheet()
        .set_name("Listing")
        .context("Failed to add worksheet")?;

    let headers = [
        "Remote", "Path", "Size", "Modified", "IsDir", "Hash", "HashType",
    ];
    for (col, header) in headers.iter().enumerate() {
        worksheet
            .write_string(0, col as u16, *header)
            .context("Failed to write header")?;
    }

    for (row, entry) in entries.iter().enumerate() {
        let row = (row + 1) as u32;
        if let Some(ref remote) = entry.remote_name {
            worksheet
                .write_string(row, 0, remote)
                .context("Failed to write remote")?;
        }
        worksheet
            .write_string(row, 1, &entry.path)
            .context("Failed to write path")?;
        if let Some(size) = entry.size {
            // Preserve integer byte counts exactly, including values above 2^53.
            worksheet
                .write_string(row, 2, size.to_string())
                .context("Failed to write size")?;
        }

        if let Some(modified) = entry.modified {
            worksheet
                .write_string(row, 3, modified.to_rfc3339())
                .context("Failed to write modified")?;
        }

        worksheet
            .write_boolean(row, 4, entry.is_dir)
            .context("Failed to write is_dir")?;

        if let Some(hash) = &entry.hash {
            worksheet
                .write_string(row, 5, hash)
                .context("Failed to write hash")?;
        }
        if let Some(hash_type) = &entry.hash_type {
            worksheet
                .write_string(row, 6, hash_type)
                .context("Failed to write hash type")?;
        }
    }

    let parent = path
        .parent()
        .filter(|p| !p.as_os_str().is_empty())
        .unwrap_or(Path::new("."));
    let mut staged = crate::utils::private_fs::tempfile_in(parent, ".listing-", ".xlsx")?;
    workbook
        .save_to_writer(staged.as_file_mut())
        .context("Failed to save workbook")?;
    staged.as_file().sync_all()?;
    crate::utils::private_fs::persist(staged, path)?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::{DateTime, Utc};

    #[test]
    fn non_private_existing_export_is_preserved_on_refusal() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("existing.csv");
        std::fs::write(&path, b"earlier export").unwrap();
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o644)).unwrap();
        }
        assert!(export_listing(&[], &path).is_err());
        assert_eq!(std::fs::read(&path).unwrap(), b"earlier export");
        assert_eq!(std::fs::read_dir(dir.path()).unwrap().count(), 1);
    }

    #[test]
    fn private_export_can_be_updated_without_staging_leftovers() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("existing.csv");
        crate::utils::private_fs::write(&path, b"earlier export").unwrap();
        export_listing(&[], &path).unwrap();
        assert_eq!(std::fs::read(&path).unwrap(), [0xef, 0xbb, 0xbf]);
        crate::utils::private_fs::open_private(&path).unwrap();
        assert_eq!(std::fs::read_dir(dir.path()).unwrap().count(), 1);
    }

    #[test]
    fn csv_round_trip_keeps_exact_paths_without_formula_execution() {
        let temp = tempfile::tempdir().unwrap();
        let path = temp.path().join("inventory.csv");
        let names = ["=1+1", "'literal.txt", " leading.txt", "trailing.txt "];
        let entries: Vec<_> = names
            .iter()
            .map(|name| FileEntry {
                path: (*name).into(),
                size: None,
                modified: None,
                is_dir: false,
                hash: None,
                hash_type: None,
                remote_name: Some("remote".into()),
            })
            .collect();
        export_listing(&entries, &path).unwrap();
        let csv = std::fs::read_to_string(&path).unwrap();
        assert!(csv.contains("'=1+1"));
        let imported = crate::files::queue::read_download_queue(&path).unwrap();
        assert_eq!(
            imported.iter().map(|e| e.path.as_str()).collect::<Vec<_>>(),
            names
        );
    }
    use tempfile::tempdir;

    #[test]
    fn test_export_listing_with_bom() {
        let dir = tempdir().unwrap();
        let csv_path = dir.path().join("listing.csv");

        let entry = FileEntry {
            path: "file.txt".to_string(),
            size: Some(123),
            modified: Some(DateTime::<Utc>::from(std::time::SystemTime::UNIX_EPOCH)),
            is_dir: false,
            hash: Some("abc".to_string()),
            hash_type: Some("md5".to_string()),
            remote_name: None,
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
            size: Some(123),
            modified: Some(DateTime::<Utc>::from(std::time::SystemTime::UNIX_EPOCH)),
            is_dir: false,
            hash: Some("abc".to_string()),
            hash_type: Some("md5".to_string()),
            remote_name: None,
        };

        export_listing_xlsx(&[entry], &xlsx_path).unwrap();
        assert!(xlsx_path.exists());
    }

    #[test]
    fn test_export_csv_with_remote_name() {
        let dir = tempdir().unwrap();
        let csv_path = dir.path().join("listing.csv");

        let entry = FileEntry {
            path: "Documents/file.txt".to_string(),
            size: Some(42),
            modified: None,
            is_dir: false,
            hash: None,
            hash_type: None,
            remote_name: Some("gdrive".to_string()),
        };

        export_listing(&[entry], &csv_path).unwrap();

        let content = std::fs::read_to_string(&csv_path).unwrap();
        // Should contain the Remote column header and value
        assert!(content.contains("remote"));
        assert!(content.contains("gdrive"));
        assert!(content.contains("Documents/file.txt"));
    }

    #[test]
    fn test_export_xlsx_with_remote_name() {
        let dir = tempdir().unwrap();
        let xlsx_path = dir.path().join("listing.xlsx");

        let entry = FileEntry {
            path: "Photos/pic.jpg".to_string(),
            size: Some(999),
            modified: None,
            is_dir: false,
            hash: None,
            hash_type: None,
            remote_name: Some("onedrive".to_string()),
        };

        export_listing_xlsx(&[entry], &xlsx_path).unwrap();
        assert!(xlsx_path.exists());
    }
}
