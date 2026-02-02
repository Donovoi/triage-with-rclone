//! Case directory structure

use anyhow::{Context, Result};
use std::fs;
use std::path::PathBuf;

use super::Case;

/// Paths for a case directory structure
#[derive(Debug, Clone)]
pub struct CaseDirectories {
    pub base: PathBuf,
    pub logs: PathBuf,
    pub downloads: PathBuf,
    pub listings: PathBuf,
    pub config: PathBuf,
    pub report: PathBuf,
}

/// Create the case directory structure
pub fn create_case_directories(case: &Case) -> Result<CaseDirectories> {
    let base = case.output_dir.join(case.session_id());
    let logs = base.join("logs");
    let downloads = base.join("downloads");
    let listings = base.join("listings");
    let config = base.join("config");
    let report = base.join("forensic_report.txt");

    fs::create_dir_all(&logs).with_context(|| format!("Failed to create {:?}", logs))?;
    fs::create_dir_all(&downloads).with_context(|| format!("Failed to create {:?}", downloads))?;
    fs::create_dir_all(&listings).with_context(|| format!("Failed to create {:?}", listings))?;
    fs::create_dir_all(&config).with_context(|| format!("Failed to create {:?}", config))?;

    Ok(CaseDirectories {
        base,
        logs,
        downloads,
        listings,
        config,
        report,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::case::Case;
    use tempfile::tempdir;

    #[test]
    fn test_create_directories() {
        let dir = tempdir().unwrap();
        let case = Case::new("my-session", dir.path().to_path_buf()).unwrap();
        let dirs = create_case_directories(&case).unwrap();

        assert!(dirs.base.exists());
        assert!(dirs.logs.exists());
        assert!(dirs.downloads.exists());
        assert!(dirs.listings.exists());
        assert!(dirs.config.exists());
        // report is a file path - not created yet
        assert!(!dirs.report.exists());
    }
}
