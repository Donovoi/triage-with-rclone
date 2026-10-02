//! Case directory structure

use anyhow::{Context, Result};
use std::fs;
use std::io::Write;
use std::path::{Path, PathBuf};

use super::Case;

/// Preserve an imported config and use a uniquely named working copy for token
/// refreshes and generated remotes. Never open the source with write permissions.
pub fn snapshot_config(source: &Path, config_dir: &Path) -> Result<PathBuf> {
    use sha2::{Digest, Sha256};
    crate::utils::path::ensure_no_link_components(config_dir)?;
    let bytes = fs::read(source).with_context(|| format!("Read source config {:?}", source))?;
    fs::create_dir_all(config_dir)?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(config_dir, fs::Permissions::from_mode(0o700))?;
    }
    let mut snapshot = tempfile::Builder::new()
        .prefix("working-")
        .suffix(".conf")
        .tempfile_in(config_dir)?;
    snapshot.write_all(&bytes)?;
    snapshot.as_file().sync_all()?;
    let provenance = serde_json::json!({
        "schema_version": 1,
        "source_path": fs::canonicalize(source)?,
        "source_sha256": hex::encode(Sha256::digest(&bytes)),
        "working_path": snapshot.path(),
        "snapshotted_at": chrono::Utc::now(),
    });
    let metadata_path = snapshot.path().with_extension("provenance.json");
    let mut metadata = fs::OpenOptions::new()
        .create_new(true)
        .write(true)
        .open(metadata_path)?;
    metadata.write_all(&serde_json::to_vec_pretty(&provenance)?)?;
    metadata.sync_all()?;
    let (_, path) = snapshot.keep()?;
    Ok(path)
}

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

    for path in [&base, &logs, &downloads, &listings, &config, &report] {
        crate::utils::path::ensure_no_link_components(path)?;
    }
    fs::create_dir_all(&base)?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(&base, fs::Permissions::from_mode(0o700))?;
    }

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
    fn snapshot_never_modifies_original_or_reuses_working_copy() {
        let dir = tempdir().unwrap();
        let source = dir.path().join("source.conf");
        let original =
            b"[remote]\ntype = local\n[_triage_combined]\ntype = alias\nremote = original\n";
        fs::write(&source, original).unwrap();
        let one = snapshot_config(&source, &dir.path().join("case/config")).unwrap();
        fs::write(&one, "changed by token refresh").unwrap();
        let two = snapshot_config(&source, &dir.path().join("case/config")).unwrap();
        assert_ne!(one, two);
        assert_eq!(fs::read(&source).unwrap(), original);
        assert_eq!(fs::read(two).unwrap(), original);
        let metadata: serde_json::Value =
            serde_json::from_slice(&fs::read(one.with_extension("provenance.json")).unwrap())
                .unwrap();
        assert_eq!(metadata["source_sha256"].as_str().unwrap().len(), 64);
    }

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
