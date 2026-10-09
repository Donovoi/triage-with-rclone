//! Case directory structure

use anyhow::{Context, Result};
use std::fs;
use std::io::Write;
use std::path::{Path, PathBuf};

use super::Case;
use crate::utils::private_fs;

/// Preserve an imported config and use a uniquely named working copy for token
/// refreshes and generated remotes. Never open the source with write permissions.
pub fn snapshot_config(source: &Path, config_dir: &Path) -> Result<PathBuf> {
    use sha2::{Digest, Sha256};
    crate::utils::path::ensure_no_link_components(config_dir)?;
    let bytes = fs::read(source).with_context(|| format!("Read source config {:?}", source))?;
    private_fs::create_dir_all(config_dir)?;
    private_fs::verify_directory(config_dir)?;
    crate::utils::path::ensure_no_link_components(config_dir)?;
    // tempfile's Windows keep() uses SetFileAttributesW directly. Canonicalize
    // the existing parent before creation so the snapshot and its provenance
    // share an extended-length path, including cases beyond MAX_PATH.
    let config_dir = fs::canonicalize(config_dir)?;
    let mut snapshot = private_fs::tempfile_in(&config_dir, "working-", ".conf")?;
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
    let mut metadata = private_fs::create_new(&metadata_path)?;
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
    private_fs::create_dir_all(&base)?;
    private_fs::verify_directory(&base)?;

    private_fs::create_dir_all(&logs).with_context(|| format!("Failed to create {:?}", logs))?;
    private_fs::create_dir_all(&downloads)
        .with_context(|| format!("Failed to create {:?}", downloads))?;
    private_fs::create_dir_all(&listings)
        .with_context(|| format!("Failed to create {:?}", listings))?;
    private_fs::create_dir_all(&config)
        .with_context(|| format!("Failed to create {:?}", config))?;
    for directory in [&logs, &downloads, &listings, &config] {
        private_fs::verify_directory(directory)?;
    }

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

    #[cfg(windows)]
    #[test]
    fn snapshot_at_long_path_preserves_source_and_exact_provenance() {
        use sha2::{Digest, Sha256};
        let dir = tempdir().unwrap();
        let source = dir.path().join("source.conf");
        let original = b"[Synthetic]\ntype = local\n";
        fs::write(&source, original).unwrap();
        let mut config_dir = dir.path().join("long-case");
        while config_dir.as_os_str().to_string_lossy().len() < 280 {
            config_dir = config_dir.join("synthetic-parent-component-0123456789");
        }
        config_dir = config_dir.join("config");

        let first = snapshot_config(&source, &config_dir).unwrap();
        assert_eq!(
            first.parent().unwrap(),
            fs::canonicalize(&config_dir).unwrap()
        );
        assert_eq!(fs::read(&first).unwrap(), original);
        fs::write(&first, b"changed only in the working copy").unwrap();
        let second = snapshot_config(&source, &config_dir).unwrap();
        assert_ne!(first, second);
        assert_eq!(
            fs::read(&first).unwrap(),
            b"changed only in the working copy"
        );
        assert_eq!(fs::read(&second).unwrap(), original);
        assert_eq!(fs::read(&source).unwrap(), original);
        for snapshot in [&first, &second] {
            let metadata: serde_json::Value = serde_json::from_slice(
                &fs::read(snapshot.with_extension("provenance.json")).unwrap(),
            )
            .unwrap();
            assert_eq!(metadata["schema_version"], 1);
            assert_eq!(
                metadata["source_sha256"],
                hex::encode(Sha256::digest(original))
            );
            assert_eq!(
                fs::canonicalize(metadata["source_path"].as_str().unwrap()).unwrap(),
                fs::canonicalize(&source).unwrap()
            );
            assert_eq!(
                fs::canonicalize(metadata["working_path"].as_str().unwrap()).unwrap(),
                fs::canonicalize(snapshot).unwrap()
            );
        }
        assert_eq!(fs::read_dir(&config_dir).unwrap().count(), 4);
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
