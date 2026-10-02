//! Shared, validated acquisition planning for CLI and TUI callers.

use super::download::{DownloadRequest, DownloadResult};
use super::queue::DownloadQueueEntry;
use crate::utils::path::{checked_join_under, ensure_no_link_components, safe_join_under};
use anyhow::{bail, Context, Result};
use serde::Serialize;
use sha2::{Digest, Sha256};
use std::collections::{BTreeMap, BTreeSet};
use std::path::{Path, PathBuf};

#[derive(Debug, Clone, Serialize)]
pub struct PlannedDownload {
    pub remote_name: String,
    pub path: String,
    pub request: DownloadRequest,
}

#[derive(Debug, Clone, Serialize)]
pub struct AcquisitionPlan {
    pub files: Vec<PlannedDownload>,
    pub skipped_directories: usize,
}

fn filesystem_key(path: &Path) -> String {
    // Conservative on every OS so an acquisition remains portable to Windows.
    path.to_string_lossy().replace('\\', "/").to_lowercase()
}

fn suffixed(path: &Path, identity: &str, attempt: usize) -> PathBuf {
    let digest = hex::encode(Sha256::digest(format!("{identity}\0{attempt}").as_bytes()));
    let stem = path.file_stem().unwrap_or_default().to_string_lossy();
    let name = match path.extension() {
        Some(ext) => format!("{stem}__triage_{}.{}", &digest[..16], ext.to_string_lossy()),
        None => format!("{stem}__triage_{}", &digest[..16]),
    };
    path.with_file_name(name)
}

/// Build the entire plan before creating directories or starting transfers.
/// Directory records are skipped: callers may expand selected directories using
/// their inventory, but execution never recursively copies an unlisted subtree.
pub fn plan_downloads(
    entries: &[DownloadQueueEntry],
    default_remote: &str,
    known_remotes: &[String],
    destination_root: &Path,
) -> Result<AcquisitionPlan> {
    let destination_root = std::path::absolute(destination_root)?;
    ensure_no_link_components(&destination_root)?;
    let known: BTreeSet<&str> = known_remotes.iter().map(String::as_str).collect();
    let mut identities: BTreeMap<(String, String), &DownloadQueueEntry> = BTreeMap::new();
    let mut skipped_directories = 0;
    for entry in entries {
        if entry.is_dir {
            skipped_directories += 1;
            continue;
        }
        let remote = entry
            .remote_name
            .as_deref()
            .unwrap_or(default_remote)
            .trim_end_matches(':');
        if !known.contains(remote) {
            bail!("Queue references unknown remote {:?}", remote);
        }
        if remote.is_empty()
            || remote.starts_with('-')
            || remote.chars().any(char::is_control)
            || remote.contains(['/', '\\', ':'])
            || remote == "."
            || remote == ".."
        {
            bail!("Invalid remote name {:?}", remote);
        }
        if cfg!(windows) && remote.len() == 1 && remote.as_bytes()[0].is_ascii_alphabetic() {
            bail!("Remote {:?} is ambiguous with a Windows drive; use a remote name with more than one letter", remote);
        }
        // Path is an exact relative object key. Do not strip a matching remote
        // prefix: an object itself may legitimately contain that text.
        let path = entry.path.as_str();
        crate::utils::path::validate_remote_path(path)?;
        let identity = (remote.to_string(), path.to_string());
        if let Some(previous) = identities.insert(identity.clone(), entry) {
            if previous.hash != entry.hash
                || previous.hash_type != entry.hash_type
                || previous.size != entry.size
            {
                bail!(
                    "Conflicting queue metadata for {}:{}",
                    identity.0,
                    identity.1
                );
            }
        }
    }

    // Sort identity before assigning names so mapping is independent of queue order.
    let mut used = BTreeSet::new();
    let mut namespace_keys = BTreeSet::new();
    let mut namespaces = BTreeMap::new();
    for (remote, _) in identities.keys() {
        if namespaces.contains_key(remote) {
            continue;
        }
        let mut namespace = safe_join_under(&destination_root, remote).path;
        let base = namespace.clone();
        let mut attempt = 0;
        while !namespace_keys.insert(filesystem_key(&namespace)) {
            namespace = suffixed(&base, remote, attempt);
            attempt += 1;
        }
        namespaces.insert(remote.clone(), namespace);
    }
    let mut directory_keys = BTreeSet::new();
    for (remote, path) in identities.keys() {
        let mapped = checked_join_under(&namespaces[remote], path)?.path;
        for parent in mapped.ancestors().skip(1) {
            directory_keys.insert(filesystem_key(parent));
        }
    }
    let mut files = Vec::with_capacity(identities.len());
    for ((remote, path), entry) in identities {
        let namespace = &namespaces[&remote];
        let base = checked_join_under(namespace, &path)?.path;
        let mut destination = base.clone();
        let mut attempt = 0;
        // Reserve directory names first, so an object "foo" and object
        // "foo/bar" can coexist without file/directory conflicts (e.g. S3 keys).
        loop {
            let key = filesystem_key(&destination);
            if destination
                .ancestors()
                .skip(1)
                .any(|p| used.contains(&filesystem_key(p)))
            {
                bail!(
                    "File/directory destination conflict for {}:{}",
                    remote,
                    path
                );
            }
            ensure_no_link_components(&destination)?;
            if !used.contains(&key) && !directory_keys.contains(&key) && !destination.exists() {
                used.insert(key);
                break;
            }
            destination = suffixed(&base, &format!("{remote}\0{path}"), attempt);
            attempt += 1;
        }
        ensure_no_link_components(&destination)?;
        if destination.is_dir() {
            bail!("Destination is an existing directory: {:?}", destination);
        }
        files.push(PlannedDownload {
            remote_name: remote.clone(),
            path: path.clone(),
            request: DownloadRequest::new_copyto(
                format!("{remote}:{path}"),
                destination.to_string_lossy(),
            )
            .with_hash(entry.hash.clone(), entry.hash_type.clone())
            .with_size(entry.size),
        });
    }
    Ok(AcquisitionPlan {
        files,
        skipped_directories,
    })
}

/// Save the exact plan and outcomes atomically. An empty result slice records a
/// planned acquisition; interrupted transfers must not masquerade as completed.
pub fn write_acquisition_manifest(
    plan: &AcquisitionPlan,
    config_path: &Path,
    results: &[DownloadResult],
    path: &Path,
) -> Result<()> {
    #[derive(Serialize)]
    struct Manifest<'a> {
        schema_version: u32,
        written_at: chrono::DateTime<chrono::Utc>,
        rclone_version: &'static str,
        config_path: &'a Path,
        plan: &'a AcquisitionPlan,
        results: &'a [DownloadResult],
        complete: bool,
    }
    ensure_no_link_components(path)?;
    let parent = path
        .parent()
        .context("Manifest path needs a parent directory")?;
    std::fs::create_dir_all(parent)?;
    let mut temp = tempfile::NamedTempFile::new_in(parent)?;
    serde_json::to_writer_pretty(
        &mut temp,
        &Manifest {
            schema_version: 1,
            written_at: chrono::Utc::now(),
            rclone_version: crate::embedded::RCLONE_VERSION,
            config_path,
            plan,
            results,
            complete: results.len() == plan.files.len()
                && results
                    .iter()
                    .all(|r| r.success && r.integrity != super::download::IntegrityStatus::DryRun),
        },
    )?;
    temp.as_file().sync_all()?;
    temp.persist(path)
        .map_err(|e| e.error)
        .context("Failed to save acquisition manifest")?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    fn entry(remote: &str, path: &str) -> DownloadQueueEntry {
        DownloadQueueEntry {
            path: path.into(),
            remote_name: Some(remote.into()),
            size: None,
            hash: None,
            hash_type: None,
            is_dir: false,
        }
    }
    #[cfg(windows)]
    #[test]
    fn rejects_remote_name_that_rclone_interprets_as_local_drive() {
        let root = tempfile::tempdir().unwrap();
        let error =
            plan_downloads(&[entry("a", "file.txt")], "a", &["a".into()], root.path()).unwrap_err();
        assert!(error.to_string().contains("Windows drive"));
    }
    #[test]
    fn remote_identity_and_windows_collisions_survive_planning() {
        let root = tempfile::tempdir().unwrap();
        let entries = [
            entry("RemoteA", "Report.txt"),
            entry("RemoteA", "report.txt"),
            entry("RemoteB", "report.txt"),
            entry("RemoteA", " report.txt"),
        ];
        let known = vec!["RemoteA".into(), "RemoteB".into()];
        let plan = plan_downloads(&entries, "RemoteA", &known, root.path()).unwrap();
        let destinations: BTreeSet<_> = plan
            .files
            .iter()
            .map(|f| filesystem_key(Path::new(&f.request.destination)))
            .collect();
        assert_eq!(destinations.len(), 4);
        assert!(plan
            .files
            .iter()
            .any(|f| f.request.source == "RemoteB:report.txt"));
        assert!(plan
            .files
            .iter()
            .any(|f| f.request.source == "RemoteA: report.txt"));
        let mut reversed = entries.to_vec();
        reversed.reverse();
        let other = plan_downloads(&reversed, "RemoteA", &known, root.path()).unwrap();
        assert_eq!(
            serde_json::to_value(plan).unwrap(),
            serde_json::to_value(other).unwrap()
        );
    }
    #[test]
    fn rejects_unsafe_or_unknown_sources_and_skips_directories() {
        let root = tempfile::tempdir().unwrap();
        let known = vec!["RemoteA".into()];
        for path in ["../outside", "C:/outside", "/outside"] {
            assert!(
                plan_downloads(&[entry("RemoteA", path)], "RemoteA", &known, root.path()).is_err()
            );
        }
        assert!(
            plan_downloads(&[entry("RemoteB", "safe")], "RemoteA", &known, root.path()).is_err()
        );
        let mut dir = entry("RemoteA", "folder");
        dir.is_dir = true;
        let plan = plan_downloads(
            &[dir, entry("RemoteA", "folder/file")],
            "RemoteA",
            &known,
            root.path(),
        )
        .unwrap();
        assert_eq!(plan.files.len(), 1);
        assert_eq!(plan.skipped_directories, 1);
    }

    #[test]
    fn object_and_directory_prefix_can_coexist() {
        let root = tempfile::tempdir().unwrap();
        let known = vec!["RemoteA".into()];
        let plan = plan_downloads(
            &[entry("RemoteA", "foo"), entry("RemoteA", "foo/bar")],
            "RemoteA",
            &known,
            root.path(),
        )
        .unwrap();
        assert_eq!(plan.files.len(), 2);
        assert_ne!(
            Path::new(&plan.files[0].request.destination),
            Path::new(&plan.files[1].request.destination)
                .parent()
                .unwrap()
        );
    }

    #[test]
    fn prior_acquisition_is_never_overwritten_by_a_new_plan() {
        let root = tempfile::tempdir().unwrap();
        let known = vec!["RemoteA".into()];
        std::fs::create_dir(root.path().join("RemoteA")).unwrap();
        std::fs::write(root.path().join("RemoteA/report.txt"), "prior evidence").unwrap();
        let plan = plan_downloads(
            &[entry("RemoteA", "report.txt")],
            "RemoteA",
            &known,
            root.path(),
        )
        .unwrap();
        assert_ne!(
            Path::new(&plan.files[0].request.destination),
            root.path().join("RemoteA/report.txt")
        );
        assert_eq!(
            std::fs::read_to_string(root.path().join("RemoteA/report.txt")).unwrap(),
            "prior evidence"
        );
    }
}
