//! OneDrive Personal Vault helpers (Windows only).

#[cfg(any(test, windows))]
use anyhow::Context;
use anyhow::{bail, Result};
use std::path::{Path, PathBuf};

#[derive(Debug, Clone)]
pub struct OneDriveVaultResult {
    pub mount_point: PathBuf,
    pub destination: PathBuf,
    pub copied_files: Vec<PathBuf>,
    pub bitlocker_disabled: bool,
    pub warnings: Vec<String>,
}

#[cfg(windows)]
pub fn open_onedrive_vault(
    mount_point: impl AsRef<Path>,
    destination: impl AsRef<Path>,
    wait_for_user: bool,
) -> Result<OneDriveVaultResult> {
    let mount_point = mount_point.as_ref().to_path_buf();
    let destination = destination.as_ref().to_path_buf();
    let mut warnings = Vec::new();

    trigger_vault_unlock()?;

    if wait_for_user {
        println!("Please complete the Windows Hello authentication.");
        println!("Press Enter after the vault is unlocked...");
        let mut input = String::new();
        let _ = std::io::stdin().read_line(&mut input);
    }

    if !mount_point.exists() {
        bail!(
            "Mount point {:?} does not exist. Ensure the vault is mounted.",
            mount_point
        );
    }

    // Acquisition must never decrypt or remove protectors from a source volume.
    // Windows Hello unlocks the vault; BitLocker policy remains untouched.
    let bitlocker_disabled = false;

    let files = find_vhdx_files(&mount_point)?;
    if files.is_empty() {
        warnings.push(format!("No VHDX files found under {:?}", mount_point));
    }

    let copied = copy_vhdx_files(&mount_point, &destination, &files)?;

    Ok(OneDriveVaultResult {
        mount_point,
        destination,
        copied_files: copied,
        bitlocker_disabled,
        warnings,
    })
}

#[cfg(not(windows))]
pub fn open_onedrive_vault(
    _mount_point: impl AsRef<Path>,
    _destination: impl AsRef<Path>,
    _wait_for_user: bool,
) -> Result<OneDriveVaultResult> {
    bail!("OneDrive Personal Vault is only supported on Windows");
}

#[cfg(windows)]
fn trigger_vault_unlock() -> Result<()> {
    use std::process::Command;
    let status = Command::new("powershell")
        .args([
            "-NoProfile",
            "-NonInteractive",
            "-Command",
            "Start-Process 'odopen://unlockVault/?accounttype=personal'",
        ])
        .status()?;
    if !status.success() {
        bail!("Failed to trigger OneDrive Vault unlock");
    }
    Ok(())
}

#[cfg(any(test, windows))]
fn find_vhdx_files(root: &Path) -> Result<Vec<PathBuf>> {
    let mut results = Vec::new();
    let mut stack = vec![root.to_path_buf()];

    while let Some(path) = stack.pop() {
        let entries = std::fs::read_dir(&path)
            .with_context(|| format!("Cannot inventory vault directory {:?}", path))?;
        for entry in entries {
            let entry = entry?;
            let path = entry.path();
            let metadata = std::fs::symlink_metadata(&path)?;
            let is_link = metadata.file_type().is_symlink();
            #[cfg(windows)]
            let is_link = {
                use std::os::windows::fs::MetadataExt;
                is_link || metadata.file_attributes() & 0x400 != 0
            };
            if is_link {
                bail!(
                    "Vault inventory contains a link or reparse point: {:?}",
                    path
                );
            }
            if metadata.is_dir() {
                stack.push(path);
                continue;
            }
            if metadata.is_file()
                && path
                    .extension()
                    .is_some_and(|ext| ext.eq_ignore_ascii_case("vhdx"))
            {
                results.push(path);
            }
        }
    }

    results.sort();
    Ok(results)
}

#[cfg(any(test, windows))]
fn copy_vhdx_files(root: &Path, destination: &Path, files: &[PathBuf]) -> Result<Vec<PathBuf>> {
    use crate::utils::path::ensure_no_link_components;
    use std::fs::OpenOptions;
    ensure_no_link_components(destination)?;
    // Resolve the explicitly selected mount point, but do not follow links found
    // inside it. Keep output outside the source to avoid collecting prior copies.
    let source_root = std::fs::canonicalize(root)?;
    let mut existing = std::path::absolute(destination)?;
    let mut missing = Vec::new();
    while !existing.exists() {
        missing.push(
            existing
                .file_name()
                .context("Invalid vault destination")?
                .to_owned(),
        );
        existing = existing
            .parent()
            .context("Invalid vault destination root")?
            .to_owned();
    }
    let mut output_root = std::fs::canonicalize(existing)?;
    for part in missing.into_iter().rev() {
        output_root.push(part);
    }
    if output_root.starts_with(&source_root) {
        bail!("Vault destination must be outside the source mount point");
    }
    let mut copies = Vec::with_capacity(files.len());
    for source in files {
        let relative = source
            .strip_prefix(root)
            .context("Vault source escaped its root")?;
        let target = output_root.join(relative);
        ensure_no_link_components(&target)?;
        if target.exists() {
            bail!(
                "Refusing to overwrite existing vault evidence: {:?}",
                target
            );
        }
        copies.push((source, target));
    }
    // Complete preflight before writing; exclusive creation also prevents a
    // newly appearing file from being overwritten between planning and copying.
    for (source, target) in &copies {
        if let Some(parent) = target.parent() {
            std::fs::create_dir_all(parent)?;
        }
        ensure_no_link_components(target)?;
        let mut input = std::fs::File::open(source)?;
        let mut output = OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(target)?;
        std::io::copy(&mut input, &mut output)
            .with_context(|| format!("Failed to copy {:?} to {:?}", source, target))?;
        output.sync_all()?;
    }
    Ok(copies.into_iter().map(|(_, target)| target).collect())
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::tempdir;

    #[test]
    fn test_find_vhdx_files() {
        let dir = tempdir().expect("tempdir");
        let root = dir.path();
        std::fs::write(root.join("a.vhdx"), b"one").unwrap();
        std::fs::write(root.join("b.txt"), b"two").unwrap();
        std::fs::create_dir_all(root.join("nested")).unwrap();
        std::fs::write(root.join("nested").join("c.vhdx"), b"three").unwrap();

        let files = find_vhdx_files(root).unwrap();
        assert_eq!(files.len(), 2);
    }

    #[test]
    fn vault_copy_preserves_nested_identity_and_never_overwrites() {
        let root = tempdir().unwrap();
        let output = tempdir().unwrap();
        std::fs::create_dir(root.path().join("nested")).unwrap();
        std::fs::write(root.path().join("image.vhdx"), b"first").unwrap();
        std::fs::write(root.path().join("nested/image.vhdx"), b"second").unwrap();
        let files = find_vhdx_files(root.path()).unwrap();
        let copied = copy_vhdx_files(root.path(), output.path(), &files).unwrap();
        assert_eq!(copied.len(), 2);
        assert_eq!(
            std::fs::read(output.path().join("image.vhdx")).unwrap(),
            b"first"
        );
        assert_eq!(
            std::fs::read(output.path().join("nested/image.vhdx")).unwrap(),
            b"second"
        );
        std::fs::write(root.path().join("image.vhdx"), b"changed source").unwrap();
        assert!(copy_vhdx_files(root.path(), output.path(), &files).is_err());
        assert_eq!(
            std::fs::read(output.path().join("image.vhdx")).unwrap(),
            b"first"
        );
    }

    #[test]
    fn unreadable_or_missing_vault_inventory_is_not_silently_complete() {
        let root = tempdir().unwrap();
        assert!(find_vhdx_files(&root.path().join("missing")).is_err());
        assert!(copy_vhdx_files(root.path(), &root.path().join("new/output"), &[]).is_err());
    }
}
