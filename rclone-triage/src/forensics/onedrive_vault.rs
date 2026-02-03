//! OneDrive Personal Vault helpers (Windows only).

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

    let bitlocker_disabled = match disable_bitlocker(&mount_point) {
        Ok(()) => true,
        Err(e) => {
            warnings.push(format!(
                "Failed to disable BitLocker: {} (admin rights may be required)",
                e
            ));
            false
        }
    };

    let files = find_vhdx_files(&mount_point)?;
    if files.is_empty() {
        warnings.push(format!(
            "No VHDX files found under {:?}",
            mount_point
        ));
    }

    if !destination.exists() {
        std::fs::create_dir_all(&destination)
            .with_context(|| format!("Failed to create {:?}", destination))?;
    }

    let mut copied = Vec::new();
    for file in files {
        let file_name = file
            .file_name()
            .ok_or_else(|| anyhow::anyhow!("Missing filename for {:?}", file))?;
        let dest_file = destination.join(file_name);
        std::fs::copy(&file, &dest_file)
            .with_context(|| format!("Failed to copy {:?} to {:?}", file, dest_file))?;
        copied.push(dest_file);
    }

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

#[cfg(windows)]
fn disable_bitlocker(mount_point: &Path) -> Result<()> {
    use std::process::Command;
    let mount_str = mount_point.to_string_lossy().to_string();
    let cmd = format!("Disable-BitLocker -MountPoint '{}'", mount_str.replace('\'', "''"));
    let status = Command::new("powershell")
        .args(["-NoProfile", "-NonInteractive", "-Command", &cmd])
        .status()?;
    if !status.success() {
        bail!("Disable-BitLocker failed");
    }
    Ok(())
}

#[cfg(any(test, windows))]
fn find_vhdx_files(root: &Path) -> Result<Vec<PathBuf>> {
    let mut results = Vec::new();
    let mut stack = vec![root.to_path_buf()];

    while let Some(path) = stack.pop() {
        let entries = match std::fs::read_dir(&path) {
            Ok(entries) => entries,
            Err(_) => continue,
        };
        for entry in entries {
            let entry = match entry {
                Ok(entry) => entry,
                Err(_) => continue,
            };
            let path = entry.path();
            if path.is_dir() {
                stack.push(path);
                continue;
            }
            if let Some(ext) = path.extension() {
                if ext.eq_ignore_ascii_case("vhdx") {
                    results.push(path);
                }
            }
        }
    }

    Ok(results)
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
}
