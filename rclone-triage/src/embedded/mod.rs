//! Embedded binary extraction and management
//!
//! This module handles extracting the embedded rclone.exe to a temporary
//! location, verifying its integrity, and cleaning up after use.

use anyhow::{bail, Context, Result};
use rust_embed::RustEmbed;
use sha2::{Digest, Sha256};
use std::fs::{self, OpenOptions};
use std::io::Write;
use std::path::{Path, PathBuf};
use tempfile::TempDir;

/// Embedded assets (rclone.exe for Windows)
#[derive(RustEmbed)]
#[folder = "assets/"]
pub struct Assets;

/// Expected SHA256 hash of embedded rclone.exe (v1.68.2 windows-amd64)
pub const RCLONE_EXE_SHA256: &str =
    "dcbb5d188358df520b08a584df42a8e76161b30a90a62fefdd0001174d002122";

/// Rclone version embedded
pub const RCLONE_VERSION: &str = "1.68.2";


/// Manages the extracted rclone binary
pub struct ExtractedBinary {
    /// Path to the extracted executable
    pub path: PathBuf,
    /// Temporary directory holding the extracted executable.
    ///
    /// When present, we prefer `TempDir::close()` for cleanup so errors can be detected.
    temp_dir: Option<TempDir>,
    /// Whether this instance owns the file (should clean up)
    owns_file: bool,
}

impl ExtractedBinary {
    /// Extract rclone.exe to a temporary directory
    ///
    /// The binary is extracted to a subdirectory of the system temp folder
    /// with a unique name to avoid conflicts. The SHA256 hash is verified
    /// after extraction.
    ///
    /// # Returns
    /// - `Ok(ExtractedBinary)` with the path to the extracted executable
    /// - `Err` if extraction fails or hash verification fails
    pub fn extract() -> Result<Self> {
        let exe_data =
            Assets::get("rclone.exe").context("rclone.exe not found in embedded assets")?;

        let exe_bytes = exe_data.data.as_ref();

        // Verify embedded bytes first (avoid writing a corrupted binary to disk).
        let mut hasher = Sha256::new();
        hasher.update(exe_bytes);
        let hash = hex::encode(hasher.finalize());
        if hash != RCLONE_EXE_SHA256 {
            bail!(
                "Embedded rclone.exe hash mismatch!\nExpected: {}\nGot: {}",
                RCLONE_EXE_SHA256,
                hash
            );
        }

        // Create a randomized temp directory (avoid predictable paths in world-writable temp dirs).
        let instance_dir = tempfile::Builder::new()
            .prefix("rclone-triage-")
            .tempdir()
            .context("Failed to create temp directory for rclone extraction")?;

        let exe_path = instance_dir.path().join("rclone.exe");

        // Write the binary using exclusive create to avoid clobbering existing files.
        let mut file = OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(&exe_path)
            .with_context(|| format!("Failed to create {:?}", exe_path))?;
        file.write_all(exe_bytes)
            .with_context(|| format!("Failed to write rclone.exe to {:?}", exe_path))?;
        file.sync_all()
            .with_context(|| format!("Failed to sync {:?}", exe_path))?;

        // Make executable on Unix (no-op on Windows)
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let mut perms = fs::metadata(&exe_path)?.permissions();
            perms.set_mode(0o755);
            fs::set_permissions(&exe_path, perms)?;
        }

        Ok(Self {
            path: exe_path,
            temp_dir: Some(instance_dir),
            owns_file: true,
        })
    }

    /// Get the path to the extracted executable
    pub fn path(&self) -> &Path {
        &self.path
    }

    /// Get the parent directory containing the extracted binary
    pub fn temp_dir(&self) -> Option<&Path> {
        self.path.parent()
    }

    /// Manually clean up the extracted binary and its directory
    ///
    /// This is called automatically when the ExtractedBinary is dropped,
    /// but can be called manually for explicit cleanup.
    pub fn cleanup(&mut self) -> Result<()> {
        if !self.owns_file {
            return Ok(());
        }

        if let Some(temp_dir) = self.temp_dir.take() {
            let dir_path = temp_dir.path().to_path_buf();
            temp_dir
                .close()
                .with_context(|| format!("Failed to remove temp directory {:?}", dir_path))?;
            self.owns_file = false;
            return Ok(());
        }

        // Remove the executable
        if self.path.exists() {
            fs::remove_file(&self.path)
                .with_context(|| format!("Failed to remove {:?}", self.path))?;
        }

        // Remove the temp directory if empty
        if let Some(dir) = self.path.parent() {
            if dir.exists() {
                // Try to remove, ignore errors (might not be empty)
                let _ = fs::remove_dir(dir);
            }
        }

        self.owns_file = false;
        Ok(())
    }

    /// Transfer ownership - the file will not be cleaned up when this instance is dropped
    pub fn release_ownership(&mut self) {
        if let Some(temp_dir) = self.temp_dir.take() {
            // Persist the directory on disk.
            let _ = temp_dir.keep();
        }
        self.owns_file = false;
    }

    /// Check if the extracted binary still exists
    pub fn exists(&self) -> bool {
        self.path.exists()
    }
}

impl Drop for ExtractedBinary {
    fn drop(&mut self) {
        if self.owns_file {
            // Best-effort cleanup on drop
            let _ = self.cleanup();
        }
    }
}

/// Verify the embedded rclone binary without extracting
///
/// This performs an in-memory hash verification of the embedded binary.
pub fn verify_embedded_binary() -> Result<()> {
    let exe_data = Assets::get("rclone.exe").context("rclone.exe not found in embedded assets")?;

    let mut hasher = Sha256::new();
    hasher.update(&exe_data.data);
    let hash = hex::encode(hasher.finalize());

    if hash != RCLONE_EXE_SHA256 {
        bail!(
            "Embedded rclone.exe hash mismatch!\nExpected: {}\nGot: {}",
            RCLONE_EXE_SHA256,
            hash
        );
    }

    Ok(())
}

/// Get information about the embedded binary without extracting
pub fn embedded_binary_info() -> Option<EmbeddedBinaryInfo> {
    Assets::get("rclone.exe").map(|content| EmbeddedBinaryInfo {
        size: content.data.len(),
        expected_sha256: RCLONE_EXE_SHA256.to_string(),
        version: RCLONE_VERSION.to_string(),
    })
}

/// Information about the embedded binary
#[derive(Debug, Clone)]
pub struct EmbeddedBinaryInfo {
    pub size: usize,
    pub expected_sha256: String,
    pub version: String,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_embedded_binary_exists() {
        assert!(Assets::get("rclone.exe").is_some());
    }

    #[test]
    fn test_verify_embedded_binary() {
        verify_embedded_binary().expect("Embedded binary verification failed");
    }

    #[test]
    fn test_extract_and_cleanup() {
        let mut binary = ExtractedBinary::extract().expect("Failed to extract binary");
        assert!(binary.exists());

        let path = binary.path().to_path_buf();
        binary.cleanup().expect("Failed to cleanup");

        assert!(!path.exists());
    }

    #[test]
    fn test_embedded_binary_info() {
        let info = embedded_binary_info().expect("Should have embedded binary info");
        assert!(info.size > 0);
        assert_eq!(info.version, RCLONE_VERSION);
    }
}
