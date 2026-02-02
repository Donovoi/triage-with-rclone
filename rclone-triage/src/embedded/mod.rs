//! Embedded binary extraction and management
//!
//! This module handles extracting the embedded rclone.exe to a temporary
//! location, verifying its integrity, and cleaning up after use.

use anyhow::{bail, Context, Result};
use rust_embed::RustEmbed;
use sha2::{Digest, Sha256};
use std::fs;
use std::path::{Path, PathBuf};
use std::sync::atomic::AtomicBool;

/// Embedded assets (rclone.exe for Windows)
#[derive(RustEmbed)]
#[folder = "assets/"]
pub struct Assets;

/// Expected SHA256 hash of embedded rclone.exe (v1.68.2 windows-amd64)
pub const RCLONE_EXE_SHA256: &str =
    "dcbb5d188358df520b08a584df42a8e76161b30a90a62fefdd0001174d002122";

/// Rclone version embedded
pub const RCLONE_VERSION: &str = "1.68.2";

/// Track whether cleanup has been registered
static CLEANUP_REGISTERED: AtomicBool = AtomicBool::new(false);

/// Manages the extracted rclone binary
pub struct ExtractedBinary {
    /// Path to the extracted executable
    pub path: PathBuf,
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

        // Create unique temp directory for this instance
        let temp_dir = std::env::temp_dir();
        let instance_dir = temp_dir.join(format!("rclone-triage-{}", std::process::id()));

        fs::create_dir_all(&instance_dir)
            .with_context(|| format!("Failed to create temp directory: {:?}", instance_dir))?;

        let exe_path = instance_dir.join("rclone.exe");

        // Write the binary
        fs::write(&exe_path, exe_data.data.as_ref())
            .with_context(|| format!("Failed to write rclone.exe to {:?}", exe_path))?;

        // Verify hash after writing
        let written_data = fs::read(&exe_path)
            .with_context(|| format!("Failed to read back {:?} for verification", exe_path))?;

        let mut hasher = Sha256::new();
        hasher.update(&written_data);
        let hash = hex::encode(hasher.finalize());

        if hash != RCLONE_EXE_SHA256 {
            // Clean up the corrupted file
            let _ = fs::remove_file(&exe_path);
            let _ = fs::remove_dir(&instance_dir);
            bail!(
                "SHA256 hash mismatch after extraction!\nExpected: {}\nGot: {}",
                RCLONE_EXE_SHA256,
                hash
            );
        }

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
