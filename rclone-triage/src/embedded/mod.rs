//! Embedded binary extraction and management
//!
//! This module handles extracting the embedded rclone.exe to a temporary
//! location, verifying its integrity, and cleaning up after use.

use crate::rclone::runtime::RuntimeTracker;
use crate::utils::private_fs::{self, PrivateTempDir};
use anyhow::{bail, Context, Result};
use rust_embed::RustEmbed;
use sha2::{Digest, Sha256};
use std::io::Write;
use std::path::{Path, PathBuf};
use std::sync::Arc;

/// Embedded assets (rclone.exe for Windows)
#[derive(RustEmbed)]
#[folder = "assets/"]
pub struct Assets;

/// Expected SHA256 hash from the repository runtime manifest.
pub const RCLONE_EXE_SHA256: &str = env!("TRIAGE_RCLONE_EXE_SHA256");

/// Rclone version embedded
pub const RCLONE_VERSION: &str = env!("TRIAGE_RCLONE_VERSION");

/// Return only finite cleanup metadata, never formatted error messages or paths.
pub fn runtime_cleanup_diagnostic(error: &anyhow::Error) -> private_fs::CleanupDiagnostic {
    error
        .chain()
        .find_map(|cause| {
            cause
                .downcast_ref::<std::io::Error>()
                .and_then(private_fs::cleanup_diagnostic)
        })
        .unwrap_or_else(private_fs::CleanupDiagnostic::ownership_unavailable)
}

/// Manages the extracted rclone binary
pub struct ExtractedBinary {
    /// Path to the extracted executable
    pub path: PathBuf,
    /// Temporary directory holding the extracted executable.
    ///
    /// Cleanup uses this identity guard; it never falls back to an unpinned path.
    temp_dir: Option<PrivateTempDir>,
    /// Whether this instance owns the file (should clean up)
    owns_file: bool,
    cleanup_failed: bool,
    tracker: Arc<RuntimeTracker>,
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
        let instance_dir = private_fs::tempdir_in(std::env::temp_dir(), "rclone-triage-")
            .context("Failed to create temp directory for rclone extraction")?;

        let exe_path = instance_dir.path().join("rclone.exe");

        // Write the binary using exclusive create to avoid clobbering existing files.
        let mut file = private_fs::create_new(&exe_path)
            .with_context(|| format!("Failed to create {:?}", exe_path))?;
        file.write_all(exe_bytes)
            .with_context(|| format!("Failed to write rclone.exe to {:?}", exe_path))?;
        file.sync_all()
            .with_context(|| format!("Failed to sync {:?}", exe_path))?;

        // Make executable on Unix (no-op on Windows)
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let mut perms = std::fs::metadata(&exe_path)?.permissions();
            perms.set_mode(0o755);
            std::fs::set_permissions(&exe_path, perms)?;
        }

        Ok(Self {
            path: exe_path,
            temp_dir: Some(instance_dir),
            owns_file: true,
            cleanup_failed: false,
            tracker: RuntimeTracker::new(),
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

    pub(crate) fn tracker(&self) -> Arc<RuntimeTracker> {
        self.tracker.clone()
    }

    /// Keep exact owned material after an uncertain child or drain outcome.
    /// This permanently closes the spawn gate and is never a deletion retry.
    pub fn retain(&mut self) {
        self.tracker.retain();
        if let Some(directory) = self.temp_dir.take() {
            directory.keep();
        }
        self.owns_file = false;
        self.cleanup_failed = true;
    }

    /// Manually clean up the extracted binary and its directory
    ///
    /// This is called automatically when the ExtractedBinary is dropped,
    /// but can be called manually for explicit cleanup.
    pub fn cleanup(&mut self) -> Result<()> {
        if self.cleanup_failed {
            bail!("Earlier runtime cleanup failed; retained paths require inspection");
        }
        if let Err(error) = self.tracker.seal() {
            self.retain();
            return Err(error).context("Runtime exit/drain ownership is unconfirmed; retained");
        }
        if !self.owns_file {
            return Ok(());
        }

        if let Some(temp_dir) = self.temp_dir.take() {
            let dir_path = temp_dir.path().to_path_buf();
            // close consumes the guard even on failure. Never let Drop retry
            // against a pathname whose identity may have caused that failure.
            self.owns_file = false;
            if let Err(error) = temp_dir.close() {
                self.cleanup_failed = true;
                return Err(error)
                    .with_context(|| format!("Failed to remove temp directory {:?}", dir_path));
            }
            return Ok(());
        }
        self.owns_file = false;
        self.cleanup_failed = true;
        bail!("Runtime cleanup ownership guard is missing; retained for inspection")
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn active_runtime_lease_retains_exact_tree_and_never_reopens_admission() {
        let root = tempfile::tempdir().unwrap();
        let owned = private_fs::tempdir_in(root.path(), "runtime-").unwrap();
        let path = owned.path().join("rclone.exe");
        private_fs::write(&path, b"synthetic runtime").unwrap();
        let tracker = RuntimeTracker::new();
        let lease = tracker.reserve().unwrap();
        let mut binary = ExtractedBinary {
            path: path.clone(),
            temp_dir: Some(owned),
            owns_file: true,
            cleanup_failed: false,
            tracker: tracker.clone(),
        };
        let runner = crate::rclone::RcloneRunner::from_extracted(&binary);
        assert!(binary.cleanup().is_err());
        lease.complete();
        assert!(binary.cleanup().is_err());
        assert!(runner.spawn(&["version"]).is_err());
        drop(binary);
        assert_eq!(std::fs::read(path).unwrap(), b"synthetic runtime");
    }

    #[test]
    fn failed_runtime_cleanup_never_retries_a_replaced_directory() {
        let root = tempfile::tempdir().unwrap();
        let owned = private_fs::tempdir_in(root.path(), "runtime-").unwrap();
        let original_path = owned.path().to_owned();
        let moved = root.path().join("original-runtime");
        private_fs::write(original_path.join("rclone.exe"), b"synthetic runtime").unwrap();
        std::fs::rename(&original_path, &moved).unwrap();
        private_fs::create_dir(&original_path).unwrap();
        private_fs::write(original_path.join("rclone.exe"), b"unrelated replacement").unwrap();
        let mut binary = ExtractedBinary {
            path: original_path.join("rclone.exe"),
            temp_dir: Some(owned),
            owns_file: true,
            cleanup_failed: false,
            tracker: RuntimeTracker::new(),
        };
        assert!(binary.cleanup().is_err());
        assert!(binary.cleanup().is_err());
        drop(binary);
        assert_eq!(
            std::fs::read(original_path.join("rclone.exe")).unwrap(),
            b"unrelated replacement"
        );
        assert_eq!(
            std::fs::read(moved.join("rclone.exe")).unwrap(),
            b"synthetic runtime"
        );
    }

    #[test]
    fn test_embedded_binary_exists() {
        assert!(Assets::get("rclone.exe").is_some());
    }

    #[test]
    fn wrapped_cleanup_io_error_keeps_stage_without_exposing_context_or_path() {
        let root = tempfile::tempdir().unwrap();
        let owned = private_fs::tempdir_in(root.path(), "private-canary-").unwrap();
        std::fs::remove_dir(owned.path()).unwrap();
        let io_error = owned.close().unwrap_err();
        let expected = private_fs::cleanup_diagnostic(&io_error)
            .unwrap()
            .to_string();
        let error = anyhow::Error::new(io_error).context("private-canary/context");
        let diagnostic = runtime_cleanup_diagnostic(&error).to_string();
        assert_eq!(diagnostic, expected);
        assert!(diagnostic.starts_with("{\"stage\":\"open_root\",\"kind\":\"not_found\","));
        assert!(!diagnostic.contains("canary"));
        assert!(!diagnostic.contains(root.path().to_string_lossy().as_ref()));
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
}
