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

/// Write only the existing finite records. Diagnostic I/O errors are best effort;
/// the caller retains the original cleanup error and never retries cleanup here.
pub fn write_runtime_cleanup_diagnostic(
    writer: &mut impl Write,
    diagnostic: private_fs::CleanupDiagnostic,
) {
    let _ = writeln!(writer, "runtime_cleanup_diagnostic={diagnostic}");
    if let Some(residue) = diagnostic.residue() {
        let _ = writeln!(writer, "runtime_cleanup_residue={residue}");
    }
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
            let closed = match self.path.file_name() {
                Some(leaf) if self.path.parent() == Some(dir_path.as_path()) => {
                    temp_dir.close_with_residue(leaf)
                }
                _ => temp_dir.close(),
            };
            if let Err(error) = closed {
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

    // No executable is created: backend startup fails before any child can run.
    fn absent_test_runtime(root: &Path) -> ExtractedBinary {
        let owned = private_fs::tempdir_in(root, "absent-runtime-").unwrap();
        ExtractedBinary {
            path: owned.path().join("absent-executable"),
            temp_dir: Some(owned),
            owns_file: true,
            cleanup_failed: false,
            tracker: RuntimeTracker::new(),
        }
    }

    #[test]
    fn owned_web_startup_failure_distinguishes_clean_and_uncertain_runtime_cleanup() {
        for retained in [false, true] {
            let root = tempfile::tempdir().unwrap();
            let binary = absent_test_runtime(root.path());
            let directory = binary.path.parent().unwrap().to_path_buf();
            if retained {
                binary.tracker.retain();
            }
            let error = crate::rclone::web::start_web_gui_owned(binary, None, 5592, None, None)
                .err()
                .expect("absent runtime cannot start");
            assert_eq!(
                crate::rclone::lifecycle::cleanup_uncertain(&error),
                retained
            );
            assert_eq!(directory.exists(), retained);
            if !retained {
                assert!(format!("{error:#}").contains("Failed to spawn rclone"));
            }
            // No child was created: this independent test root may remove its fixture.
            root.close().unwrap();
        }
    }

    #[test]
    fn mount_preflight_failure_preserves_typed_cleanup_without_running_a_helper() {
        for retained in [false, true] {
            let root = tempfile::tempdir().unwrap();
            let binary = absent_test_runtime(root.path());
            let directory = binary.path.parent().unwrap().to_path_buf();
            if retained {
                binary.tracker.retain();
            }
            // The first preflight predicate rejects this different path, before
            // FUSE checks, installation, directory creation or any process spawn.
            let manager = crate::rclone::MountManager::new(root.path().join("wrong-executable"))
                .unwrap()
                .with_mount_base(root.path().join("unused-mount"));
            let error = manager
                .mount(binary, "Synthetic", None)
                .err()
                .expect("owner mismatch");
            assert!(format!("{error:#}").contains("Mount runtime does not match its owner"));
            assert_eq!(
                crate::rclone::lifecycle::cleanup_uncertain(&error),
                retained
            );
            assert_eq!(directory.exists(), retained);
            assert!(!root.path().join("unused-mount").exists());
            root.close().unwrap();
        }
    }

    // The production runtime remains extraction-only. These Unix tests construct
    // an owned synthetic script here, where its private fields are accessible.
    #[cfg(unix)]
    fn web_gui_test_runtime(root: &Path) -> ExtractedBinary {
        use std::os::unix::fs::PermissionsExt;
        let owned = private_fs::tempdir_in(root, "web-runtime-").unwrap();
        let path = owned.path().join("mock-rclone");
        private_fs::write(
            &path,
            br#"#!/bin/sh
set -eu
printf '%s\n' "$@" > "$0.args"
printf ready > "$0.ready"
# No descendants, network, browser, or external utilities. The wrapper stops us.
while :; do :; done
"#,
        )
        .unwrap();
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o700)).unwrap();
        ExtractedBinary {
            path,
            temp_dir: Some(owned),
            owns_file: true,
            cleanup_failed: false,
            tracker: RuntimeTracker::new(),
        }
    }

    #[cfg(unix)]
    fn captured_web_gui_args(path: &Path) -> std::io::Result<String> {
        let deadline = std::time::Instant::now() + std::time::Duration::from_secs(3);
        while !path.with_extension("ready").is_file() {
            if std::time::Instant::now() >= deadline {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::TimedOut,
                    "Synthetic child readiness timed out",
                ));
            }
            std::thread::sleep(std::time::Duration::from_millis(10));
        }
        std::fs::read_to_string(path.with_extension("args"))
    }

    #[cfg(unix)]
    #[test]
    fn web_gui_borrowed_runtime_has_exact_args_and_blocks_cleanup_of_live_child() {
        let root = tempfile::tempdir().unwrap();
        let config = root.path().join("synthetic config.conf");
        private_fs::write(&config, b"# synthetic config\n").unwrap();
        let mut binary = web_gui_test_runtime(root.path());
        let path = binary.path().to_path_buf();
        let started = crate::rclone::web::start_web_gui(
            &binary,
            Some(&config),
            5590,
            Some("synthetic-user"),
            Some("synthetic-password"),
        );
        let mut process = match started {
            Ok(process) => process,
            Err(_) => {
                let _ = root.keep();
                panic!("Synthetic Web GUI child startup failed");
            }
        };
        let args = captured_web_gui_args(&path);
        let active_cleanup = binary.cleanup();
        if process.stop().is_err() {
            // Test fixture cleanup must not bypass uncertain child ownership.
            let _ = root.keep();
            panic!("Synthetic Web GUI child shutdown was not confirmed");
        }
        assert!(
            active_cleanup.is_err(),
            "Live child must hold a runtime lease"
        );
        assert_eq!(
            args.unwrap().lines().collect::<Vec<_>>(),
            vec![
                "rcd",
                "--rc-web-gui",
                "--rc-addr",
                "127.0.0.1:5590",
                "--config",
                config.to_str().unwrap(),
                "--rc-user",
                "synthetic-user",
                "--rc-pass",
                "synthetic-password",
            ]
        );
        process.stop().unwrap();
        assert!(
            binary.cleanup().is_err(),
            "Failed cleanup must stay sticky after child exit"
        );
        drop(binary);
        assert!(
            path.is_file(),
            "No Drop fallback may delete retained runtime"
        );
        // The exact child is confirmed stopped; the independent test root owns
        // the intentionally retained synthetic fixture and can now remove it.
        root.close().unwrap();
    }

    #[cfg(unix)]
    #[test]
    fn web_gui_owned_runtime_is_kept_until_confirmed_stop_then_removed() {
        let root = tempfile::tempdir().unwrap();
        let binary = web_gui_test_runtime(root.path());
        let path = binary.path().to_path_buf();
        let directory = path.parent().unwrap().to_path_buf();
        let runner = crate::rclone::RcloneRunner::from_extracted(&binary);
        let mut process =
            match crate::rclone::web::start_web_gui_owned(binary, None, 5591, None, None) {
                Ok(process) => process,
                Err(_) => {
                    let _ = root.keep();
                    panic!("Synthetic Web GUI child startup failed");
                }
            };
        let args = captured_web_gui_args(&path);
        let existed_while_owned = path.is_file();
        if process.stop().is_err() {
            let _ = root.keep();
            panic!("Synthetic Web GUI child shutdown was not confirmed");
        }
        assert!(existed_while_owned);
        assert_eq!(
            args.unwrap().lines().collect::<Vec<_>>(),
            ["rcd", "--rc-web-gui", "--rc-addr", "127.0.0.1:5591"]
        );
        assert!(!directory.exists());
        assert!(
            runner.spawn(&["must-not-run"]).is_err(),
            "Finalized owner must close future spawn admission"
        );
        process.stop().unwrap();
        drop(process);
        assert!(!directory.exists());
    }

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

    #[cfg(windows)]
    #[test]
    fn runtime_sharing_failure_observation_never_retries_after_handle_closes() {
        let root = tempfile::tempdir().unwrap();
        let owned = private_fs::tempdir_in(root.path(), "runtime-canary-").unwrap();
        let path = owned.path().join("rclone.exe");
        private_fs::write(&path, b"synthetic file; never executed").unwrap();
        let blocking = private_fs::open_stable_read(&path).unwrap();
        let mut binary = ExtractedBinary {
            path: path.clone(),
            temp_dir: Some(owned),
            owns_file: true,
            cleanup_failed: false,
            tracker: RuntimeTracker::new(),
        };
        let error = binary.cleanup().unwrap_err();
        let diagnostic = runtime_cleanup_diagnostic(&error);
        assert!(diagnostic.to_string().contains("\"os_code\":32"));
        let residue = diagnostic.residue().unwrap().to_string();
        assert!(residue.contains("\"executable\":\"regular_file\""));
        assert!(!residue.contains("canary"));
        let mut written = Vec::new();
        write_runtime_cleanup_diagnostic(&mut written, diagnostic);
        let written = String::from_utf8(written).unwrap();
        let records: Vec<_> = written.lines().collect();
        assert_eq!(records.len(), 2);
        assert_eq!(
            records[0],
            format!("runtime_cleanup_diagnostic={diagnostic}")
        );
        assert_eq!(records[1], format!("runtime_cleanup_residue={residue}"));
        assert!(records[0].len() <= 112 && records[1].len() <= 320);
        assert!(!written.contains("canary"));
        drop(blocking);
        assert!(binary.cleanup().is_err());
        drop(binary);
        assert_eq!(
            std::fs::read(&path).unwrap(),
            b"synthetic file; never executed"
        );
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
