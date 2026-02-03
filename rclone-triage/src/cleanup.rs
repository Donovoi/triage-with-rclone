//! Cleanup utilities
//!
//! Tracks temporary files and environment changes and restores them when done.

use anyhow::{Context, Result};
use std::collections::BTreeSet;
use std::path::{Path, PathBuf};

/// Cleanup manager
#[derive(Debug, Default, Clone)]
pub struct Cleanup {
    temp_files: BTreeSet<PathBuf>,
    temp_dirs: BTreeSet<PathBuf>,
    env_changes: Vec<(String, Option<String>)>,
    unrevertable: Vec<String>,
}

impl Cleanup {
    pub fn new() -> Self {
        Self::default()
    }

    /// Track a temporary file to remove on cleanup
    pub fn track_file(&mut self, path: impl AsRef<Path>) {
        self.temp_files.insert(path.as_ref().to_path_buf());
    }

    /// Track a temporary directory to remove on cleanup
    pub fn track_dir(&mut self, path: impl AsRef<Path>) {
        self.temp_dirs.insert(path.as_ref().to_path_buf());
    }

    /// Track an environment variable change
    pub fn track_env(&mut self, name: impl Into<String>) {
        let name = name.into();
        let old_value = std::env::var(&name).ok();
        self.track_env_value(name, old_value);
    }

    /// Track an environment variable change with a known original value
    pub fn track_env_value(&mut self, name: impl Into<String>, old_value: Option<String>) {
        let name = name.into();
        if self.env_changes.iter().any(|(existing, _)| existing == &name) {
            return;
        }
        self.env_changes.push((name, old_value));
    }

    /// Record a change that cannot be automatically reverted
    pub fn note_unrevertable(&mut self, description: impl Into<String>) {
        self.unrevertable.push(description.into());
    }

    /// Execute cleanup
    pub fn execute(&mut self) -> Result<()> {
        // Restore env vars
        for (name, old_value) in self.env_changes.drain(..) {
            match old_value {
                Some(val) => std::env::set_var(&name, val),
                None => std::env::remove_var(&name),
            }
        }

        // Remove tracked files
        let paths: Vec<PathBuf> = self.temp_files.iter().cloned().collect();
        self.temp_files.clear();
        for path in paths {
            if path.exists() {
                std::fs::remove_file(&path)
                    .with_context(|| format!("Failed to remove {:?}", path))
                    .map_err(|e| {
                        self.unrevertable
                            .push(format!("Failed to remove file {:?}: {}", path, e));
                        e
                    })
                    .ok();
            }
        }

        // Remove tracked directories
        let dirs: Vec<PathBuf> = self.temp_dirs.iter().cloned().collect();
        self.temp_dirs.clear();
        for dir in dirs {
            if dir.exists() {
                std::fs::remove_dir_all(&dir)
                    .with_context(|| format!("Failed to remove {:?}", dir))
                    .map_err(|e| {
                        self.unrevertable
                            .push(format!("Failed to remove dir {:?}: {}", dir, e));
                        e
                    })
                    .ok();
            }
        }

        Ok(())
    }

    /// Generate a cleanup report for unrevertable changes
    pub fn cleanup_report(&self) -> Option<String> {
        if self.unrevertable.is_empty() {
            return None;
        }

        let mut report = String::new();
        report.push_str("=== Cleanup Report ===\n\n");
        report.push_str("Unrevertable changes:\n");
        for item in &self.unrevertable {
            report.push_str(&format!("- {}\n", item));
        }
        Some(report)
    }

    /// Create a shallow clone for signal handlers
    pub fn clone_for_signal(&self) -> Self {
        self.clone()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::tempdir;

    #[test]
    fn test_cleanup_files() {
        let dir = tempdir().unwrap();
        let file = dir.path().join("temp.txt");
        std::fs::write(&file, "test").unwrap();

        let mut cleanup = Cleanup::new();
        cleanup.track_file(&file);
        cleanup.execute().unwrap();

        assert!(!file.exists());
    }

    #[test]
    fn test_cleanup_env() {
        std::env::remove_var("TEST_CLEANUP_ENV");
        let mut cleanup = Cleanup::new();
        cleanup.track_env("TEST_CLEANUP_ENV");
        std::env::set_var("TEST_CLEANUP_ENV", "value");
        cleanup.execute().unwrap();
        assert!(std::env::var("TEST_CLEANUP_ENV").is_err());
    }

    #[test]
    fn test_cleanup_env_tracks_first_value() {
        std::env::set_var("TEST_CLEANUP_ENV_FIRST", "original");
        let mut cleanup = Cleanup::new();
        cleanup.track_env_value(
            "TEST_CLEANUP_ENV_FIRST",
            std::env::var("TEST_CLEANUP_ENV_FIRST").ok(),
        );
        std::env::set_var("TEST_CLEANUP_ENV_FIRST", "changed");
        cleanup.track_env_value(
            "TEST_CLEANUP_ENV_FIRST",
            std::env::var("TEST_CLEANUP_ENV_FIRST").ok(),
        );

        cleanup.execute().unwrap();

        assert_eq!(
            std::env::var("TEST_CLEANUP_ENV_FIRST").ok(),
            Some("original".to_string())
        );
        std::env::remove_var("TEST_CLEANUP_ENV_FIRST");
    }

    #[test]
    fn test_cleanup_dirs() {
        let dir = tempdir().unwrap();
        let sub = dir.path().join("nested");
        std::fs::create_dir_all(&sub).unwrap();
        std::fs::write(sub.join("file.txt"), "test").unwrap();

        let mut cleanup = Cleanup::new();
        cleanup.track_dir(&sub);
        cleanup.execute().unwrap();

        assert!(!sub.exists());
    }

    #[test]
    fn test_cleanup_report() {
        let mut cleanup = Cleanup::new();
        cleanup.note_unrevertable("Could not remove temp file".to_string());
        let report = cleanup.cleanup_report().unwrap();
        assert!(report.contains("Cleanup Report"));
        assert!(report.contains("Could not remove temp file"));
    }
}
