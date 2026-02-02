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
    env_changes: Vec<(String, Option<String>)>,
}

impl Cleanup {
    pub fn new() -> Self {
        Self::default()
    }

    /// Track a temporary file to remove on cleanup
    pub fn track_file(&mut self, path: impl AsRef<Path>) {
        self.temp_files.insert(path.as_ref().to_path_buf());
    }

    /// Track an environment variable change
    pub fn track_env(&mut self, name: impl Into<String>) {
        let name = name.into();
        let old_value = std::env::var(&name).ok();
        self.env_changes.push((name, old_value));
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
                    .ok();
            }
        }

        Ok(())
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
}
