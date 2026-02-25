//! Change tracking for forensic documentation
//!
//! Tracks all changes made to the system during tool execution
//! and provides methods to revert changes or document them.

use anyhow::{Context, Result};
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::fs;
use std::path::{Path, PathBuf};

/// Types of changes that can be tracked
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub enum ChangeType {
    /// File was created
    FileCreated { path: PathBuf },
    /// File was modified
    FileModified {
        path: PathBuf,
        backup_path: Option<PathBuf>,
    },
    /// File was deleted
    FileDeleted {
        path: PathBuf,
        backup_path: Option<PathBuf>,
    },
    /// Environment variable was set
    EnvVarSet {
        name: String,
        old_value: Option<String>,
    },
    /// Environment variable was removed
    EnvVarRemoved { name: String, old_value: String },
    /// Registry key was created (Windows)
    #[cfg(windows)]
    RegistryKeyCreated { path: String },
    /// Registry value was set (Windows)
    #[cfg(windows)]
    RegistryValueSet {
        path: String,
        name: String,
        old_value: Option<String>,
    },
}

/// A single tracked change
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TrackedChange {
    /// When the change was made
    pub timestamp: DateTime<Utc>,
    /// What type of change
    pub change_type: ChangeType,
    /// Whether this change was reverted
    pub reverted: bool,
    /// Description of the change
    pub description: String,
}

/// Tracks all changes made by the tool
#[derive(Debug, Default)]
pub struct ChangeTracker {
    /// All tracked changes in order
    changes: Vec<TrackedChange>,
    /// Backup directory for storing original files
    backup_dir: Option<PathBuf>,
}

impl ChangeTracker {
    /// Create a new change tracker
    pub fn new() -> Self {
        Self::default()
    }

    /// Create a change tracker with a backup directory for storing originals
    pub fn with_backup_dir(backup_dir: impl AsRef<Path>) -> Result<Self> {
        let backup_dir = backup_dir.as_ref().to_path_buf();
        fs::create_dir_all(&backup_dir)
            .with_context(|| format!("Failed to create backup directory: {:?}", backup_dir))?;

        Ok(Self {
            changes: Vec::new(),
            backup_dir: Some(backup_dir),
        })
    }

    /// Track a file creation
    pub fn track_file_created(&mut self, path: impl AsRef<Path>, description: impl Into<String>) {
        self.changes.push(TrackedChange {
            timestamp: Utc::now(),
            change_type: ChangeType::FileCreated {
                path: path.as_ref().to_path_buf(),
            },
            reverted: false,
            description: description.into(),
        });
    }

    /// Track a file deletion (optionally backing up the file first)
    pub fn track_file_deleted(
        &mut self,
        path: impl AsRef<Path>,
        description: impl Into<String>,
    ) -> Result<()> {
        let path = path.as_ref();
        let backup_path = if let Some(ref backup_dir) = self.backup_dir {
            if path.exists() {
                let backup = backup_dir.join(format!(
                    "{}-{}",
                    Utc::now().format("%Y%m%d_%H%M%S"),
                    path.file_name().unwrap_or_default().to_string_lossy()
                ));
                fs::copy(path, &backup)?;
                Some(backup)
            } else {
                None
            }
        } else {
            None
        };

        self.changes.push(TrackedChange {
            timestamp: Utc::now(),
            change_type: ChangeType::FileDeleted {
                path: path.to_path_buf(),
                backup_path,
            },
            reverted: false,
            description: description.into(),
        });

        Ok(())
    }

    /// Track an environment variable being set
    pub fn track_env_set(&mut self, name: impl Into<String>, description: impl Into<String>) {
        let name = name.into();
        let old_value = std::env::var(&name).ok();

        self.changes.push(TrackedChange {
            timestamp: Utc::now(),
            change_type: ChangeType::EnvVarSet { name, old_value },
            reverted: false,
            description: description.into(),
        });
    }

    /// Track an environment variable being removed
    pub fn track_env_removed(&mut self, name: impl Into<String>, description: impl Into<String>) {
        let name = name.into();
        if let Ok(old_value) = std::env::var(&name) {
            self.changes.push(TrackedChange {
                timestamp: Utc::now(),
                change_type: ChangeType::EnvVarRemoved { name, old_value },
                reverted: false,
                description: description.into(),
            });
        }
    }

    /// Get all tracked changes
    pub fn changes(&self) -> &[TrackedChange] {
        &self.changes
    }

    /// Get count of changes
    pub fn change_count(&self) -> usize {
        self.changes.len()
    }

    /// Get count of changes that have been reverted
    pub fn reverted_count(&self) -> usize {
        self.changes.iter().filter(|c| c.reverted).count()
    }

    /// Attempt to revert all changes in reverse order
    pub fn revert_all(&mut self) -> Vec<RevertResult> {
        let mut results = Vec::new();

        // Revert in reverse order
        for i in (0..self.changes.len()).rev() {
            if self.changes[i].reverted {
                continue;
            }

            let result = self.revert_change(i);
            results.push(result);
        }

        results
    }

    /// Revert a specific change by index
    fn revert_change(&mut self, index: usize) -> RevertResult {
        let change = &self.changes[index];

        let result = match &change.change_type {
            ChangeType::FileCreated { path } => {
                // Delete the created file
                if path.exists() {
                    match fs::remove_file(path) {
                        Ok(_) => RevertResult::Success(format!("Deleted: {:?}", path)),
                        Err(e) => {
                            RevertResult::Failed(format!("Failed to delete {:?}: {}", path, e))
                        }
                    }
                } else {
                    RevertResult::Success(format!("Already gone: {:?}", path))
                }
            }
            ChangeType::FileDeleted { path, backup_path } => {
                // Restore from backup if available
                if let Some(backup) = backup_path {
                    if backup.exists() {
                        match fs::copy(backup, path) {
                            Ok(_) => RevertResult::Success(format!("Restored: {:?}", path)),
                            Err(e) => {
                                RevertResult::Failed(format!("Failed to restore {:?}: {}", path, e))
                            }
                        }
                    } else {
                        RevertResult::CannotRevert(format!("Backup missing for {:?}", path))
                    }
                } else {
                    RevertResult::CannotRevert(format!("No backup for {:?}", path))
                }
            }
            ChangeType::FileModified { path, backup_path } => {
                // Restore from backup if available
                if let Some(backup) = backup_path {
                    if backup.exists() {
                        match fs::copy(backup, path) {
                            Ok(_) => RevertResult::Success(format!("Restored: {:?}", path)),
                            Err(e) => {
                                RevertResult::Failed(format!("Failed to restore {:?}: {}", path, e))
                            }
                        }
                    } else {
                        RevertResult::CannotRevert(format!("Backup missing for {:?}", path))
                    }
                } else {
                    RevertResult::CannotRevert(format!("No backup for {:?}", path))
                }
            }
            ChangeType::EnvVarSet { name, old_value } => {
                // Restore old value or remove
                match old_value {
                    Some(val) => {
                        std::env::set_var(name, val);
                        RevertResult::Success(format!("Restored env var: {}", name))
                    }
                    None => {
                        std::env::remove_var(name);
                        RevertResult::Success(format!("Removed env var: {}", name))
                    }
                }
            }
            ChangeType::EnvVarRemoved { name, old_value } => {
                std::env::set_var(name, old_value);
                RevertResult::Success(format!("Restored env var: {}", name))
            }
            #[cfg(windows)]
            _ => RevertResult::CannotRevert("Registry revert not implemented".to_string()),
        };

        // Mark as reverted if successful
        if matches!(result, RevertResult::Success(_)) {
            self.changes[index].reverted = true;
        }

        result
    }

    /// Generate a report of all changes
    pub fn generate_report(&self) -> String {
        let mut report = String::new();

        report.push_str("=== Change Tracking Report ===\n\n");
        report.push_str(&format!(
            "Total changes: {}\n\
             Reverted: {}\n\
             Remaining: {}\n\n",
            self.change_count(),
            self.reverted_count(),
            self.change_count() - self.reverted_count(),
        ));

        if self.changes.is_empty() {
            report.push_str("No changes tracked.\n");
            return report;
        }

        for (i, change) in self.changes.iter().enumerate() {
            let status = if change.reverted {
                "[REVERTED]"
            } else {
                "[ACTIVE]"
            };
            report.push_str(&format!(
                "{}. {} {} - {}\n   {}\n\n",
                i + 1,
                change.timestamp.format("%H:%M:%S"),
                status,
                change.description,
                format_change_type(&change.change_type),
            ));
        }

        report
    }
}

/// Result of attempting to revert a change
#[derive(Debug, Clone)]
pub enum RevertResult {
    /// Successfully reverted
    Success(String),
    /// Failed to revert
    Failed(String),
    /// Cannot be automatically reverted (documented only)
    CannotRevert(String),
}

/// Format a change type for display
fn format_change_type(change: &ChangeType) -> String {
    match change {
        ChangeType::FileCreated { path } => {
            format!("Created file: {:?}", path)
        }
        ChangeType::FileModified { path, .. } => {
            format!("Modified file: {:?}", path)
        }
        ChangeType::FileDeleted { path, .. } => {
            format!("Deleted file: {:?}", path)
        }
        ChangeType::EnvVarSet { name, old_value } => match old_value {
            Some(old) => format!("Set env var: {} (was: {})", name, old),
            None => format!("Set env var: {} (was unset)", name),
        },
        ChangeType::EnvVarRemoved { name, old_value } => {
            format!("Removed env var: {} (was: {})", name, old_value)
        }
        #[cfg(windows)]
        ChangeType::RegistryKeyCreated { path } => {
            format!("Created registry key: {}", path)
        }
        #[cfg(windows)]
        ChangeType::RegistryValueSet {
            path,
            name,
            old_value,
        } => match old_value {
            Some(old) => format!("Set registry value: {}\\{} (was: {})", path, name, old),
            None => format!("Set registry value: {}\\{} (was unset)", path, name),
        },
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::tempdir;

    #[test]
    fn test_track_file_created() {
        let mut tracker = ChangeTracker::new();
        tracker.track_file_created("/tmp/test", "Created test file");

        assert_eq!(tracker.change_count(), 1);
        assert_eq!(tracker.reverted_count(), 0);
    }

    #[test]
    fn test_track_env_var() {
        let mut tracker = ChangeTracker::new();
        tracker.track_env_set("TEST_VAR", "Set test variable");

        assert_eq!(tracker.change_count(), 1);
    }

    #[test]
    fn test_revert_file_created() {
        let dir = tempdir().unwrap();
        let test_file = dir.path().join("test.txt");

        // Create file
        fs::write(&test_file, "test content").unwrap();

        let mut tracker = ChangeTracker::new();
        tracker.track_file_created(&test_file, "Created test file");

        // Revert should delete it
        let results = tracker.revert_all();

        assert!(!test_file.exists());
        assert_eq!(tracker.reverted_count(), 1);
        assert!(matches!(results[0], RevertResult::Success(_)));
    }

    #[test]
    fn test_revert_env_var() {
        let mut tracker = ChangeTracker::new();

        // Make sure it doesn't exist first
        std::env::remove_var("TEST_REVERT_VAR_CHANGES");

        // Track the change BEFORE setting the var (this captures old_value as None)
        tracker.track_env_set("TEST_REVERT_VAR_CHANGES", "Set test var");

        // Now set the var
        std::env::set_var("TEST_REVERT_VAR_CHANGES", "new_value");

        // Revert should remove it (since old_value was None)
        tracker.revert_all();

        assert!(std::env::var("TEST_REVERT_VAR_CHANGES").is_err());
    }

    #[test]
    fn test_generate_report() {
        let mut tracker = ChangeTracker::new();
        tracker.track_file_created("/tmp/test1", "First file");
        tracker.track_file_created("/tmp/test2", "Second file");
        tracker.track_env_set("TEST_VAR", "Test variable");

        let report = tracker.generate_report();

        assert!(report.contains("Change Tracking Report"));
        assert!(report.contains("Total changes: 3"));
        assert!(report.contains("First file"));
        assert!(report.contains("Second file"));
    }
}
