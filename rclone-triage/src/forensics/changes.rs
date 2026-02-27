//! Change tracking for forensic documentation
//!
//! Tracks all changes made to the system during tool execution
//! and provides methods to document them.

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::path::{Path, PathBuf};

/// Types of changes that can be tracked
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub enum ChangeType {
    /// File was created
    FileCreated { path: PathBuf },
    /// Environment variable was set
    EnvVarSet {
        name: String,
        old_value: Option<String>,
    },
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
    /// Description of the change
    pub description: String,
}

/// Tracks all changes made by the tool
#[derive(Debug, Default)]
pub struct ChangeTracker {
    /// All tracked changes in order
    changes: Vec<TrackedChange>,
}

impl ChangeTracker {
    /// Create a new change tracker
    pub fn new() -> Self {
        Self::default()
    }

    /// Track a file creation
    pub fn track_file_created(&mut self, path: impl AsRef<Path>, description: impl Into<String>) {
        self.changes.push(TrackedChange {
            timestamp: Utc::now(),
            change_type: ChangeType::FileCreated {
                path: path.as_ref().to_path_buf(),
            },
            description: description.into(),
        });
    }

    /// Track an environment variable being set
    pub fn track_env_set(&mut self, name: impl Into<String>, description: impl Into<String>) {
        let name = name.into();
        let old_value = std::env::var(&name).ok();

        self.changes.push(TrackedChange {
            timestamp: Utc::now(),
            change_type: ChangeType::EnvVarSet { name, old_value },
            description: description.into(),
        });
    }

    /// Get count of changes
    pub fn change_count(&self) -> usize {
        self.changes.len()
    }

    /// Generate a report of all changes
    pub fn generate_report(&self) -> String {
        let mut report = String::new();

        report.push_str("=== Change Tracking Report ===\n\n");
        report.push_str(&format!("Total changes: {}\n\n", self.change_count()));

        if self.changes.is_empty() {
            report.push_str("No changes tracked.\n");
            return report;
        }

        for (i, change) in self.changes.iter().enumerate() {
            report.push_str(&format!(
                "{}. {} - {}\n   {}\n\n",
                i + 1,
                change.timestamp.format("%H:%M:%S"),
                change.description,
                format_change_type(&change.change_type),
            ));
        }

        report
    }
}

/// Format a change type for display
fn format_change_type(change: &ChangeType) -> String {
    match change {
        ChangeType::FileCreated { path } => {
            format!("Created file: {:?}", path)
        }
        ChangeType::EnvVarSet { name, old_value } => match old_value {
            Some(old) => format!("Set env var: {} (was: {})", name, old),
            None => format!("Set env var: {} (was unset)", name),
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

    #[test]
    fn test_track_file_created() {
        let mut tracker = ChangeTracker::new();
        tracker.track_file_created("/tmp/test", "Created test file");

        assert_eq!(tracker.change_count(), 1);
    }

    #[test]
    fn test_track_env_var() {
        let mut tracker = ChangeTracker::new();
        tracker.track_env_set("TEST_VAR", "Set test variable");

        assert_eq!(tracker.change_count(), 1);
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
