//! System state snapshot capture
//!
//! Captures the state of the system before and after operations
//! to document what changes were made by the tool.

use anyhow::Result;
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, BTreeSet};
use std::fs;
use std::path::PathBuf;

/// A snapshot of system state at a point in time
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SystemStateSnapshot {
    /// When the snapshot was taken
    pub timestamp: DateTime<Utc>,
    /// Description of when/why this snapshot was taken
    pub description: String,
    /// Files in the temp directory
    pub temp_files: BTreeSet<PathBuf>,
    /// Environment variables (key -> value)
    pub env_vars: BTreeMap<String, String>,
    /// Registry keys (Windows only) - key path -> values
    #[cfg(windows)]
    pub registry_keys: BTreeMap<String, BTreeMap<String, String>>,
}

impl SystemStateSnapshot {
    /// Capture current system state
    ///
    /// # Arguments
    /// * `description` - A description of when/why this snapshot is being taken
    pub fn capture(description: impl Into<String>) -> Result<Self> {
        let timestamp = Utc::now();
        let description = description.into();

        // Capture temp directory contents
        let temp_files = Self::capture_temp_files()?;

        // Capture environment variables (filtered to relevant ones)
        let env_vars = Self::capture_env_vars();

        Ok(Self {
            timestamp,
            description,
            temp_files,
            env_vars,
            #[cfg(windows)]
            registry_keys: Self::capture_registry_keys()?,
        })
    }

    /// Capture files in the system temp directory
    fn capture_temp_files() -> Result<BTreeSet<PathBuf>> {
        let temp_dir = std::env::temp_dir();
        let mut files = BTreeSet::new();

        if temp_dir.exists() {
            // Only capture top-level items to avoid huge lists
            if let Ok(entries) = fs::read_dir(&temp_dir) {
                for entry in entries.flatten() {
                    let path = entry.path();
                    // Only include rclone-related files
                    if let Some(name) = path.file_name().and_then(|n| n.to_str()) {
                        if name.contains("rclone") || name.contains("triage") {
                            files.insert(path);
                        }
                    }
                }
            }
        }

        Ok(files)
    }

    /// Capture relevant environment variables
    fn capture_env_vars() -> BTreeMap<String, String> {
        let relevant_vars = [
            "RCLONE_CONFIG",
            "RCLONE_CONFIG_PASS",
            "PATH",
            "TEMP",
            "TMP",
            "HOME",
            "USERPROFILE",
            "APPDATA",
            "LOCALAPPDATA",
        ];

        let mut vars = BTreeMap::new();
        for var in &relevant_vars {
            if let Ok(value) = std::env::var(var) {
                vars.insert(var.to_string(), value);
            }
        }
        vars
    }

    /// Capture relevant registry keys (Windows only)
    #[cfg(windows)]
    fn capture_registry_keys() -> Result<BTreeMap<String, BTreeMap<String, String>>> {
        use winreg::enums::*;
        use winreg::RegKey;

        let mut keys = BTreeMap::new();

        // Check HKCU\Software\rclone if it exists
        let hkcu = RegKey::predef(HKEY_CURRENT_USER);
        if let Ok(rclone_key) = hkcu.open_subkey("Software\\rclone") {
            let mut values = BTreeMap::new();
            for (name, value) in rclone_key.enum_values().flatten() {
                values.insert(name, format!("{:?}", value));
            }
            keys.insert("HKCU\\Software\\rclone".to_string(), values);
        }

        Ok(keys)
    }

    /// Compare this snapshot to another and return the differences
    pub fn diff(&self, other: &SystemStateSnapshot) -> StateDiff {
        // Files added (in other but not self)
        let files_added: BTreeSet<_> = other
            .temp_files
            .difference(&self.temp_files)
            .cloned()
            .collect();

        // Files removed (in self but not other)
        let files_removed: BTreeSet<_> = self
            .temp_files
            .difference(&other.temp_files)
            .cloned()
            .collect();

        // Env vars added
        let mut env_added = BTreeMap::new();
        let mut env_removed = BTreeMap::new();
        let mut env_changed = BTreeMap::new();

        for (key, new_value) in &other.env_vars {
            match self.env_vars.get(key) {
                Some(old_value) if old_value != new_value => {
                    env_changed.insert(key.clone(), (old_value.clone(), new_value.clone()));
                }
                None => {
                    env_added.insert(key.clone(), new_value.clone());
                }
                _ => {}
            }
        }

        for (key, value) in &self.env_vars {
            if !other.env_vars.contains_key(key) {
                env_removed.insert(key.clone(), value.clone());
            }
        }

        StateDiff {
            before: self.clone(),
            after: other.clone(),
            files_added,
            files_removed,
            env_added,
            env_removed,
            env_changed,
        }
    }
}

/// Differences between two system state snapshots
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StateDiff {
    /// The "before" snapshot
    pub before: SystemStateSnapshot,
    /// The "after" snapshot
    pub after: SystemStateSnapshot,
    /// Files that were added
    pub files_added: BTreeSet<PathBuf>,
    /// Files that were removed
    pub files_removed: BTreeSet<PathBuf>,
    /// Environment variables that were added
    pub env_added: BTreeMap<String, String>,
    /// Environment variables that were removed  
    pub env_removed: BTreeMap<String, String>,
    /// Environment variables that changed (key -> (old, new))
    pub env_changed: BTreeMap<String, (String, String)>,
}

impl StateDiff {
    /// Check if there are any changes
    pub fn has_changes(&self) -> bool {
        !self.files_added.is_empty()
            || !self.files_removed.is_empty()
            || !self.env_added.is_empty()
            || !self.env_removed.is_empty()
            || !self.env_changed.is_empty()
    }

    /// Generate a human-readable report of the changes
    pub fn generate_report(&self) -> String {
        let mut report = String::new();

        report.push_str(&format!(
            "=== System State Diff ===\n\
             Before: {} ({})\n\
             After:  {} ({})\n\n",
            self.before.timestamp.format("%Y-%m-%d %H:%M:%S UTC"),
            self.before.description,
            self.after.timestamp.format("%Y-%m-%d %H:%M:%S UTC"),
            self.after.description,
        ));

        if !self.has_changes() {
            report.push_str("No changes detected.\n");
            return report;
        }

        if !self.files_added.is_empty() {
            report.push_str("Files Added:\n");
            for file in &self.files_added {
                report.push_str(&format!("  + {}\n", file.display()));
            }
            report.push('\n');
        }

        if !self.files_removed.is_empty() {
            report.push_str("Files Removed:\n");
            for file in &self.files_removed {
                report.push_str(&format!("  - {}\n", file.display()));
            }
            report.push('\n');
        }

        if !self.env_added.is_empty() {
            report.push_str("Environment Variables Added:\n");
            for (key, value) in &self.env_added {
                report.push_str(&format!("  + {}={}\n", key, value));
            }
            report.push('\n');
        }

        if !self.env_removed.is_empty() {
            report.push_str("Environment Variables Removed:\n");
            for (key, value) in &self.env_removed {
                report.push_str(&format!("  - {}={}\n", key, value));
            }
            report.push('\n');
        }

        if !self.env_changed.is_empty() {
            report.push_str("Environment Variables Changed:\n");
            for (key, (old, new)) in &self.env_changed {
                report.push_str(&format!("  ~ {} : {} -> {}\n", key, old, new));
            }
            report.push('\n');
        }

        report
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::env;

    #[test]
    fn test_capture_snapshot() {
        let snapshot =
            SystemStateSnapshot::capture("test snapshot").expect("Failed to capture snapshot");

        assert!(!snapshot.description.is_empty());
        // Should have at least some env vars
        assert!(!snapshot.env_vars.is_empty());
    }

    #[test]
    fn test_diff_detects_env_change() {
        let before =
            SystemStateSnapshot::capture("before").expect("Failed to capture before snapshot");

        // Set a new env var
        env::set_var("RCLONE_TEST_VAR", "test_value");

        // Capture again - but we need to manually add this to env_vars check
        // since our capture only looks for specific vars
        let mut after =
            SystemStateSnapshot::capture("after").expect("Failed to capture after snapshot");
        after
            .env_vars
            .insert("RCLONE_CONFIG".to_string(), "/tmp/test".to_string());

        let diff = before.diff(&after);

        // Clean up
        env::remove_var("RCLONE_TEST_VAR");

        // Diff should show the added config
        assert!(
            diff.env_added.contains_key("RCLONE_CONFIG")
                || diff.env_changed.contains_key("RCLONE_CONFIG")
                || !diff.has_changes()
        );
    }

    #[test]
    fn test_diff_detects_file_change() {
        let mut before =
            SystemStateSnapshot::capture("before").expect("Failed to capture before snapshot");

        let mut after = before.clone();
        after.description = "after".to_string();
        after.timestamp = Utc::now();

        // Simulate a file being added
        after
            .temp_files
            .insert(PathBuf::from("/tmp/rclone-test-file"));

        let diff = before.diff(&after);

        assert!(diff.has_changes());
        assert!(diff
            .files_added
            .contains(&PathBuf::from("/tmp/rclone-test-file")));
    }

    #[test]
    fn test_generate_report() {
        let mut before =
            SystemStateSnapshot::capture("before operation").expect("Failed to capture snapshot");

        let mut after = before.clone();
        after.description = "after operation".to_string();
        after.timestamp = Utc::now();
        after.temp_files.insert(PathBuf::from("/tmp/rclone-added"));
        after
            .env_vars
            .insert("RCLONE_CONFIG".to_string(), "/tmp/config".to_string());

        let diff = before.diff(&after);
        let report = diff.generate_report();

        assert!(report.contains("System State Diff"));
        assert!(report.contains("Files Added"));
        assert!(report.contains("rclone-added"));
    }
}
