//! Case management
//!
//! Defines session metadata and tracking of downloads.

use anyhow::Result;
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::path::PathBuf;

use crate::providers::CloudProvider;

pub mod directory;
pub mod report;

/// Session metadata
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Case {
    /// Session/folder name
    pub name: String,
    pub output_dir: PathBuf,
    pub start_time: DateTime<Utc>,
    pub end_time: Option<DateTime<Utc>>,
    pub providers: Vec<AuthenticatedProvider>,
    pub downloaded_files: Vec<DownloadedFile>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuthenticatedProvider {
    pub provider: CloudProvider,
    pub remote_name: String,
    pub user_info: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DownloadedFile {
    pub path: String,
    pub size: u64,
    pub hash: Option<String>,
    pub hash_type: Option<String>,
}

impl Case {
    /// Create a new session with the given name
    pub fn new(name: impl Into<String>, output_dir: PathBuf) -> Result<Self> {
        let name = name.into();
        let name = if name.is_empty() {
            // Default name: triage-YYYYMMDD-HHMMSS
            Utc::now().format("triage-%Y%m%d-%H%M%S").to_string()
        } else {
            name
        };

        Ok(Self {
            name,
            output_dir,
            start_time: Utc::now(),
            end_time: None,
            providers: Vec::new(),
            downloaded_files: Vec::new(),
        })
    }

    pub fn finalize(&mut self) {
        self.end_time = Some(Utc::now());
    }

    /// Get the session identifier (folder name)
    pub fn session_id(&self) -> &str {
        &self.name
    }

    pub fn add_provider(&mut self, provider: AuthenticatedProvider) {
        self.providers.push(provider);
    }

    pub fn add_download(&mut self, file: DownloadedFile) {
        self.downloaded_files.push(file);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_case_creation() {
        let case = Case::new("my-session", PathBuf::from("/tmp/case")).unwrap();
        assert_eq!(case.session_id(), "my-session");
    }

    #[test]
    fn test_case_default_name() {
        let case = Case::new("", PathBuf::from("/tmp/case")).unwrap();
        assert!(case.session_id().starts_with("triage-"));
    }

    #[test]
    fn test_case_serialize() {
        let case = Case::new("my-session", PathBuf::from("/tmp/case")).unwrap();
        let json = serde_json::to_string(&case).unwrap();
        assert!(json.contains("name"));
    }
}
