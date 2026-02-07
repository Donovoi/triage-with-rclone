//! Case management
//!
//! Defines session metadata and tracking of downloads.

use anyhow::Result;
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::path::PathBuf;

pub mod directory;
pub mod report;

fn is_windows_reserved_name(name: &str) -> bool {
    // Windows device names are reserved (case-insensitive), even with extensions (e.g. CON.txt).
    // See: https://learn.microsoft.com/windows/win32/fileio/naming-a-file
    let upper = name.to_ascii_uppercase();
    matches!(
        upper.as_str(),
        "CON"
            | "PRN"
            | "AUX"
            | "NUL"
            | "COM1"
            | "COM2"
            | "COM3"
            | "COM4"
            | "COM5"
            | "COM6"
            | "COM7"
            | "COM8"
            | "COM9"
            | "LPT1"
            | "LPT2"
            | "LPT3"
            | "LPT4"
            | "LPT5"
            | "LPT6"
            | "LPT7"
            | "LPT8"
            | "LPT9"
    )
}

fn sanitize_session_id(input: &str) -> String {
    let trimmed = input.trim();
    if trimmed.is_empty() {
        return String::new();
    }

    let mut out = String::with_capacity(trimmed.len());
    for c in trimmed.chars() {
        // Cross-platform and Windows filename restrictions.
        let invalid = c.is_control() || matches!(c, '<' | '>' | ':' | '"' | '/' | '\\' | '|' | '?' | '*');
        if invalid {
            out.push('_');
        } else {
            out.push(c);
        }
    }

    // Windows: trailing dots/spaces are not allowed. Also strip outer whitespace.
    let mut out = out.trim().trim_end_matches(['.', ' ']).to_string();

    // Avoid "." and ".." as path components.
    if out == "." || out == ".." {
        out = "_".to_string();
    }

    // Avoid reserved device names (check the stem, ignoring extensions).
    let stem = out.split('.').next().unwrap_or(&out);
    if is_windows_reserved_name(stem) {
        out = format!("_{}", out);
    }

    // Bound length to reduce path-length issues.
    const MAX_LEN: usize = 120;
    if out.len() > MAX_LEN {
        out.truncate(MAX_LEN);
        out = out.trim_end_matches(['.', ' ']).to_string();
    }

    out
}

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
    pub provider_id: String,
    pub provider_name: String,
    pub remote_name: String,
    pub user_info: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DownloadedFile {
    pub path: String,
    pub size: u64,
    pub hash: Option<String>,
    pub hash_type: Option<String>,
    pub hash_verified: Option<bool>,
    pub hash_error: Option<String>,
}

impl Case {
    /// Create a new session with the given name
    pub fn new(name: impl Into<String>, output_dir: PathBuf) -> Result<Self> {
        let name = sanitize_session_id(&name.into());
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
    fn test_case_name_sanitizes_traversal_and_separators() {
        let case = Case::new("../evil\\name", PathBuf::from("/tmp/case")).unwrap();
        let id = case.session_id();
        assert_ne!(id, ".");
        assert_ne!(id, "..");
        assert!(!id.contains('/'));
        assert!(!id.contains('\\'));
    }

    #[test]
    fn test_case_name_sanitizes_windows_reserved_names() {
        let case = Case::new("CON.txt", PathBuf::from("/tmp/case")).unwrap();
        assert_ne!(case.session_id().to_ascii_uppercase(), "CON.TXT");
        assert!(
            case.session_id().starts_with('_'),
            "expected reserved name to be prefixed, got: {}",
            case.session_id()
        );
    }

    #[test]
    fn test_case_name_sanitizes_windows_invalid_chars() {
        let case = Case::new(r#"a:b*?"><|/"#, PathBuf::from("/tmp/case")).unwrap();
        let id = case.session_id();
        for c in ['<', '>', ':', '"', '/', '\\', '|', '?', '*'] {
            assert!(
                !id.contains(c),
                "expected {:?} to be removed from session id, got: {}",
                c,
                id
            );
        }
    }

    #[test]
    fn test_case_serialize() {
        let case = Case::new("my-session", PathBuf::from("/tmp/case")).unwrap();
        let json = serde_json::to_string(&case).unwrap();
        assert!(json.contains("name"));
    }
}
