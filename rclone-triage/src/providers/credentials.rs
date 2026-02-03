//! Custom OAuth credential loading
//!
//! Supports loading per-provider OAuth client IDs/secrets from a JSON file.
//! Default path: `$XDG_CONFIG_HOME/rclone-triage/oauth.json` (or platform equivalent).
//! Override path via `RCLONE_TRIAGE_OAUTH_CONFIG`.
//!
//! Example file:
//! {
//!   "drive": { "client_id": "123.apps.googleusercontent.com", "client_secret": "GOCSPX-..." },
//!   "onedrive": { "client_id": "00000000-0000-0000-0000-000000000000" },
//!   "dropbox": { "client_id": "abcd1234" },
//!   "box": { "client_id": "efgh5678", "client_secret": "secret" }
//! }

use super::CloudProvider;
use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::env;
use std::fs;
use std::path::{Path, PathBuf};

const CUSTOM_OAUTH_ENV: &str = "RCLONE_TRIAGE_OAUTH_CONFIG";

/// OAuth credentials for a provider
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OAuthCredentials {
    /// OAuth client ID
    pub client_id: String,
    /// OAuth client secret (optional)
    #[serde(default)]
    pub client_secret: Option<String>,
}

/// Custom OAuth config file structure
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct CustomOAuthConfig {
    /// Map of provider name -> credentials
    #[serde(flatten)]
    pub providers: HashMap<String, OAuthCredentials>,
}

impl CustomOAuthConfig {
    /// Return credentials for a provider if present
    pub fn credentials_for(&self, provider: CloudProvider) -> Option<OAuthCredentials> {
        let candidates = [
            provider.short_name(),
            provider.rclone_type(),
            provider.display_name(),
        ];

        for candidate in candidates {
            let candidate_norm = normalize_key(candidate);
            for (key, creds) in &self.providers {
                if normalize_key(key) == candidate_norm && !creds.client_id.trim().is_empty() {
                    return Some(creds.clone());
                }
            }
        }

        None
    }
}

impl std::str::FromStr for CustomOAuthConfig {
    type Err = anyhow::Error;

    fn from_str(content: &str) -> Result<Self, Self::Err> {
        serde_json::from_str(content).context("Failed to parse custom OAuth JSON")
    }
}

fn normalize_key(key: &str) -> String {
    key.trim()
        .to_lowercase()
        .chars()
        .filter(|c| !c.is_whitespace() && *c != '_' && *c != '-')
        .collect()
}

/// Default location for the custom OAuth config file
pub fn custom_oauth_config_path() -> Option<PathBuf> {
    if let Ok(path) = env::var(CUSTOM_OAUTH_ENV) {
        let trimmed = path.trim();
        if !trimmed.is_empty() {
            return Some(PathBuf::from(trimmed));
        }
    }

    dirs::config_dir().map(|dir| dir.join("rclone-triage").join("oauth.json"))
}

/// Load custom OAuth config from a specific path
pub fn load_custom_oauth_config_from_path(path: impl AsRef<Path>) -> Result<CustomOAuthConfig> {
    let content =
        fs::read_to_string(&path).with_context(|| format!("Failed to read {:?}", path.as_ref()))?;
    content.parse::<CustomOAuthConfig>()
}

/// Load custom OAuth config from the default location (if present)
pub fn load_custom_oauth_config() -> Result<Option<CustomOAuthConfig>> {
    let path = match custom_oauth_config_path() {
        Some(path) => path,
        None => return Ok(None),
    };

    if !path.exists() {
        return Ok(None);
    }

    let config = load_custom_oauth_config_from_path(&path)?;
    Ok(Some(config))
}

/// Get custom OAuth credentials for a provider (if configured)
pub fn custom_oauth_credentials_for(provider: CloudProvider) -> Result<Option<OAuthCredentials>> {
    let config = match load_custom_oauth_config()? {
        Some(config) => config,
        None => return Ok(None),
    };

    Ok(config.credentials_for(provider))
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::tempdir;

    #[test]
    fn test_custom_oauth_config_parsing() {
        let json = r#"
        {
            "drive": { "client_id": "id1", "client_secret": "secret1" },
            "onedrive": { "client_id": "id2" },
            "google drive": { "client_id": "id3", "client_secret": "secret3" }
        }"#;

        let config: CustomOAuthConfig = json.parse().unwrap();

        let drive = config.credentials_for(CloudProvider::GoogleDrive).unwrap();
        assert_eq!(drive.client_id, "id1");
        assert_eq!(drive.client_secret.as_deref(), Some("secret1"));

        let onedrive = config.credentials_for(CloudProvider::OneDrive).unwrap();
        assert_eq!(onedrive.client_id, "id2");
        assert_eq!(onedrive.client_secret, None);
    }

    #[test]
    fn test_load_custom_oauth_config_from_path() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("oauth.json");
        let json = r#"{ "dropbox": { "client_id": "dbx" } }"#;
        fs::write(&path, json).unwrap();

        let config = load_custom_oauth_config_from_path(&path).unwrap();
        let creds = config.credentials_for(CloudProvider::Dropbox).unwrap();
        assert_eq!(creds.client_id, "dbx");
        assert_eq!(creds.client_secret, None);
    }
}
