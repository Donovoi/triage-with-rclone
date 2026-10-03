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
use anyhow::{bail, Context, Result};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::env;
use std::fs;
use std::path::{Path, PathBuf};

const CUSTOM_OAUTH_ENV: &str = "RCLONE_TRIAGE_OAUTH_CONFIG";

/// OAuth credentials for a provider
#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct OAuthCredentials {
    /// OAuth client ID
    pub client_id: String,
    /// OAuth client secret (optional)
    #[serde(default)]
    pub client_secret: Option<String>,
}

impl std::fmt::Debug for OAuthCredentials {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("OAuthCredentials")
            .field("client_id", &"[REDACTED]")
            .field(
                "client_secret",
                &self.client_secret.as_ref().map(|_| "[REDACTED]"),
            )
            .finish()
    }
}

/// Custom OAuth config file structure
#[derive(Debug, Clone, Serialize, Default)]
pub struct CustomOAuthConfig {
    /// Map of provider name -> credentials
    #[serde(flatten)]
    pub providers: HashMap<String, OAuthCredentials>,
}

impl<'de> Deserialize<'de> for CustomOAuthConfig {
    fn deserialize<D: serde::Deserializer<'de>>(
        deserializer: D,
    ) -> std::result::Result<Self, D::Error> {
        struct ConfigVisitor;
        impl<'de> serde::de::Visitor<'de> for ConfigVisitor {
            type Value = CustomOAuthConfig;
            fn expecting(&self, formatter: &mut std::fmt::Formatter) -> std::fmt::Result {
                formatter.write_str("an OAuth provider map with unique keys")
            }
            fn visit_map<A: serde::de::MapAccess<'de>>(
                self,
                mut map: A,
            ) -> std::result::Result<Self::Value, A::Error> {
                let mut providers = HashMap::new();
                while let Some((key, value)) = map.next_entry::<String, OAuthCredentials>()? {
                    if providers.insert(key, value).is_some() {
                        return Err(serde::de::Error::custom("Duplicate OAuth provider key"));
                    }
                }
                Ok(CustomOAuthConfig { providers })
            }
        }
        deserializer.deserialize_map(ConfigVisitor)
    }
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
        // Serde type errors can quote the offending value (including a secret).
        let config: Self = serde_json::from_str(content)
            .map_err(|_| anyhow::anyhow!("Failed to parse custom OAuth JSON"))?;
        config.validate()?;
        Ok(config)
    }
}

impl CustomOAuthConfig {
    fn validate(&self) -> Result<()> {
        let mut keys = std::collections::HashSet::new();
        for (key, credentials) in &self.providers {
            if !keys.insert(normalize_key(key)) {
                bail!("Ambiguous custom OAuth provider keys");
            }
            if credentials.client_id.trim().is_empty()
                || credentials.client_id.contains(['\r', '\n', '\0'])
                || credentials.client_secret.as_ref().is_some_and(|value| {
                    value.trim().is_empty() || value.contains(['\r', '\n', '\0'])
                })
            {
                bail!("Custom OAuth credentials contain an empty or invalid field");
            }
        }
        for provider in CloudProvider::all() {
            let aliases = [
                provider.short_name(),
                provider.rclone_type(),
                provider.display_name(),
            ];
            if self
                .providers
                .keys()
                .filter(|key| {
                    aliases
                        .iter()
                        .any(|alias| normalize_key(key) == normalize_key(alias))
                })
                .count()
                > 1
            {
                bail!("Multiple OAuth registrations configured for one provider");
            }
        }
        Ok(())
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

    let explicit = env::var(CUSTOM_OAUTH_ENV).is_ok_and(|value| !value.trim().is_empty());
    load_custom_oauth_config_at(&path, explicit)
}

fn load_custom_oauth_config_at(path: &Path, explicit: bool) -> Result<Option<CustomOAuthConfig>> {
    if !explicit
        && !path
            .try_exists()
            .context("Unable to inspect OAuth configuration")?
    {
        return Ok(None);
    }
    load_custom_oauth_config_from_path(path).map(Some)
}

/// Get custom OAuth credentials for a provider (if configured)
pub fn custom_oauth_credentials_for(provider: CloudProvider) -> Result<Option<OAuthCredentials>> {
    let config = match load_custom_oauth_config()? {
        Some(config) => config,
        None => return Ok(None),
    };

    Ok(config.credentials_for(provider))
}

/// Load the custom OAuth config (or create an empty config if missing).
pub fn load_or_init_custom_oauth_config(path: &Path) -> Result<CustomOAuthConfig> {
    if path.exists() {
        load_custom_oauth_config_from_path(path)
    } else {
        Ok(CustomOAuthConfig::default())
    }
}

/// Write the custom OAuth config to disk.
pub fn write_custom_oauth_config(path: &Path, config: &CustomOAuthConfig) -> Result<()> {
    config.validate()?;
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent).with_context(|| format!("Failed to create {:?}", parent))?;
    }
    let json = serde_json::to_string_pretty(config).context("Failed to serialize OAuth config")?;
    fs::write(path, json).with_context(|| format!("Failed to write {:?}", path))?;
    // Restrict permissions so other users cannot read client secrets.
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let perms = std::fs::Permissions::from_mode(0o600);
        std::fs::set_permissions(path, perms).ok();
    }
    Ok(())
}

/// Upsert OAuth credentials for a provider key.
pub fn upsert_custom_oauth_credentials(
    provider_key: &str,
    client_id: String,
    client_secret: Option<String>,
    path_override: Option<PathBuf>,
) -> Result<PathBuf> {
    let path = if let Some(path) = path_override {
        path
    } else {
        custom_oauth_config_path()
            .ok_or_else(|| anyhow::anyhow!("Unable to resolve OAuth config path"))?
    };

    let mut config = load_or_init_custom_oauth_config(&path)?;
    config.providers.insert(
        provider_key.to_string(),
        OAuthCredentials {
            client_id,
            client_secret,
        },
    );
    write_custom_oauth_config(&path, &config)?;
    Ok(path)
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
            "onedrive": { "client_id": "id2" }
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

    #[test]
    fn malformed_or_ambiguous_credentials_never_fall_back_or_echo_values() {
        for json in [
            r#"{"onedrive":{"client_id":" "}}"#,
            r#"{"onedrive":{"client_id":"id","client_secret":" "}}"#,
            r#"{"onedrive":{"client_id":"id\nextra=value"}}"#,
            r#"{"onedrive":{"client_id":"id","client_secert":"SYNTHETIC_SECRET_DO_NOT_ECHO"}}"#,
            r#"{"drive":{"client_id":"first"},"google drive":{"client_id":"second"}}"#,
            r#"{"OneDrive":{"client_id":"first"},"one-drive":{"client_id":"second"}}"#,
            r#"{"onedrive":{"client_id":"first"},"onedrive":{"client_id":"second"}}"#,
            r#"{"onedrive":{"client_id":{"SYNTHETIC_SECRET_DO_NOT_ECHO":"value"}}}"#,
        ] {
            let error = json.parse::<CustomOAuthConfig>().unwrap_err();
            assert!(!format!("{error:#}").contains("SYNTHETIC_SECRET_DO_NOT_ECHO"));
        }
        let directory = tempdir().unwrap();
        let missing = directory.path().join("missing.json");
        assert!(load_custom_oauth_config_at(&missing, false)
            .unwrap()
            .is_none());
        assert!(load_custom_oauth_config_at(&missing, true).is_err());
        let malformed = directory.path().join("malformed.json");
        fs::write(&malformed, "not JSON").unwrap();
        assert!(load_custom_oauth_config_at(&malformed, false).is_err());
        let credentials = OAuthCredentials {
            client_id: "private-id".into(),
            client_secret: Some("private-secret".into()),
        };
        assert!(!format!("{credentials:?}").contains("private-"));
    }

    #[test]
    fn test_upsert_custom_oauth_credentials() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("oauth.json");

        let saved = upsert_custom_oauth_credentials(
            "drive",
            "client123".to_string(),
            Some("secret123".to_string()),
            Some(path.clone()),
        )
        .unwrap();

        assert_eq!(saved, path);
        let config = load_custom_oauth_config_from_path(&path).unwrap();
        let creds = config.credentials_for(CloudProvider::GoogleDrive).unwrap();
        assert_eq!(creds.client_id, "client123");
        assert_eq!(creds.client_secret.as_deref(), Some("secret123"));
    }
}
