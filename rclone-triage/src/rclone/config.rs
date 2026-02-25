//! Rclone configuration management
//!
//! Manages rclone config files and environment variables.
//! Includes parsing of INI format and OAuth token extraction.

use anyhow::{bail, Context, Result};
use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::fs;
use std::path::{Path, PathBuf};

/// Parsed OAuth token from rclone config
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OAuthToken {
    /// Access token
    pub access_token: Option<String>,
    /// Refresh token
    pub refresh_token: Option<String>,
    /// Token type (usually "Bearer")
    pub token_type: Option<String>,
    /// Expiry timestamp
    pub expiry: Option<String>,
    /// ID token (JWT) - contains user info for some providers
    pub id_token: Option<String>,
}

impl OAuthToken {
    /// Parse token from JSON string
    pub fn from_json(json: &str) -> Result<Self> {
        serde_json::from_str(json).context("Failed to parse token JSON")
    }

    /// Extract user info from the ID token (JWT)
    pub fn extract_user_info(&self) -> Option<UserInfo> {
        let id_token = self.id_token.as_ref()?;
        UserInfo::from_jwt_unverified(id_token)
    }
}

/// User information extracted from OAuth token
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UserInfo {
    /// Email address
    pub email: Option<String>,
    /// Display name
    pub name: Option<String>,
    /// Unique identifier
    pub sub: Option<String>,
    /// Preferred username (Microsoft)
    pub preferred_username: Option<String>,
    /// UPN - User Principal Name (Microsoft)
    pub upn: Option<String>,
    /// Unique name claim (Microsoft)
    pub unique_name: Option<String>,
}

impl UserInfo {
    /// Extract user info claims from a JWT token payload.
    ///
    /// # Security Warning
    ///
    /// This function **does not validate the JWT signature** and MUST NOT be used for
    /// authorization or access-control decisions.  It only extracts claims for
    /// *display purposes* (e.g. showing the authenticated user's email in the TUI
    /// and forensic report).  The token's authenticity is implicitly trusted because
    /// it was obtained directly from the OAuth provider over TLS.
    ///
    /// If stronger guarantees are needed in the future (e.g. accepting tokens from
    /// untrusted sources), implement proper signature verification with the
    /// provider's JWKS endpoint.
    pub fn from_jwt_unverified(jwt: &str) -> Option<Self> {
        // JWT format: header.payload.signature
        let parts: Vec<&str> = jwt.split('.').collect();
        if parts.len() < 2 {
            return None;
        }

        // Decode the payload (second part) — signature is NOT verified.
        let payload = parts[1];
        let decoded = URL_SAFE_NO_PAD.decode(payload).ok()?;
        let json_str = String::from_utf8(decoded).ok()?;

        // Parse as JSON and extract claims (display use only)
        let claims: serde_json::Value = serde_json::from_str(&json_str).ok()?;

        Some(UserInfo {
            email: claims
                .get("email")
                .and_then(|v| v.as_str())
                .map(String::from),
            name: claims
                .get("name")
                .and_then(|v| v.as_str())
                .map(String::from),
            sub: claims.get("sub").and_then(|v| v.as_str()).map(String::from),
            preferred_username: claims
                .get("preferred_username")
                .and_then(|v| v.as_str())
                .map(String::from),
            upn: claims.get("upn").and_then(|v| v.as_str()).map(String::from),
            unique_name: claims
                .get("unique_name")
                .and_then(|v| v.as_str())
                .map(String::from),
        })
    }

    /// Get the best available identifier (email preferred)
    pub fn best_identifier(&self) -> Option<String> {
        self.email
            .as_deref()
            .or(self.preferred_username.as_deref())
            .or(self.upn.as_deref())
            .or(self.unique_name.as_deref())
            .or(self.name.as_deref())
            .or(self.sub.as_deref())
            .map(String::from)
    }
}

/// OAuth credential summary for a configured remote.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OAuthCredentialStatus {
    /// Remote name (section header)
    pub remote_name: String,
    /// Client ID (if present)
    pub client_id: Option<String>,
    /// Client secret (masked if present)
    pub client_secret: Option<String>,
    /// Whether client ID is present
    pub has_client_id: bool,
    /// Whether client secret is present
    pub has_client_secret: bool,
    /// True if both client ID and secret are set
    pub is_using_custom_credentials: bool,
    /// True if either client ID or secret is missing
    pub using_default_rclone_credentials: bool,
}

/// A parsed remote section from rclone config
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RemoteSection {
    /// Remote name (section header without brackets)
    pub name: String,
    /// Remote type (e.g., "drive", "onedrive")
    pub remote_type: String,
    /// OAuth token if present
    pub token: Option<OAuthToken>,
    /// All key-value options
    pub options: HashMap<String, String>,
}

impl RemoteSection {
    /// Get user info from the token
    pub fn user_info(&self) -> Option<UserInfo> {
        self.token.as_ref()?.extract_user_info()
    }

    /// Get the best identifier for this remote
    pub fn user_identifier(&self) -> Option<String> {
        self.user_info()?.best_identifier()
    }
}

/// Parsed rclone configuration
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct ParsedConfig {
    /// All remote sections
    pub remotes: Vec<RemoteSection>,
}

impl ParsedConfig {
    /// Parse config from INI string
    pub fn parse(content: &str) -> Self {
        let mut config = ParsedConfig::default();
        let mut current_section: Option<RemoteSection> = None;

        for line in content.lines() {
            let line = line.trim();

            // Skip empty lines and comments
            if line.is_empty() || line.starts_with('#') || line.starts_with(';') {
                continue;
            }

            // Check for section header
            if line.starts_with('[') && line.ends_with(']') {
                // Save previous section
                if let Some(section) = current_section.take() {
                    config.remotes.push(section);
                }

                // Start new section
                let name = line[1..line.len() - 1].to_string();
                current_section = Some(RemoteSection {
                    name,
                    remote_type: String::new(),
                    token: None,
                    options: HashMap::new(),
                });
                continue;
            }

            // Parse key = value
            if let Some((key, value)) = line.split_once('=') {
                let key = key.trim();
                let value = value.trim();

                if let Some(ref mut section) = current_section {
                    match key {
                        "type" => section.remote_type = value.to_string(),
                        "token" => {
                            // Token is JSON, may be quoted
                            let token_json = value.trim_matches(|c| c == '\'' || c == '"');
                            if let Ok(token) = OAuthToken::from_json(token_json) {
                                section.token = Some(token);
                            }
                        }
                        _ => {
                            section.options.insert(key.to_string(), value.to_string());
                        }
                    }
                }
            }
        }

        // Don't forget the last section
        if let Some(section) = current_section {
            config.remotes.push(section);
        }

        config
    }

    /// Find a remote by name
    pub fn get_remote(&self, name: &str) -> Option<&RemoteSection> {
        self.remotes.iter().find(|r| r.name == name)
    }

    /// Find remotes by type
    pub fn remotes_by_type(&self, remote_type: &str) -> Vec<&RemoteSection> {
        self.remotes
            .iter()
            .filter(|r| r.remote_type == remote_type)
            .collect()
    }

    /// Get all remote names
    pub fn remote_names(&self) -> Vec<&str> {
        self.remotes.iter().map(|r| r.name.as_str()).collect()
    }
}

/// Manages rclone configuration
pub struct RcloneConfig {
    /// Path to the config file
    config_path: PathBuf,
    /// Whether we created this config file
    created: bool,
    /// Original RCLONE_CONFIG env var value (for restoration)
    original_env: Option<String>,
}

#[cfg(test)]
static ENV_MUTEX: std::sync::Mutex<()> = std::sync::Mutex::new(());

#[cfg(test)]
fn with_env_lock<F, R>(f: F) -> R
where
    F: FnOnce() -> R,
{
    let _guard = ENV_MUTEX.lock().unwrap();
    f()
}

#[cfg(not(test))]
fn with_env_lock<F, R>(f: F) -> R
where
    F: FnOnce() -> R,
{
    f()
}

impl RcloneConfig {
    /// Create a new config manager with a specific config file path
    ///
    /// If the directory doesn't exist, it will be created.
    /// If the file doesn't exist, an empty config file will be created.
    pub fn new(config_path: impl AsRef<Path>) -> Result<Self> {
        with_env_lock(|| {
            let config_path = config_path.as_ref().to_path_buf();

            // Save original env var
            let original_env = std::env::var("RCLONE_CONFIG").ok();

            // Create parent directories
            if let Some(parent) = config_path.parent() {
                fs::create_dir_all(parent)
                    .with_context(|| format!("Failed to create config directory: {:?}", parent))?;
            }

            // Check if we need to create the file
            let created = !config_path.exists();
            if created {
                fs::write(&config_path, "# rclone-triage config\n")
                    .with_context(|| format!("Failed to create config file: {:?}", config_path))?;
                // Restrict permissions so other users cannot read OAuth tokens.
                #[cfg(unix)]
                {
                    use std::os::unix::fs::PermissionsExt;
                    let perms = std::fs::Permissions::from_mode(0o600);
                    std::fs::set_permissions(&config_path, perms).ok();
                }
            }

            // Set the environment variable
            std::env::set_var("RCLONE_CONFIG", &config_path);

            Ok(Self {
                config_path,
                created,
                original_env,
            })
        })
    }

    /// Open an existing rclone config without creating a new file.
    pub fn open_existing(config_path: impl AsRef<Path>) -> Result<Self> {
        let config_path = config_path.as_ref();
        if !config_path.exists() {
            bail!("Config file not found: {:?}", config_path);
        }
        Self::new(config_path)
    }

    /// Create a config in the system's rclone config directory
    pub fn in_default_location() -> Result<Self> {
        let config_dir = dirs::config_dir()
            .context("Could not find config directory")?
            .join("rclone");

        fs::create_dir_all(&config_dir)?;
        Self::new(config_dir.join("rclone.conf"))
    }

    /// Create a config in a case-specific directory
    pub fn for_case(case_dir: impl AsRef<Path>) -> Result<Self> {
        let case_dir = case_dir.as_ref();
        let config_path = match case_dir.file_name().and_then(|name| name.to_str()) {
            Some("config") => case_dir.join("rclone.conf"),
            Some("rclone.conf") => case_dir.to_path_buf(),
            _ => case_dir.join("config").join("rclone.conf"),
        };
        Self::new(config_path)
    }

    /// Get the config file path
    pub fn path(&self) -> &Path {
        &self.config_path
    }

    /// Get the original RCLONE_CONFIG value before this config was created
    pub fn original_env(&self) -> Option<String> {
        self.original_env.clone()
    }

    /// Check if a remote is configured
    pub fn has_remote(&self, name: &str) -> Result<bool> {
        let content = fs::read_to_string(&self.config_path)
            .with_context(|| format!("Failed to read config: {:?}", self.config_path))?;

        let section = format!("[{}]", name);
        Ok(content.contains(&section))
    }

    /// Get all configured remote names
    pub fn list_remotes(&self) -> Result<Vec<String>> {
        let content = fs::read_to_string(&self.config_path)
            .with_context(|| format!("Failed to read config: {:?}", self.config_path))?;

        let mut remotes = Vec::new();
        for line in content.lines() {
            if line.starts_with('[') && line.ends_with(']') {
                let name = line.trim_start_matches('[').trim_end_matches(']');
                remotes.push(name.to_string());
            }
        }
        Ok(remotes)
    }

    /// Find the next available remote name by appending a numeric suffix if needed.
    pub fn next_available_remote_name(&self, base: &str) -> Result<String> {
        let base = base.trim();
        if base.is_empty() {
            bail!("Remote base name cannot be empty");
        }

        let remotes = self.list_remotes()?;
        if !remotes.iter().any(|r| r == base) {
            return Ok(base.to_string());
        }

        let mut suffix = 2;
        loop {
            let candidate = format!("{}-{}", base, suffix);
            if !remotes.iter().any(|r| r == &candidate) {
                return Ok(candidate);
            }
            suffix += 1;
        }
    }

    /// Add or update a remote configuration
    ///
    /// # Arguments
    /// * `name` - Remote name
    /// * `remote_type` - Rclone remote type (e.g., "drive", "onedrive")
    /// * `options` - Key-value pairs for configuration
    pub fn set_remote(
        &self,
        name: &str,
        remote_type: &str,
        options: &[(&str, &str)],
    ) -> Result<()> {
        let mut content = fs::read_to_string(&self.config_path).unwrap_or_default();

        // Remove existing section if present
        let section_start = format!("[{}]", name);
        if let Some(start_idx) = content.find(&section_start) {
            // Find the end of this section (next [ or end of file)
            let rest = &content[start_idx + section_start.len()..];
            let end_offset = rest.find("\n[").unwrap_or(rest.len());
            let end_idx = start_idx + section_start.len() + end_offset;
            content = format!("{}{}", &content[..start_idx], &content[end_idx..]);
        }

        // Add new section
        let mut section = format!("\n[{}]\n", name);
        section.push_str(&format!("type = {}\n", remote_type));
        for (key, value) in options {
            section.push_str(&format!("{} = {}\n", key, value));
        }

        content.push_str(&section);

        fs::write(&self.config_path, content.trim_start())
            .with_context(|| format!("Failed to write config: {:?}", self.config_path))?;

        Ok(())
    }

    /// Remove a remote from the configuration
    pub fn remove_remote(&self, name: &str) -> Result<()> {
        let content = fs::read_to_string(&self.config_path)
            .with_context(|| format!("Failed to read config: {:?}", self.config_path))?;

        let section_start = format!("[{}]", name);
        if let Some(start_idx) = content.find(&section_start) {
            let rest = &content[start_idx + section_start.len()..];
            let end_offset = rest.find("\n[").map(|i| i + 1).unwrap_or(rest.len());
            let end_idx = start_idx + section_start.len() + end_offset;

            let new_content = format!("{}{}", &content[..start_idx], &content[end_idx..]);
            fs::write(&self.config_path, new_content.trim_start())
                .with_context(|| format!("Failed to write config: {:?}", self.config_path))?;
        }

        Ok(())
    }

    /// Get a specific option from a remote's configuration
    pub fn get_remote_option(&self, name: &str, key: &str) -> Result<Option<String>> {
        let content = fs::read_to_string(&self.config_path)
            .with_context(|| format!("Failed to read config: {:?}", self.config_path))?;

        let section_start = format!("[{}]", name);
        if let Some(start_idx) = content.find(&section_start) {
            let section = &content[start_idx..];
            let section_end = section[1..]
                .find('[')
                .map(|i| i + 1)
                .unwrap_or(section.len());
            let section = &section[..section_end];

            for line in section.lines() {
                if let Some((k, v)) = line.split_once('=') {
                    if k.trim() == key {
                        return Ok(Some(v.trim().to_string()));
                    }
                }
            }
        }

        Ok(None)
    }

    /// Copy the config file to a destination
    pub fn copy_to(&self, dest: impl AsRef<Path>) -> Result<PathBuf> {
        let dest = dest.as_ref();
        fs::copy(&self.config_path, dest)
            .with_context(|| format!("Failed to copy config to {:?}", dest))?;
        Ok(dest.to_path_buf())
    }

    /// Parse the config file into structured data
    pub fn parse(&self) -> Result<ParsedConfig> {
        let content = fs::read_to_string(&self.config_path)
            .with_context(|| format!("Failed to read config: {:?}", self.config_path))?;
        Ok(ParsedConfig::parse(&content))
    }

    /// Get user info for a specific remote (if available in token)
    pub fn get_user_info(&self, remote_name: &str) -> Result<Option<UserInfo>> {
        let parsed = self.parse()?;
        Ok(parsed.get_remote(remote_name).and_then(|r| r.user_info()))
    }

    /// Get OAuth credential status for a specific remote.
    pub fn get_oauth_credentials(&self, remote_name: &str) -> Result<OAuthCredentialStatus> {
        let parsed = self.parse()?;
        let remote = parsed
            .get_remote(remote_name)
            .ok_or_else(|| anyhow::anyhow!("Remote {} not found", remote_name))?;

        let client_id = remote
            .options
            .get("client_id")
            .map(|s| s.trim())
            .filter(|s| !s.is_empty())
            .map(|s| s.to_string());
        let has_client_id = client_id.is_some();

        let client_secret_value = remote
            .options
            .get("client_secret")
            .map(|s| s.trim())
            .filter(|s| !s.is_empty());
        let has_client_secret = client_secret_value.is_some();
        let client_secret = if has_client_secret {
            Some("***HIDDEN***".to_string())
        } else {
            None
        };

        let is_using_custom_credentials = has_client_id && has_client_secret;
        let using_default_rclone_credentials = !has_client_id || !has_client_secret;

        Ok(OAuthCredentialStatus {
            remote_name: remote_name.to_string(),
            client_id,
            client_secret,
            has_client_id,
            has_client_secret,
            is_using_custom_credentials,
            using_default_rclone_credentials,
        })
    }

    /// Restore the original RCLONE_CONFIG environment variable
    pub fn restore_env(&self) {
        with_env_lock(|| match &self.original_env {
            Some(val) => std::env::set_var("RCLONE_CONFIG", val),
            None => std::env::remove_var("RCLONE_CONFIG"),
        });
    }

    /// Clean up - delete the config file if we created it and restore env
    pub fn cleanup(&self) -> Result<()> {
        self.restore_env();
        if self.created && self.config_path.exists() {
            fs::remove_file(&self.config_path)
                .with_context(|| format!("Failed to delete config: {:?}", self.config_path))?;
        }
        Ok(())
    }
}

impl Drop for RcloneConfig {
    fn drop(&mut self) {
        // Restore env var on drop
        self.restore_env();
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::tempdir;

    #[test]
    fn test_create_config() {
        let dir = tempdir().unwrap();
        let config_path = dir.path().join("rclone.conf");

        let config = RcloneConfig::new(&config_path).unwrap();
        assert!(config_path.exists());
        assert!(config.created);
    }

    #[test]
    fn test_for_case_accepts_config_dir() {
        let dir = tempdir().unwrap();
        let config_dir = dir.path().join("config");
        fs::create_dir_all(&config_dir).unwrap();

        let config = RcloneConfig::for_case(&config_dir).unwrap();
        assert_eq!(config.path(), config_dir.join("rclone.conf"));
        assert!(config.path().exists());
    }

    #[test]
    fn test_set_remote() {
        let dir = tempdir().unwrap();
        let config_path = dir.path().join("rclone.conf");

        let config = RcloneConfig::new(&config_path).unwrap();
        config
            .set_remote(
                "test",
                "drive",
                &[("client_id", "test_id"), ("client_secret", "test_secret")],
            )
            .unwrap();

        assert!(config.has_remote("test").unwrap());

        let remotes = config.list_remotes().unwrap();
        assert!(remotes.contains(&"test".to_string()));

        let client_id = config.get_remote_option("test", "client_id").unwrap();
        assert_eq!(client_id, Some("test_id".to_string()));
    }

    #[test]
    fn test_remove_remote() {
        let dir = tempdir().unwrap();
        let config_path = dir.path().join("rclone.conf");

        let config = RcloneConfig::new(&config_path).unwrap();
        config.set_remote("test1", "drive", &[]).unwrap();
        config.set_remote("test2", "onedrive", &[]).unwrap();

        assert!(config.has_remote("test1").unwrap());
        assert!(config.has_remote("test2").unwrap());

        config.remove_remote("test1").unwrap();

        assert!(!config.has_remote("test1").unwrap());
        assert!(config.has_remote("test2").unwrap());
    }

    #[test]
    fn test_env_management() {
        let dir = tempdir().unwrap();
        let config_path = dir.path().join("rclone.conf");

        // Save current env
        let original = std::env::var("RCLONE_CONFIG").ok();

        {
            let _config = RcloneConfig::new(&config_path).unwrap();
            assert_eq!(
                std::env::var("RCLONE_CONFIG").unwrap(),
                config_path.to_str().unwrap()
            );
        }

        // After drop, should be restored
        assert_eq!(std::env::var("RCLONE_CONFIG").ok(), original);
    }

    #[test]
    fn test_parse_config_ini() {
        let content = r#"
# rclone config file
[gdrive]
type = drive
client_id = abc123
client_secret = secret456
scope = drive

[onedrive]
type = onedrive
drive_id = xyz789
"#;

        let parsed = ParsedConfig::parse(content);
        assert_eq!(parsed.remotes.len(), 2);

        let gdrive = parsed.get_remote("gdrive").unwrap();
        assert_eq!(gdrive.remote_type, "drive");
        assert_eq!(gdrive.options.get("client_id"), Some(&"abc123".to_string()));

        let onedrive = parsed.get_remote("onedrive").unwrap();
        assert_eq!(onedrive.remote_type, "onedrive");
        assert_eq!(
            onedrive.options.get("drive_id"),
            Some(&"xyz789".to_string())
        );

        let drive_remotes = parsed.remotes_by_type("drive");
        assert_eq!(drive_remotes.len(), 1);
        assert_eq!(drive_remotes[0].name, "gdrive");
    }

    #[test]
    fn test_get_oauth_credentials() {
        let dir = tempdir().unwrap();
        let config_path = dir.path().join("rclone.conf");
        let config = RcloneConfig::new(&config_path).unwrap();

        config
            .set_remote(
                "with-secret",
                "drive",
                &[("client_id", "abc"), ("client_secret", "def")],
            )
            .unwrap();
        let creds = config.get_oauth_credentials("with-secret").unwrap();
        assert_eq!(creds.client_id.as_deref(), Some("abc"));
        assert_eq!(creds.client_secret.as_deref(), Some("***HIDDEN***"));
        assert!(creds.has_client_id);
        assert!(creds.has_client_secret);
        assert!(creds.is_using_custom_credentials);
        assert!(!creds.using_default_rclone_credentials);

        config
            .set_remote("id-only", "drive", &[("client_id", "only")])
            .unwrap();
        let creds = config.get_oauth_credentials("id-only").unwrap();
        assert_eq!(creds.client_id.as_deref(), Some("only"));
        assert_eq!(creds.client_secret, None);
        assert!(creds.has_client_id);
        assert!(!creds.has_client_secret);
        assert!(!creds.is_using_custom_credentials);
        assert!(creds.using_default_rclone_credentials);
    }

    #[test]
    fn test_parse_config_with_token() {
        let content = r#"
[my-drive]
type = drive
token = {"access_token":"ya29.xxx","token_type":"Bearer","refresh_token":"1//xxx","expiry":"2024-01-01T00:00:00Z"}
"#;

        let parsed = ParsedConfig::parse(content);
        let remote = parsed.get_remote("my-drive").unwrap();

        assert!(remote.token.is_some());
        let token = remote.token.as_ref().unwrap();
        assert_eq!(token.access_token, Some("ya29.xxx".to_string()));
        assert_eq!(token.token_type, Some("Bearer".to_string()));
    }

    #[test]
    fn test_jwt_parsing() {
        // This is a mock JWT with claims in the payload
        // Header: {"alg":"RS256","typ":"JWT"}
        // Payload: {"email":"test@example.com","name":"Test User","sub":"123456"}
        // Note: we only decode the payload, not validate the signature
        let jwt = "eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.eyJlbWFpbCI6InRlc3RAZXhhbXBsZS5jb20iLCJuYW1lIjoiVGVzdCBVc2VyIiwic3ViIjoiMTIzNDU2In0.signature";

        let user_info = UserInfo::from_jwt_unverified(jwt);
        assert!(user_info.is_some());

        let user = user_info.unwrap();
        assert_eq!(user.email, Some("test@example.com".to_string()));
        assert_eq!(user.name, Some("Test User".to_string()));
        assert_eq!(user.sub, Some("123456".to_string()));
        assert_eq!(user.best_identifier(), Some("test@example.com".to_string()));
    }

    #[test]
    fn test_user_info_best_identifier() {
        // Test with only Microsoft claims
        let user = UserInfo {
            email: None,
            name: None,
            sub: None,
            preferred_username: Some("user@company.com".to_string()),
            upn: Some("upn@company.com".to_string()),
            unique_name: None,
        };
        assert_eq!(user.best_identifier(), Some("user@company.com".to_string()));

        // Test fallback chain
        let user2 = UserInfo {
            email: None,
            name: Some("John Doe".to_string()),
            sub: Some("12345".to_string()),
            preferred_username: None,
            upn: None,
            unique_name: None,
        };
        assert_eq!(user2.best_identifier(), Some("John Doe".to_string()));
    }

    #[test]
    fn test_oauth_token_from_json() {
        let json = r#"{"access_token":"abc","refresh_token":"xyz","token_type":"Bearer","expiry":"2024-01-01"}"#;
        let token = OAuthToken::from_json(json).unwrap();

        assert_eq!(token.access_token, Some("abc".to_string()));
        assert_eq!(token.refresh_token, Some("xyz".to_string()));
        assert_eq!(token.token_type, Some("Bearer".to_string()));
    }

    #[test]
    fn test_remote_names() {
        let content = r#"
[alpha]
type = drive

[beta]
type = onedrive

[gamma]
type = dropbox
"#;

        let parsed = ParsedConfig::parse(content);
        let names = parsed.remote_names();

        assert_eq!(names.len(), 3);
        assert!(names.contains(&"alpha"));
        assert!(names.contains(&"beta"));
        assert!(names.contains(&"gamma"));
    }
}
