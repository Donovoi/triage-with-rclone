//! Provider-specific configuration
//!
//! OAuth client IDs, scopes, and rclone configuration options.

use super::CloudProvider;

/// OAuth configuration for a provider
#[derive(Debug, Clone)]
pub struct OAuthConfig {
    /// OAuth client ID
    pub client_id: &'static str,
    /// OAuth client secret (if applicable)
    pub client_secret: &'static str,
    /// OAuth authorization URL
    pub auth_url: &'static str,
    /// OAuth token URL
    pub token_url: &'static str,
    /// OAuth scopes
    pub scopes: &'static [&'static str],
}

/// Provider configuration
#[derive(Debug, Clone)]
pub struct ProviderConfig {
    /// The provider
    pub provider: CloudProvider,
    /// OAuth configuration
    pub oauth: OAuthConfig,
    /// Additional rclone config options
    pub rclone_options: &'static [(&'static str, &'static str)],
}

impl ProviderConfig {
    /// Get configuration for a provider
    pub fn for_provider(provider: CloudProvider) -> Self {
        match provider {
            CloudProvider::GoogleDrive => Self::google_drive(),
            CloudProvider::OneDrive => Self::onedrive(),
            CloudProvider::Dropbox => Self::dropbox(),
            CloudProvider::Box => Self::box_(),
            CloudProvider::ICloud => Self::icloud(),
        }
    }

    /// Google Drive configuration
    fn google_drive() -> Self {
        Self {
            provider: CloudProvider::GoogleDrive,
            oauth: OAuthConfig {
                // Rclone's default client ID
                client_id: "202264815644.apps.googleusercontent.com",
                client_secret: "X4Z3ca8xfWDb1Voo-F9a7ZxJ",
                auth_url: "https://accounts.google.com/o/oauth2/auth",
                token_url: "https://oauth2.googleapis.com/token",
                scopes: &["https://www.googleapis.com/auth/drive"],
            },
            rclone_options: &[],
        }
    }

    /// OneDrive configuration
    fn onedrive() -> Self {
        Self {
            provider: CloudProvider::OneDrive,
            oauth: OAuthConfig {
                // Rclone's default client ID
                client_id: "b15665d9-eda6-4092-8539-0eec376afd59",
                client_secret: "",
                auth_url: "https://login.microsoftonline.com/common/oauth2/v2.0/authorize",
                token_url: "https://login.microsoftonline.com/common/oauth2/v2.0/token",
                scopes: &["Files.Read", "Files.ReadWrite", "Files.Read.All", "Files.ReadWrite.All", "offline_access"],
            },
            rclone_options: &[],
        }
    }

    /// Dropbox configuration
    fn dropbox() -> Self {
        Self {
            provider: CloudProvider::Dropbox,
            oauth: OAuthConfig {
                // Rclone's default client ID
                client_id: "eqxpiW7xg9A757Rz",
                client_secret: "",
                auth_url: "https://www.dropbox.com/oauth2/authorize",
                token_url: "https://api.dropboxapi.com/oauth2/token",
                scopes: &[],
            },
            rclone_options: &[],
        }
    }

    /// Box configuration
    fn box_() -> Self {
        Self {
            provider: CloudProvider::Box,
            oauth: OAuthConfig {
                // Rclone's default client ID
                client_id: "d0374ba6pgmaguie02ge15sv1mllndho",
                client_secret: "sYbJqKcUXJ1SFPfQxXeJqSWJlNLTnsxV",
                auth_url: "https://app.box.com/api/oauth2/authorize",
                token_url: "https://app.box.com/api/oauth2/token",
                scopes: &[],
            },
            rclone_options: &[],
        }
    }

    /// iCloud configuration
    fn icloud() -> Self {
        Self {
            provider: CloudProvider::ICloud,
            oauth: OAuthConfig {
                client_id: "",
                client_secret: "",
                auth_url: "",
                token_url: "",
                scopes: &[],
            },
            // iCloud uses username/password, not OAuth
            rclone_options: &[],
        }
    }

    /// Check if this provider uses OAuth
    pub fn uses_oauth(&self) -> bool {
        !self.oauth.client_id.is_empty()
    }

    /// Build OAuth authorization URL
    pub fn build_auth_url(&self, redirect_uri: &str, state: Option<&str>) -> String {
        let mut url = format!(
            "{}?client_id={}&redirect_uri={}&response_type=code",
            self.oauth.auth_url,
            urlencoded(self.oauth.client_id),
            urlencoded(redirect_uri),
        );

        if !self.oauth.scopes.is_empty() {
            let scope = self.oauth.scopes.join(" ");
            url.push_str(&format!("&scope={}", urlencoded(&scope)));
        }

        if let Some(state) = state {
            url.push_str(&format!("&state={}", urlencoded(state)));
        }

        // Provider-specific params
        if self.provider == CloudProvider::Dropbox {
            url.push_str("&token_access_type=offline");
        }

        url
    }
}

/// URL encode a string
fn urlencoded(s: &str) -> String {
    let mut result = String::with_capacity(s.len() * 3);
    for c in s.chars() {
        match c {
            'a'..='z' | 'A'..='Z' | '0'..='9' | '-' | '_' | '.' | '~' => result.push(c),
            ' ' => result.push_str("%20"),
            _ => {
                for b in c.to_string().as_bytes() {
                    result.push_str(&format!("%{:02X}", b));
                }
            }
        }
    }
    result
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_provider_configs() {
        for provider in CloudProvider::all() {
            let config = ProviderConfig::for_provider(*provider);
            assert_eq!(config.provider, *provider);
        }
    }

    #[test]
    fn test_oauth_providers() {
        // These should use OAuth
        assert!(ProviderConfig::for_provider(CloudProvider::GoogleDrive).uses_oauth());
        assert!(ProviderConfig::for_provider(CloudProvider::OneDrive).uses_oauth());
        assert!(ProviderConfig::for_provider(CloudProvider::Dropbox).uses_oauth());
        assert!(ProviderConfig::for_provider(CloudProvider::Box).uses_oauth());
        // iCloud doesn't use OAuth
        assert!(!ProviderConfig::for_provider(CloudProvider::ICloud).uses_oauth());
    }

    #[test]
    fn test_build_auth_url() {
        let config = ProviderConfig::for_provider(CloudProvider::GoogleDrive);
        let url = config.build_auth_url("http://localhost:53682/", Some("test_state"));
        
        assert!(url.contains("accounts.google.com"));
        assert!(url.contains("client_id="));
        assert!(url.contains("redirect_uri="));
        assert!(url.contains("state=test_state"));
    }
}
