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
            CloudProvider::GooglePhotos => Self::google_photos(),
            CloudProvider::PCloud => Self::pcloud(),
            CloudProvider::AzureBlob => Self::no_oauth(provider),
            CloudProvider::AzureFiles => Self::no_oauth(provider),
            CloudProvider::B2 => Self::no_oauth(provider),
            CloudProvider::Cloudinary => Self::no_oauth(provider),
            CloudProvider::Doi => Self::no_oauth(provider),
            CloudProvider::Drime => Self::no_oauth(provider),
            CloudProvider::Fichier => Self::no_oauth(provider),
            CloudProvider::FileFabric => Self::no_oauth(provider),
            CloudProvider::Filelu => Self::no_oauth(provider),
            CloudProvider::Filen => Self::no_oauth(provider),
            CloudProvider::FilesCom => Self::no_oauth(provider),
            CloudProvider::Ftp => Self::no_oauth(provider),
            CloudProvider::Gofile => Self::no_oauth(provider),
            CloudProvider::GoogleCloudStorage => Self::no_oauth(provider),
            CloudProvider::Hdfs => Self::no_oauth(provider),
            CloudProvider::HiDrive => Self::hidrive(),
            CloudProvider::Http => Self::no_oauth(provider),
            CloudProvider::ImageKit => Self::no_oauth(provider),
            CloudProvider::InternetArchive => Self::no_oauth(provider),
            CloudProvider::Internxt => Self::no_oauth(provider),
            CloudProvider::Jottacloud => Self::jottacloud(),
            CloudProvider::Koofr => Self::no_oauth(provider),
            CloudProvider::Linkbox => Self::no_oauth(provider),
            CloudProvider::Local => Self::no_oauth(provider),
            CloudProvider::Mailru => Self::mailru(),
            CloudProvider::Mega => Self::no_oauth(provider),
            CloudProvider::Memory => Self::no_oauth(provider),
            CloudProvider::NetStorage => Self::no_oauth(provider),
            CloudProvider::OpenDrive => Self::no_oauth(provider),
            CloudProvider::OracleObjectStorage => Self::no_oauth(provider),
            CloudProvider::PikPak => Self::pikpak(),
            CloudProvider::Pixeldrain => Self::no_oauth(provider),
            CloudProvider::PremiumizeMe => Self::premiumizeme(),
            CloudProvider::ProtonDrive => Self::no_oauth(provider),
            CloudProvider::Putio => Self::putio(),
            CloudProvider::QingStor => Self::no_oauth(provider),
            CloudProvider::Quatrix => Self::no_oauth(provider),
            CloudProvider::S3 => Self::no_oauth(provider),
            CloudProvider::Seafile => Self::no_oauth(provider),
            CloudProvider::Sftp => Self::no_oauth(provider),
            CloudProvider::Shade => Self::no_oauth(provider),
            CloudProvider::ShareFile => Self::sharefile(),
            CloudProvider::Sia => Self::no_oauth(provider),
            CloudProvider::Smb => Self::no_oauth(provider),
            CloudProvider::Storj => Self::no_oauth(provider),
            CloudProvider::SugarSync => Self::sugarsync(),
            CloudProvider::Swift => Self::no_oauth(provider),
            CloudProvider::Ulozto => Self::no_oauth(provider),
            CloudProvider::WebDav => Self::no_oauth(provider),
            CloudProvider::YandexDisk => Self::yandex(),
            CloudProvider::Zoho => Self::zoho(),
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
            // rclone requires 'scope' in config to know which Drive API scope to use
            rclone_options: &[("scope", "drive")],
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
                scopes: &[
                    "Files.Read",
                    "Files.ReadWrite",
                    "Files.Read.All",
                    "Files.ReadWrite.All",
                    "offline_access",
                ],
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

    /// Google Photos configuration
    fn google_photos() -> Self {
        Self {
            provider: CloudProvider::GooglePhotos,
            oauth: OAuthConfig {
                // Rclone's default client ID
                client_id: "202264815644.apps.googleusercontent.com",
                client_secret: "X4Z3ca8xfWDb1Voo-F9a7ZxJ",
                auth_url: "https://accounts.google.com/o/oauth2/auth",
                token_url: "https://oauth2.googleapis.com/token",
                scopes: &["https://www.googleapis.com/auth/photoslibrary.readonly"],
            },
            rclone_options: &[],
        }
    }

    /// pCloud configuration
    fn pcloud() -> Self {
        Self {
            provider: CloudProvider::PCloud,
            oauth: OAuthConfig {
                // Rclone's default client ID
                client_id: "pcp-ctrl",
                client_secret: "",
                auth_url: "https://my.pcloud.com/oauth2/authorize",
                token_url: "https://api.pcloud.com/oauth2_token",
                scopes: &[],
            },
            rclone_options: &[],
        }
    }

    /// Provider that does not use OAuth (key-based, user/pass, or manual config)
    fn no_oauth(provider: CloudProvider) -> Self {
        Self {
            provider,
            oauth: OAuthConfig {
                client_id: "",
                client_secret: "",
                auth_url: "",
                token_url: "",
                scopes: &[],
            },
            rclone_options: &[],
        }
    }

    /// HiDrive configuration (OAuth)
    fn hidrive() -> Self {
        Self {
            provider: CloudProvider::HiDrive,
            oauth: OAuthConfig {
                client_id: "f3a5e856480f4c75b024e4a1aa18f899",
                client_secret: "",
                auth_url: "https://my.hidrive.com/client/authorize",
                token_url: "https://my.hidrive.com/oauth2/token",
                scopes: &["admin.rw"],
            },
            rclone_options: &[],
        }
    }

    /// Jottacloud configuration (OAuth)
    fn jottacloud() -> Self {
        Self {
            provider: CloudProvider::Jottacloud,
            oauth: OAuthConfig {
                client_id: "jottacli",
                client_secret: "",
                auth_url: "https://id.jottacloud.com/auth/authorize",
                token_url: "https://id.jottacloud.com/auth/token",
                scopes: &["openid", "offline_access"],
            },
            rclone_options: &[],
        }
    }

    /// Mail.ru Cloud configuration (OAuth)
    fn mailru() -> Self {
        Self {
            provider: CloudProvider::Mailru,
            oauth: OAuthConfig {
                client_id: "cOBJ0MlEMnKlhFAdIy0edANnGeVjjgWl",
                client_secret: "",
                auth_url: "https://o2.mail.ru/login",
                token_url: "https://o2.mail.ru/token",
                scopes: &[],
            },
            rclone_options: &[],
        }
    }

    /// PikPak configuration (OAuth)
    fn pikpak() -> Self {
        Self {
            provider: CloudProvider::PikPak,
            oauth: OAuthConfig {
                client_id: "YNxT9w7GMdWvEOKa",
                client_secret: "dbw2OtmVEeuUvIptb1Coyg",
                auth_url: "https://user.mypikpak.com/v1/auth/signin",
                token_url: "https://user.mypikpak.com/v1/auth/token",
                scopes: &[],
            },
            rclone_options: &[],
        }
    }

    /// Premiumize.me configuration (OAuth)
    fn premiumizeme() -> Self {
        Self {
            provider: CloudProvider::PremiumizeMe,
            oauth: OAuthConfig {
                client_id: "GV1OAR2DOtY6YoI",
                client_secret: "",
                auth_url: "https://www.premiumize.me/authorize",
                token_url: "https://www.premiumize.me/token",
                scopes: &[],
            },
            rclone_options: &[],
        }
    }

    /// put.io configuration (OAuth)
    fn putio() -> Self {
        Self {
            provider: CloudProvider::Putio,
            oauth: OAuthConfig {
                client_id: "4575",
                client_secret: "",
                auth_url: "https://app.put.io/v2/oauth2/authenticate",
                token_url: "https://api.put.io/v2/oauth2/access_token",
                scopes: &[],
            },
            rclone_options: &[],
        }
    }

    /// Citrix ShareFile configuration (OAuth)
    fn sharefile() -> Self {
        Self {
            provider: CloudProvider::ShareFile,
            oauth: OAuthConfig {
                client_id: "djhjUbBz4zCyjFnS",
                client_secret: "",
                auth_url: "https://secure.sharefile.com/oauth/authorize",
                token_url: "https://secure.sharefile.com/oauth/token",
                scopes: &[],
            },
            rclone_options: &[],
        }
    }

    /// SugarSync configuration (OAuth)
    fn sugarsync() -> Self {
        Self {
            provider: CloudProvider::SugarSync,
            oauth: OAuthConfig {
                client_id: "/sc/569344/49_3OoFnJKO4Mh0",
                client_secret: "",
                auth_url: "https://api.sugarsync.com/authorization",
                token_url: "https://api.sugarsync.com/app-authorization",
                scopes: &[],
            },
            rclone_options: &[],
        }
    }

    /// Yandex Disk configuration (OAuth)
    fn yandex() -> Self {
        Self {
            provider: CloudProvider::YandexDisk,
            oauth: OAuthConfig {
                client_id: "2018091340eb45cf8a0c735fc8e82ccf",
                client_secret: "3ea4a9a4e7014858b54e46e96cd07b41",
                auth_url: "https://oauth.yandex.com/authorize",
                token_url: "https://oauth.yandex.com/token",
                scopes: &[],
            },
            rclone_options: &[],
        }
    }

    /// Zoho WorkDrive configuration (OAuth)
    fn zoho() -> Self {
        Self {
            provider: CloudProvider::Zoho,
            oauth: OAuthConfig {
                client_id: "1000.46TVW3B5RBBRJKR2AF574CC41SKWWM",
                client_secret: "",
                auth_url: "https://accounts.zoho.com/oauth/v2/auth",
                token_url: "https://accounts.zoho.com/oauth/v2/token",
                scopes: &[
                    "aaaserver.profile.read",
                    "WorkDrive.team.READ",
                    "WorkDrive.workspace.READ",
                    "WorkDrive.files.ALL",
                ],
            },
            rclone_options: &[],
        }
    }

    /// Check if this provider uses OAuth
    pub fn uses_oauth(&self) -> bool {
        !self.oauth.client_id.is_empty()
    }

    /// Build OAuth authorization URL
    pub fn build_auth_url(&self, redirect_uri: &str, state: Option<&str>) -> String {
        self.build_auth_url_with_client_id(self.oauth.client_id, redirect_uri, state)
    }

    /// Build OAuth authorization URL with a custom client_id
    pub fn build_auth_url_with_client_id(
        &self,
        client_id: &str,
        redirect_uri: &str,
        state: Option<&str>,
    ) -> String {
        let mut url = format!(
            "{}?client_id={}&redirect_uri={}&response_type=code",
            self.oauth.auth_url,
            urlencoded(client_id),
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
        match self.provider {
            CloudProvider::Dropbox => {
                url.push_str("&token_access_type=offline");
            }
            CloudProvider::GoogleDrive | CloudProvider::GooglePhotos => {
                // Required for Google to return a refresh_token
                url.push_str("&access_type=offline&prompt=consent");
            }
            _ => {}
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
        assert!(ProviderConfig::for_provider(CloudProvider::GooglePhotos).uses_oauth());
        assert!(ProviderConfig::for_provider(CloudProvider::PCloud).uses_oauth());
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
