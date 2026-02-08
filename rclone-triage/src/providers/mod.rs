//! Cloud provider support
//!
//! Defines supported cloud providers and their configurations.

pub mod auth;
pub mod browser;
pub mod config;
pub mod credentials;
pub mod discovery;
pub mod features;
pub mod mobile;
pub mod schema;
pub mod session;

use serde::{Deserialize, Serialize};
use std::fmt;
use std::str::FromStr;

/// Best-effort classification of how a backend is typically authenticated.
///
/// This is used to gate UI flows so we don't offer OAuth/mobile auth on backends that
/// require API keys or other manual configuration.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize, Default)]
pub enum ProviderAuthKind {
    /// Auth mechanism could not be determined from `rclone config providers`.
    #[default]
    Unknown,
    /// OAuth-style interactive authorization (`rclone authorize` / auth URL).
    OAuth,
    /// Key-based auth (access keys, API keys, secrets).
    KeyBased,
    /// Username/password or similar manual credential entry.
    UserPass,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProviderEntry {
    pub id: String,
    pub name: String,
    pub description: Option<String>,
    pub known: Option<CloudProvider>,
    pub oauth_capable: bool,
    #[serde(default)]
    pub auth_kind: ProviderAuthKind,
}

impl ProviderEntry {
    pub fn display_name(&self) -> &str {
        &self.name
    }

    pub fn description(&self) -> Option<&str> {
        self.description.as_deref()
    }

    pub fn oauth_capable(&self) -> bool {
        self.oauth_capable
    }

    pub fn auth_kind(&self) -> ProviderAuthKind {
        self.auth_kind
    }

    pub fn short_name(&self) -> &str {
        &self.id
    }

    pub fn from_known(provider: CloudProvider) -> Self {
        let uses_oauth =
            crate::providers::config::ProviderConfig::for_provider(provider).uses_oauth();
        let auth_kind = if uses_oauth {
            ProviderAuthKind::OAuth
        } else {
            ProviderAuthKind::UserPass
        };
        Self {
            id: provider.rclone_type().to_string(),
            name: provider.display_name().to_string(),
            description: None,
            known: Some(provider),
            oauth_capable: uses_oauth,
            auth_kind,
        }
    }

    pub fn sort_entries(entries: &mut [ProviderEntry]) {
        entries.sort_by(|a, b| {
            let left = a.display_name().to_ascii_lowercase();
            let right = b.display_name().to_ascii_lowercase();
            left.cmp(&right).then_with(|| a.id.cmp(&b.id))
        });
    }
}

/// Supported cloud providers
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum CloudProvider {
    /// Google Drive
    GoogleDrive,
    /// Microsoft OneDrive
    OneDrive,
    /// Dropbox
    Dropbox,
    /// Box
    Box,
    /// Apple iCloud Drive
    ICloud,
    /// Google Photos
    GooglePhotos,
    /// pCloud
    PCloud,
}

impl CloudProvider {
    /// Get all supported providers
    pub fn all() -> &'static [CloudProvider] {
        &[
            CloudProvider::GoogleDrive,
            CloudProvider::OneDrive,
            CloudProvider::Dropbox,
            CloudProvider::Box,
            CloudProvider::ICloud,
            CloudProvider::GooglePhotos,
            CloudProvider::PCloud,
        ]
    }

    pub fn entries() -> Vec<ProviderEntry> {
        Self::all().iter().copied().map(ProviderEntry::from_known).collect()
    }

    /// Get the rclone remote type for this provider
    pub fn rclone_type(&self) -> &'static str {
        match self {
            CloudProvider::GoogleDrive => "drive",
            CloudProvider::OneDrive => "onedrive",
            CloudProvider::Dropbox => "dropbox",
            CloudProvider::Box => "box",
            CloudProvider::ICloud => "iclouddrive",
            CloudProvider::GooglePhotos => "gphotos",
            CloudProvider::PCloud => "pcloud",
        }
    }

    /// Get the display name for this provider
    pub fn display_name(&self) -> &'static str {
        match self {
            CloudProvider::GoogleDrive => "Google Drive",
            CloudProvider::OneDrive => "Microsoft OneDrive",
            CloudProvider::Dropbox => "Dropbox",
            CloudProvider::Box => "Box",
            CloudProvider::ICloud => "iCloud Drive",
            CloudProvider::GooglePhotos => "Google Photos",
            CloudProvider::PCloud => "pCloud",
        }
    }

    /// Get the short name (for file naming)
    pub fn short_name(&self) -> &'static str {
        match self {
            CloudProvider::GoogleDrive => "gdrive",
            CloudProvider::OneDrive => "onedrive",
            CloudProvider::Dropbox => "dropbox",
            CloudProvider::Box => "box",
            CloudProvider::ICloud => "icloud",
            CloudProvider::GooglePhotos => "gphotos",
            CloudProvider::PCloud => "pcloud",
        }
    }

    /// Get supported hash types for this provider
    pub fn hash_types(&self) -> &'static [&'static str] {
        match self {
            CloudProvider::GoogleDrive => &["md5", "sha1", "sha256"],
            CloudProvider::OneDrive => &["quickxorhash"],
            CloudProvider::Dropbox => &["dropbox"],
            CloudProvider::Box => &["sha1"],
            CloudProvider::ICloud => &[],
            CloudProvider::GooglePhotos => &[],
            CloudProvider::PCloud => &["sha1", "md5"],
        }
    }

    /// Returns true if token-based user info extraction is expected to work.
    pub fn supports_token_user_info(&self) -> bool {
        !matches!(self, CloudProvider::ICloud | CloudProvider::PCloud)
    }
}

impl fmt::Display for CloudProvider {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.display_name())
    }
}

impl FromStr for CloudProvider {
    type Err = String;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s.to_lowercase().as_str() {
            "googledrive" | "google_drive" | "gdrive" | "drive" => Ok(CloudProvider::GoogleDrive),
            "onedrive" | "one_drive" | "microsoft" => Ok(CloudProvider::OneDrive),
            "dropbox" => Ok(CloudProvider::Dropbox),
            "box" => Ok(CloudProvider::Box),
            "icloud" | "iclouddrive" | "icloud_drive" => Ok(CloudProvider::ICloud),
            "gphotos" | "googlephotos" | "google_photos" | "google photos" => {
                Ok(CloudProvider::GooglePhotos)
            }
            "pcloud" => Ok(CloudProvider::PCloud),
            _ => Err(format!("Unknown provider: {}", s)),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_provider_roundtrip() {
        for provider in CloudProvider::all() {
            let s = provider.short_name();
            let parsed: CloudProvider = s.parse().unwrap();
            assert_eq!(*provider, parsed);
        }
    }

    #[test]
    fn test_display() {
        assert_eq!(CloudProvider::GoogleDrive.to_string(), "Google Drive");
        assert_eq!(CloudProvider::OneDrive.to_string(), "Microsoft OneDrive");
    }

    #[test]
    fn test_rclone_type() {
        assert_eq!(CloudProvider::GoogleDrive.rclone_type(), "drive");
        assert_eq!(CloudProvider::OneDrive.rclone_type(), "onedrive");
    }
}
