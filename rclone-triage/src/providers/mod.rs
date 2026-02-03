//! Cloud provider support
//!
//! Defines supported cloud providers and their configurations.

pub mod auth;
pub mod browser;
pub mod config;
pub mod credentials;
pub mod discovery;
pub mod mobile;
pub mod session;

use serde::{Deserialize, Serialize};
use std::fmt;
use std::str::FromStr;

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
        ]
    }

    /// Get the rclone remote type for this provider
    pub fn rclone_type(&self) -> &'static str {
        match self {
            CloudProvider::GoogleDrive => "drive",
            CloudProvider::OneDrive => "onedrive",
            CloudProvider::Dropbox => "dropbox",
            CloudProvider::Box => "box",
            CloudProvider::ICloud => "iclouddrive",
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
        }
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
