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
    /// Azure Blob Storage
    AzureBlob,
    /// Azure Files
    AzureFiles,
    /// Backblaze B2
    B2,
    /// Cloudinary
    Cloudinary,
    /// Doi (Digital Object Identifier)
    Doi,
    /// Drime
    Drime,
    /// 1Fichier
    Fichier,
    /// Enterprise File Fabric
    FileFabric,
    /// Filelu
    Filelu,
    /// Filen
    Filen,
    /// Files.com
    FilesCom,
    /// FTP
    Ftp,
    /// Gofile
    Gofile,
    /// Google Cloud Storage
    GoogleCloudStorage,
    /// HDFS (Hadoop Distributed File System)
    Hdfs,
    /// HiDrive
    HiDrive,
    /// HTTP
    Http,
    /// ImageKit
    ImageKit,
    /// Internet Archive
    InternetArchive,
    /// Internxt
    Internxt,
    /// Jottacloud
    Jottacloud,
    /// Koofr
    Koofr,
    /// Linkbox
    Linkbox,
    /// Local filesystem
    Local,
    /// Mail.ru Cloud
    Mailru,
    /// Mega
    Mega,
    /// Memory (in-memory storage)
    Memory,
    /// Akamai NetStorage
    NetStorage,
    /// OpenDrive
    OpenDrive,
    /// Oracle Object Storage
    OracleObjectStorage,
    /// PikPak
    PikPak,
    /// Pixeldrain
    Pixeldrain,
    /// Premiumize.me
    PremiumizeMe,
    /// Proton Drive
    ProtonDrive,
    /// put.io
    Putio,
    /// QingStor
    QingStor,
    /// Quatrix by Maytech
    Quatrix,
    /// S3-compatible (AWS, Minio, etc.)
    S3,
    /// Seafile
    Seafile,
    /// SFTP
    Sftp,
    /// Shade (Stora)
    Shade,
    /// Citrix ShareFile
    ShareFile,
    /// Sia
    Sia,
    /// SMB / CIFS
    Smb,
    /// Storj
    Storj,
    /// SugarSync
    SugarSync,
    /// OpenStack Swift
    Swift,
    /// Uloz.to
    Ulozto,
    /// WebDAV
    WebDav,
    /// Yandex Disk
    YandexDisk,
    /// Zoho WorkDrive
    Zoho,
}

impl CloudProvider {
    /// Get all supported providers
    pub fn all() -> &'static [CloudProvider] {
        &[
            CloudProvider::AzureBlob,
            CloudProvider::AzureFiles,
            CloudProvider::B2,
            CloudProvider::Box,
            CloudProvider::Cloudinary,
            CloudProvider::Doi,
            CloudProvider::Drime,
            CloudProvider::GoogleDrive,
            CloudProvider::Dropbox,
            CloudProvider::Fichier,
            CloudProvider::FileFabric,
            CloudProvider::Filelu,
            CloudProvider::Filen,
            CloudProvider::FilesCom,
            CloudProvider::Ftp,
            CloudProvider::Gofile,
            CloudProvider::GoogleCloudStorage,
            CloudProvider::GooglePhotos,
            CloudProvider::Hdfs,
            CloudProvider::HiDrive,
            CloudProvider::Http,
            CloudProvider::ICloud,
            CloudProvider::ImageKit,
            CloudProvider::InternetArchive,
            CloudProvider::Internxt,
            CloudProvider::Jottacloud,
            CloudProvider::Koofr,
            CloudProvider::Linkbox,
            CloudProvider::Local,
            CloudProvider::Mailru,
            CloudProvider::Mega,
            CloudProvider::Memory,
            CloudProvider::NetStorage,
            CloudProvider::OneDrive,
            CloudProvider::OpenDrive,
            CloudProvider::OracleObjectStorage,
            CloudProvider::PCloud,
            CloudProvider::PikPak,
            CloudProvider::Pixeldrain,
            CloudProvider::PremiumizeMe,
            CloudProvider::ProtonDrive,
            CloudProvider::Putio,
            CloudProvider::QingStor,
            CloudProvider::Quatrix,
            CloudProvider::S3,
            CloudProvider::Seafile,
            CloudProvider::Sftp,
            CloudProvider::Shade,
            CloudProvider::ShareFile,
            CloudProvider::Sia,
            CloudProvider::Smb,
            CloudProvider::Storj,
            CloudProvider::SugarSync,
            CloudProvider::Swift,
            CloudProvider::Ulozto,
            CloudProvider::WebDav,
            CloudProvider::YandexDisk,
            CloudProvider::Zoho,
        ]
    }

    pub fn entries() -> Vec<ProviderEntry> {
        Self::all().iter().copied().map(ProviderEntry::from_known).collect()
    }

    /// Get the rclone remote type for this provider
    pub fn rclone_type(&self) -> &'static str {
        match self {
            CloudProvider::AzureBlob => "azureblob",
            CloudProvider::AzureFiles => "azurefiles",
            CloudProvider::B2 => "b2",
            CloudProvider::Box => "box",
            CloudProvider::Cloudinary => "cloudinary",
            CloudProvider::Doi => "doi",
            CloudProvider::Drime => "drime",
            CloudProvider::GoogleDrive => "drive",
            CloudProvider::Dropbox => "dropbox",
            CloudProvider::Fichier => "fichier",
            CloudProvider::FileFabric => "filefabric",
            CloudProvider::Filelu => "filelu",
            CloudProvider::Filen => "filen",
            CloudProvider::FilesCom => "filescom",
            CloudProvider::Ftp => "ftp",
            CloudProvider::Gofile => "gofile",
            CloudProvider::GoogleCloudStorage => "gcs",
            CloudProvider::GooglePhotos => "gphotos",
            CloudProvider::Hdfs => "hdfs",
            CloudProvider::HiDrive => "hidrive",
            CloudProvider::Http => "http",
            CloudProvider::ICloud => "iclouddrive",
            CloudProvider::ImageKit => "imagekit",
            CloudProvider::InternetArchive => "internetarchive",
            CloudProvider::Internxt => "internxt",
            CloudProvider::Jottacloud => "jottacloud",
            CloudProvider::Koofr => "koofr",
            CloudProvider::Linkbox => "linkbox",
            CloudProvider::Local => "local",
            CloudProvider::Mailru => "mailru",
            CloudProvider::Mega => "mega",
            CloudProvider::Memory => "memory",
            CloudProvider::NetStorage => "netstorage",
            CloudProvider::OneDrive => "onedrive",
            CloudProvider::OpenDrive => "opendrive",
            CloudProvider::OracleObjectStorage => "oracleobjectstorage",
            CloudProvider::PCloud => "pcloud",
            CloudProvider::PikPak => "pikpak",
            CloudProvider::Pixeldrain => "pixeldrain",
            CloudProvider::PremiumizeMe => "premiumizeme",
            CloudProvider::ProtonDrive => "protondrive",
            CloudProvider::Putio => "putio",
            CloudProvider::QingStor => "qingstor",
            CloudProvider::Quatrix => "quatrix",
            CloudProvider::S3 => "s3",
            CloudProvider::Seafile => "seafile",
            CloudProvider::Sftp => "sftp",
            CloudProvider::Shade => "shade",
            CloudProvider::ShareFile => "sharefile",
            CloudProvider::Sia => "sia",
            CloudProvider::Smb => "smb",
            CloudProvider::Storj => "storj",
            CloudProvider::SugarSync => "sugarsync",
            CloudProvider::Swift => "swift",
            CloudProvider::Ulozto => "ulozto",
            CloudProvider::WebDav => "webdav",
            CloudProvider::YandexDisk => "yandex",
            CloudProvider::Zoho => "zoho",
        }
    }

    /// Get the display name for this provider
    pub fn display_name(&self) -> &'static str {
        match self {
            CloudProvider::AzureBlob => "Azure Blob",
            CloudProvider::AzureFiles => "Azure Files",
            CloudProvider::B2 => "Backblaze B2",
            CloudProvider::Box => "Box",
            CloudProvider::Cloudinary => "Cloudinary",
            CloudProvider::Doi => "Doi",
            CloudProvider::Drime => "Drime",
            CloudProvider::GoogleDrive => "Google Drive",
            CloudProvider::Dropbox => "Dropbox",
            CloudProvider::Fichier => "1Fichier",
            CloudProvider::FileFabric => "Enterprise File Fabric",
            CloudProvider::Filelu => "Filelu",
            CloudProvider::Filen => "Filen",
            CloudProvider::FilesCom => "Files.com",
            CloudProvider::Ftp => "FTP",
            CloudProvider::Gofile => "Gofile",
            CloudProvider::GoogleCloudStorage => "Google Cloud Storage",
            CloudProvider::GooglePhotos => "Google Photos",
            CloudProvider::Hdfs => "HDFS",
            CloudProvider::HiDrive => "HiDrive",
            CloudProvider::Http => "HTTP",
            CloudProvider::ICloud => "iCloud Drive",
            CloudProvider::ImageKit => "ImageKit",
            CloudProvider::InternetArchive => "Internet Archive",
            CloudProvider::Internxt => "Internxt",
            CloudProvider::Jottacloud => "Jottacloud",
            CloudProvider::Koofr => "Koofr",
            CloudProvider::Linkbox => "Linkbox",
            CloudProvider::Local => "Local",
            CloudProvider::Mailru => "Mail.ru Cloud",
            CloudProvider::Mega => "Mega",
            CloudProvider::Memory => "Memory",
            CloudProvider::NetStorage => "Akamai NetStorage",
            CloudProvider::OneDrive => "Microsoft OneDrive",
            CloudProvider::OpenDrive => "OpenDrive",
            CloudProvider::OracleObjectStorage => "Oracle Object Storage",
            CloudProvider::PCloud => "pCloud",
            CloudProvider::PikPak => "PikPak",
            CloudProvider::Pixeldrain => "Pixeldrain",
            CloudProvider::PremiumizeMe => "Premiumize.me",
            CloudProvider::ProtonDrive => "Proton Drive",
            CloudProvider::Putio => "put.io",
            CloudProvider::QingStor => "QingStor",
            CloudProvider::Quatrix => "Quatrix",
            CloudProvider::S3 => "S3",
            CloudProvider::Seafile => "Seafile",
            CloudProvider::Sftp => "SFTP",
            CloudProvider::Shade => "Shade",
            CloudProvider::ShareFile => "Citrix ShareFile",
            CloudProvider::Sia => "Sia",
            CloudProvider::Smb => "SMB",
            CloudProvider::Storj => "Storj",
            CloudProvider::SugarSync => "SugarSync",
            CloudProvider::Swift => "OpenStack Swift",
            CloudProvider::Ulozto => "Uloz.to",
            CloudProvider::WebDav => "WebDAV",
            CloudProvider::YandexDisk => "Yandex Disk",
            CloudProvider::Zoho => "Zoho WorkDrive",
        }
    }

    /// Get the short name (for file naming)
    pub fn short_name(&self) -> &'static str {
        match self {
            CloudProvider::AzureBlob => "azureblob",
            CloudProvider::AzureFiles => "azurefiles",
            CloudProvider::B2 => "b2",
            CloudProvider::Box => "box",
            CloudProvider::Cloudinary => "cloudinary",
            CloudProvider::Doi => "doi",
            CloudProvider::Drime => "drime",
            CloudProvider::GoogleDrive => "gdrive",
            CloudProvider::Dropbox => "dropbox",
            CloudProvider::Fichier => "fichier",
            CloudProvider::FileFabric => "filefabric",
            CloudProvider::Filelu => "filelu",
            CloudProvider::Filen => "filen",
            CloudProvider::FilesCom => "filescom",
            CloudProvider::Ftp => "ftp",
            CloudProvider::Gofile => "gofile",
            CloudProvider::GoogleCloudStorage => "gcs",
            CloudProvider::GooglePhotos => "gphotos",
            CloudProvider::Hdfs => "hdfs",
            CloudProvider::HiDrive => "hidrive",
            CloudProvider::Http => "http",
            CloudProvider::ICloud => "icloud",
            CloudProvider::ImageKit => "imagekit",
            CloudProvider::InternetArchive => "internetarchive",
            CloudProvider::Internxt => "internxt",
            CloudProvider::Jottacloud => "jottacloud",
            CloudProvider::Koofr => "koofr",
            CloudProvider::Linkbox => "linkbox",
            CloudProvider::Local => "local",
            CloudProvider::Mailru => "mailru",
            CloudProvider::Mega => "mega",
            CloudProvider::Memory => "memory",
            CloudProvider::NetStorage => "netstorage",
            CloudProvider::OneDrive => "onedrive",
            CloudProvider::OpenDrive => "opendrive",
            CloudProvider::OracleObjectStorage => "oos",
            CloudProvider::PCloud => "pcloud",
            CloudProvider::PikPak => "pikpak",
            CloudProvider::Pixeldrain => "pixeldrain",
            CloudProvider::PremiumizeMe => "premiumizeme",
            CloudProvider::ProtonDrive => "protondrive",
            CloudProvider::Putio => "putio",
            CloudProvider::QingStor => "qingstor",
            CloudProvider::Quatrix => "quatrix",
            CloudProvider::S3 => "s3",
            CloudProvider::Seafile => "seafile",
            CloudProvider::Sftp => "sftp",
            CloudProvider::Shade => "shade",
            CloudProvider::ShareFile => "sharefile",
            CloudProvider::Sia => "sia",
            CloudProvider::Smb => "smb",
            CloudProvider::Storj => "storj",
            CloudProvider::SugarSync => "sugarsync",
            CloudProvider::Swift => "swift",
            CloudProvider::Ulozto => "ulozto",
            CloudProvider::WebDav => "webdav",
            CloudProvider::YandexDisk => "yandex",
            CloudProvider::Zoho => "zoho",
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
            CloudProvider::AzureBlob => &["md5"],
            CloudProvider::AzureFiles => &["md5"],
            CloudProvider::B2 => &["sha1"],
            CloudProvider::GoogleCloudStorage => &["md5", "crc32"],
            CloudProvider::S3 => &["md5"],
            CloudProvider::Swift => &["md5"],
            CloudProvider::Mega => &[],
            CloudProvider::Jottacloud => &["md5"],
            CloudProvider::Koofr => &["md5"],
            CloudProvider::Mailru => &["md5"],
            CloudProvider::YandexDisk => &["md5", "sha256"],
            CloudProvider::Seafile => &[],
            CloudProvider::Putio => &["crc32"],
            CloudProvider::HiDrive => &["md5", "sha1", "sha256", "crc32"],
            CloudProvider::Storj => &[],
            CloudProvider::SugarSync => &[],
            CloudProvider::ShareFile => &["md5"],
            CloudProvider::Ftp => &[],
            CloudProvider::Sftp => &["md5", "sha1"],
            CloudProvider::WebDav => &["md5", "sha1"],
            CloudProvider::Http => &[],
            CloudProvider::QingStor => &["md5"],
            CloudProvider::OracleObjectStorage => &["md5", "sha256"],
            CloudProvider::PikPak => &["md5"],
            CloudProvider::Hdfs => &[],
            CloudProvider::Local => &["md5", "sha1", "sha256"],
            CloudProvider::Fichier => &["whirlpool"],
            CloudProvider::FileFabric => &[],
            CloudProvider::OpenDrive => &["md5"],
            CloudProvider::Quatrix => &[],
            CloudProvider::PremiumizeMe => &[],
            CloudProvider::Zoho => &[],
            CloudProvider::ProtonDrive => &["sha1"],
            CloudProvider::Smb => &[],
            CloudProvider::Sia => &[],
            CloudProvider::Linkbox => &[],
            CloudProvider::InternetArchive => &["md5", "sha1", "crc32"],
            CloudProvider::NetStorage => &["md5", "sha256"],
            CloudProvider::Pixeldrain => &["sha256"],
            CloudProvider::Gofile => &["md5"],
            CloudProvider::Ulozto => &["md5", "sha256"],
            CloudProvider::Cloudinary => &[],
            CloudProvider::Doi => &[],
            CloudProvider::Drime => &[],
            CloudProvider::Filelu => &[],
            CloudProvider::Filen => &[],
            CloudProvider::FilesCom => &["md5"],
            CloudProvider::ImageKit => &[],
            CloudProvider::Internxt => &[],
            CloudProvider::Memory => &["md5"],
            CloudProvider::Shade => &["md5"],
        }
    }

    /// Returns true if token-based user info extraction is expected to work.
    pub fn supports_token_user_info(&self) -> bool {
        matches!(
            self,
            CloudProvider::GoogleDrive
                | CloudProvider::OneDrive
                | CloudProvider::Dropbox
                | CloudProvider::Box
                | CloudProvider::GooglePhotos
                | CloudProvider::YandexDisk
                | CloudProvider::Mailru
                | CloudProvider::HiDrive
                | CloudProvider::Jottacloud
                | CloudProvider::Zoho
        )
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
            "azureblob" | "azure_blob" => Ok(CloudProvider::AzureBlob),
            "azurefiles" | "azure_files" => Ok(CloudProvider::AzureFiles),
            "b2" | "backblaze" | "backblazeb2" => Ok(CloudProvider::B2),
            "cloudinary" => Ok(CloudProvider::Cloudinary),
            "doi" => Ok(CloudProvider::Doi),
            "drime" => Ok(CloudProvider::Drime),
            "fichier" | "1fichier" => Ok(CloudProvider::Fichier),
            "filefabric" | "file_fabric" => Ok(CloudProvider::FileFabric),
            "filelu" => Ok(CloudProvider::Filelu),
            "filen" => Ok(CloudProvider::Filen),
            "filescom" | "files.com" | "files_com" => Ok(CloudProvider::FilesCom),
            "ftp" => Ok(CloudProvider::Ftp),
            "gofile" => Ok(CloudProvider::Gofile),
            "gcs" | "googlecloudstorage" | "google_cloud_storage" => {
                Ok(CloudProvider::GoogleCloudStorage)
            }
            "hdfs" => Ok(CloudProvider::Hdfs),
            "hidrive" => Ok(CloudProvider::HiDrive),
            "http" => Ok(CloudProvider::Http),
            "imagekit" => Ok(CloudProvider::ImageKit),
            "internetarchive" | "internet_archive" => Ok(CloudProvider::InternetArchive),
            "internxt" => Ok(CloudProvider::Internxt),
            "jottacloud" => Ok(CloudProvider::Jottacloud),
            "koofr" => Ok(CloudProvider::Koofr),
            "linkbox" => Ok(CloudProvider::Linkbox),
            "local" => Ok(CloudProvider::Local),
            "mailru" | "mail.ru" | "mail_ru" => Ok(CloudProvider::Mailru),
            "mega" => Ok(CloudProvider::Mega),
            "memory" => Ok(CloudProvider::Memory),
            "netstorage" | "akamai" => Ok(CloudProvider::NetStorage),
            "opendrive" | "open_drive" => Ok(CloudProvider::OpenDrive),
            "oracleobjectstorage" | "oos" | "oracle" => Ok(CloudProvider::OracleObjectStorage),
            "pikpak" => Ok(CloudProvider::PikPak),
            "pixeldrain" => Ok(CloudProvider::Pixeldrain),
            "premiumizeme" | "premiumize" => Ok(CloudProvider::PremiumizeMe),
            "protondrive" | "proton" | "proton_drive" => Ok(CloudProvider::ProtonDrive),
            "putio" | "put.io" => Ok(CloudProvider::Putio),
            "qingstor" => Ok(CloudProvider::QingStor),
            "quatrix" => Ok(CloudProvider::Quatrix),
            "s3" | "aws" | "minio" => Ok(CloudProvider::S3),
            "seafile" => Ok(CloudProvider::Seafile),
            "sftp" | "ssh" => Ok(CloudProvider::Sftp),
            "shade" | "stora" => Ok(CloudProvider::Shade),
            "sharefile" | "citrix" => Ok(CloudProvider::ShareFile),
            "sia" => Ok(CloudProvider::Sia),
            "smb" | "cifs" => Ok(CloudProvider::Smb),
            "storj" => Ok(CloudProvider::Storj),
            "sugarsync" | "sugar_sync" => Ok(CloudProvider::SugarSync),
            "swift" | "openstack" => Ok(CloudProvider::Swift),
            "ulozto" | "uloz.to" => Ok(CloudProvider::Ulozto),
            "webdav" => Ok(CloudProvider::WebDav),
            "yandex" | "yandexdisk" | "yandex_disk" => Ok(CloudProvider::YandexDisk),
            "zoho" | "zohoworkdrive" => Ok(CloudProvider::Zoho),
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
