//! Rclone integration module
//!
//! Provides functionality for:
//! - Running rclone processes
//! - Managing rclone configuration
//! - OAuth authentication flows
//! - Mounting remotes as local filesystems

pub mod config;
pub mod mount;
pub mod oauth;
pub mod process;

pub use config::{OAuthToken, ParsedConfig, RcloneConfig, RemoteSection, UserInfo};
pub use mount::{open_file_explorer, MountManager, MountedRemote};
pub use oauth::OAuthFlow;
pub use process::{RcloneOutput, RcloneRunner};
