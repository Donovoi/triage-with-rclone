//! Rclone integration module
//!
//! Provides functionality for:
//! - Running rclone processes
//! - Managing rclone configuration
//! - OAuth authentication flows
//! - Mounting remotes as local filesystems

pub mod config;
pub mod connectivity;
pub mod mount;
pub mod oauth;
pub mod process;
pub mod web;

pub use config::{OAuthToken, ParsedConfig, RcloneConfig, RemoteSection, UserInfo};
pub use connectivity::{test_connectivity, ConnectivityResult};
pub use mount::{open_file_explorer, MountManager, MountedRemote};
pub use oauth::OAuthFlow;
pub use process::{RcloneOutput, RcloneRunner};
pub use web::{start_web_gui, WebGuiProcess};
