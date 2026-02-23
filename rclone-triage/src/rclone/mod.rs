//! Rclone integration module
//!
//! Provides functionality for:
//! - Running rclone processes
//! - Managing rclone configuration
//! - OAuth authentication flows
//! - Mounting remotes as local filesystems

pub mod authorize;
pub mod config;
pub mod connectivity;
pub mod mount;
pub mod oauth;
pub mod process;
pub mod web;

pub use authorize::{authorize_fallback, AuthorizeFallbackResult};
pub use config::{
    OAuthCredentialStatus, OAuthToken, ParsedConfig, RcloneConfig, RemoteSection, UserInfo,
};
pub use connectivity::{retry_delay, test_connectivity, test_connectivity_with_retry, ConnectivityResult};
pub use mount::{open_file_explorer, MountManager, MountedRemote};
pub use oauth::OAuthFlow;
pub use process::{RcloneOutput, RcloneRunner};
pub use web::{start_web_gui, WebGuiProcess};
