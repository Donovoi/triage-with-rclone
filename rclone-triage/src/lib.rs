//! rclone-triage library crate
//!
//! Exposes internal modules for integration tests and reuse by the binary.

pub mod case;
pub mod cleanup;
pub mod embedded;
pub mod files;
pub mod forensics;
pub mod providers;
pub mod rclone;
pub mod ui;
pub mod utils;

// Named re-exports used by the binary crate and integration tests.
pub use case::Case;
pub use cleanup::Cleanup;
pub use files::{list_path, FileEntry, ListPathOptions};
pub use forensics::{
    generate_password, get_forensic_access_point_status, open_onedrive_vault, render_wifi_qr,
    start_forensic_access_point, stop_forensic_access_point, SystemStateSnapshot,
};
pub use ui::App;
