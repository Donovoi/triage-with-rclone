//! Forensics module
//!
//! Contains forensic-focused utilities for:
//! - System state snapshots (before/after comparison)
//! - Hash-chained logging
//! - Change tracking and documentation

pub mod changes;
pub mod access_point;
pub mod logger;
pub mod onedrive_vault;
pub mod state;

pub use access_point::{
    get_forensic_access_point_status, generate_password, render_wifi_qr,
    start_forensic_access_point, start_forensic_ap_timer, stop_forensic_access_point,
    wait_for_usb_wifi_adapter, ForensicAccessPointInfo, ForensicAccessPointStatus,
};
pub use changes::ChangeTracker;
pub use logger::ForensicLogger;
pub use onedrive_vault::{open_onedrive_vault, OneDriveVaultResult};
pub use state::SystemStateSnapshot;
