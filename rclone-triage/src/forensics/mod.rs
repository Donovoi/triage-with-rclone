//! Forensics module
//!
//! Contains forensic-focused utilities for:
//! - System state snapshots (before/after comparison)
//! - Hash-chained logging
//! - Change tracking and documentation

pub mod access_point;
pub mod changes;
pub mod logger;
pub mod onedrive_vault;
pub mod state;

pub use access_point::{
    generate_password, get_forensic_access_point_status, render_wifi_qr,
    start_forensic_access_point, start_forensic_access_point_with_status,
    stop_forensic_access_point, wait_for_usb_wifi_adapter, ForensicAccessPointInfo,
    ForensicAccessPointStatus,
};
pub use changes::ChangeTracker;
pub use logger::ForensicLogger;
pub use onedrive_vault::open_onedrive_vault;
pub use state::SystemStateSnapshot;
