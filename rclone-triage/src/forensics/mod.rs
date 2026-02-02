//! Forensics module
//!
//! Contains forensic-focused utilities for:
//! - System state snapshots (before/after comparison)
//! - Hash-chained logging
//! - Change tracking and documentation

pub mod changes;
pub mod logger;
pub mod state;

pub use changes::ChangeTracker;
pub use logger::ForensicLogger;
pub use state::SystemStateSnapshot;
