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

// Common re-exports for convenience in integration tests or downstream tools.
pub use case::Case;
pub use cleanup::Cleanup;
pub use files::*;
pub use forensics::*;
pub use ui::*;
