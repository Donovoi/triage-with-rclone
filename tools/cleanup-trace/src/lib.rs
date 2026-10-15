//! Default-off diagnostics only. Never changes the original removal result.
#[cfg(any(windows, test))]
mod admission;
#[cfg(any(windows, test))]
mod model;
#[cfg(windows)]
mod native;
#[cfg(any(windows, test))]
mod ownership;
#[cfg(windows)]
mod schema_metadata;
#[cfg(windows)]
pub use native::Trace;

#[cfg(any(windows, test))]
mod resource_use;
#[cfg(windows)]
mod resource_use_windows;

// Explicit ignored hosted calibration only; never an application/ordinary-test hook.
#[cfg(all(windows, test))]
mod resource_use_calibration;
