//! Default-off diagnostics only. Never changes the original removal result.
#[cfg(any(windows, test))]
mod model;
#[cfg(windows)]
mod native;
#[cfg(any(windows, test))]
mod ownership;
#[cfg(windows)]
pub use native::Trace;
