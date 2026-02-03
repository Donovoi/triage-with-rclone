//! Utility helpers (formatting, networking, HTTP, Windows helpers).

pub mod format;
pub mod http;
pub mod network;
pub mod time;
pub mod windows;

pub use format::format_bytes;
pub use http::http_get_json_with_retry;
pub use network::get_local_ip_address;
pub use time::sleep_with_countdown;
pub use windows::{close_window_by_title, window_exists};
