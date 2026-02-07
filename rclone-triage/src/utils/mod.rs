//! Utility helpers (formatting, networking, HTTP, Windows helpers).

pub mod format;
pub mod http;
pub mod network;
pub mod path;
pub mod time;
pub mod windows;

pub use format::format_bytes;
pub use http::http_get_json_with_retry;
pub use network::get_local_ip_address;
pub use path::{safe_join_under, SafeMappedPath};
pub use time::sleep_with_countdown;
pub use windows::{close_window_by_title, invoke_button_press, open_file_dialog, window_exists};
