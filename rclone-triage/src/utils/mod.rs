//! Utility helpers (networking, path sanitization, Windows helpers).

pub mod network;
pub mod path;
pub mod windows;

pub use network::get_local_ip_address;
pub use path::{safe_join_under, SafeMappedPath};
pub use windows::{close_window_by_title, invoke_button_press, open_file_dialog, window_exists};
