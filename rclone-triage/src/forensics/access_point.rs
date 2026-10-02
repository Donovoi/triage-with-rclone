//! Process-owned Windows hosted-network sessions with restoration of prior settings.
use anyhow::{bail, Result};
#[cfg(windows)]
#[path = "access_point_native.rs"]
mod native;

pub const ADGUARD_DNS_IPV4: [&str; 2] = ["94.140.14.14", "94.140.15.15"];
#[derive(Debug, Clone)]
pub struct ForensicAccessPointInfo {
    pub ssid: String,
    pub password: String,
    pub ip_address: String,
    pub dns_servers: Vec<String>,
    pub adapter_name: Option<String>,
    pub dns_configured: bool,
    pub dns_error: Option<String>,
}
#[derive(Debug, Clone)]
pub struct ForensicAccessPointStatus {
    pub active: bool,
    pub ssid: Option<String>,
    pub connected_clients: u32,
    pub adapter_name: Option<String>,
    pub ip_address: Option<String>,
}
pub fn generate_password() -> String {
    use rand::Rng;
    const CHARS: &[u8] = b"abcdefghjkmnpqrstuvwxyzABCDEFGHJKMNPQRSTUVWXYZ23456789";
    let mut rng = rand::rngs::OsRng;
    (0..16)
        .map(|_| CHARS[rng.gen_range(0..CHARS.len())] as char)
        .collect()
}
fn qr_escape(value: &str) -> String {
    value
        .chars()
        .flat_map(|c| {
            if matches!(c, '\\' | ';' | ',' | ':' | '"') {
                vec!['\\', c]
            } else {
                vec![c]
            }
        })
        .collect()
}
pub fn wifi_qr_string(ssid: &str, password: &str) -> String {
    format!(
        "WIFI:T:WPA;S:{};P:{};;",
        qr_escape(ssid),
        qr_escape(password)
    )
}
pub fn render_wifi_qr(ssid: &str, password: &str) -> Result<String> {
    crate::providers::mobile::render_qr_code(&wifi_qr_string(ssid, password))
}
fn validate_settings(ssid: &str, password: &str) -> Result<()> {
    if ssid.is_empty() || ssid.len() > 32 || ssid.chars().any(char::is_control) {
        bail!("SSID must contain 1-32 UTF-8 bytes without control characters");
    }
    if !(8..=63).contains(&password.len()) || !password.bytes().all(|c| (32..=126).contains(&c)) {
        bail!("Access-point password must contain 8-63 printable ASCII characters");
    }
    Ok(())
}
pub fn start_forensic_access_point(
    ssid: &str,
    password: &str,
    timeout_minutes: Option<u64>,
) -> Result<ForensicAccessPointInfo> {
    start_forensic_access_point_with_status(ssid, password, timeout_minutes, |_| {})
}
/// The caller must retain its process until stop/timeout completes; closing the
/// native WLAN session also releases this process's use of the hosted network.
pub fn start_forensic_access_point_with_status(
    ssid: &str,
    password: &str,
    timeout_minutes: Option<u64>,
    on_status: impl FnMut(&str),
) -> Result<ForensicAccessPointInfo> {
    validate_settings(ssid, password)?;
    #[cfg(windows)]
    {
        native::start(ssid, password, timeout_minutes, on_status)
    }
    #[cfg(not(windows))]
    {
        let _ = (timeout_minutes, on_status);
        bail!("Forensic Access Point is only supported on Windows")
    }
}
/// Stop only the session owned by this process. `force` never overrides ownership.
pub fn stop_forensic_access_point(_force: bool) -> Result<()> {
    #[cfg(windows)]
    {
        native::stop()
    }
    #[cfg(not(windows))]
    {
        bail!("Forensic Access Point is only supported on Windows")
    }
}
pub fn get_forensic_access_point_status() -> Result<ForensicAccessPointStatus> {
    #[cfg(windows)]
    {
        native::status()
    }
    #[cfg(not(windows))]
    {
        bail!("Forensic Access Point is only supported on Windows")
    }
}
/// Retained for API compatibility. Adapter discovery no longer changes host state.
pub fn wait_for_usb_wifi_adapter(_timeout_secs: u64) -> Result<bool> {
    #[cfg(windows)]
    {
        Ok(native::status().is_ok())
    }
    #[cfg(not(windows))]
    {
        Ok(false)
    }
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn passwords_are_valid_and_qr_fields_escape_delimiters() {
        let password = generate_password();
        assert_eq!(password.len(), 16);
        assert!(validate_settings("FORENSIC-AP", &password).is_ok());
        assert_eq!(
            wifi_qr_string("a;b", "a:b\\cdef"),
            r"WIFI:T:WPA;S:a\;b;P:a\:b\\cdef;;"
        );
    }
    #[test]
    fn invalid_settings_are_rejected_before_platform_operations() {
        assert!(validate_settings("", "password").is_err());
        assert!(validate_settings(&"é".repeat(17), "password").is_err());
        assert!(validate_settings("valid", "short").is_err());
        assert!(validate_settings("valid", "pass\nword").is_err());
    }
}
