//! Forensic Access Point (WiFi hotspot) helpers.

use anyhow::{bail, Result};

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
    use rand::rngs::OsRng;
    use rand::Rng;

    const CHARS: &[u8] = b"abcdefghjkmnpqrstuvwxyzABCDEFGHJKMNPQRSTUVWXYZ23456789";
    let mut rng = OsRng;
    let mut out = String::with_capacity(16);
    for _ in 0..16 {
        let idx = rng.gen_range(0..CHARS.len());
        out.push(CHARS[idx] as char);
    }
    out
}

pub fn wifi_qr_string(ssid: &str, password: &str) -> String {
    format!("WIFI:T:WPA;S:{};P:{};;", ssid, password)
}

pub fn render_wifi_qr(ssid: &str, password: &str) -> Result<String> {
    let text = wifi_qr_string(ssid, password);
    crate::providers::mobile::render_qr_code(&text)
}

#[cfg(windows)]
pub fn start_forensic_access_point(
    ssid: &str,
    password: &str,
    timeout_minutes: Option<u64>,
) -> Result<ForensicAccessPointInfo> {
    let native = test_native_ap_support()?;
    if !native.supported {
        if let Some(reason) = native.reason {
            bail!("Access Point not supported: {}", reason);
        } else {
            bail!("Access Point not supported on this adapter");
        }
    }

    set_hostednetwork_config(ssid, password)?;
    ensure_firewall_rules(ssid)?;
    start_hostednetwork()?;

    let adapter = get_ap_adapter_name().ok().flatten();
    let ip_address = get_ap_ip_address(adapter.as_deref()).unwrap_or_else(|_| "192.168.137.1".to_string());

    let mut dns_configured = false;
    let mut dns_error = None;
    if let Some(ref name) = adapter {
        match set_dns_servers(name, &ADGUARD_DNS_IPV4) {
            Ok(()) => dns_configured = true,
            Err(e) => dns_error = Some(e.to_string()),
        }
    }

    if let Some(minutes) = timeout_minutes {
        if minutes > 0 {
            std::thread::spawn(move || {
                std::thread::sleep(std::time::Duration::from_secs(minutes * 60));
                let _ = stop_forensic_access_point(true);
            });
        }
    }

    Ok(ForensicAccessPointInfo {
        ssid: ssid.to_string(),
        password: password.to_string(),
        ip_address,
        dns_servers: ADGUARD_DNS_IPV4.iter().map(|s| s.to_string()).collect(),
        adapter_name: adapter,
        dns_configured,
        dns_error,
    })
}

#[cfg(not(windows))]
pub fn start_forensic_access_point(
    _ssid: &str,
    _password: &str,
    _timeout_minutes: Option<u64>,
) -> Result<ForensicAccessPointInfo> {
    bail!("Forensic Access Point is only supported on Windows");
}

#[cfg(windows)]
pub fn stop_forensic_access_point(force: bool) -> Result<()> {
    if !force {
        // No prompt support here; caller can confirm externally.
    }
    let _ = stop_hostednetwork();
    let adapter = get_ap_adapter_name().ok().flatten();
    if let Some(name) = adapter {
        let _ = reset_dns_servers(&name);
    }
    let _ = remove_firewall_rules();
    Ok(())
}

#[cfg(not(windows))]
pub fn stop_forensic_access_point(_force: bool) -> Result<()> {
    bail!("Forensic Access Point is only supported on Windows");
}

#[cfg(windows)]
pub fn get_forensic_access_point_status() -> Result<ForensicAccessPointStatus> {
    let output = run_netsh(&["wlan", "show", "hostednetwork"])?;
    Ok(parse_status(&output))
}

#[cfg(not(windows))]
pub fn get_forensic_access_point_status() -> Result<ForensicAccessPointStatus> {
    bail!("Forensic Access Point is only supported on Windows");
}

#[cfg(windows)]
fn run_netsh(args: &[&str]) -> Result<String> {
    use std::process::Command;
    let output = Command::new("netsh").args(args).output()?;
    let stdout = String::from_utf8_lossy(&output.stdout).to_string();
    let stderr = String::from_utf8_lossy(&output.stderr).to_string();
    if !output.status.success() {
        bail!("netsh failed: {}", stderr.trim());
    }
    Ok(format!("{}{}", stdout, stderr))
}

#[cfg(windows)]
fn run_powershell(script: &str) -> Result<String> {
    use std::process::Command;
    let output = Command::new("powershell")
        .args(["-NoProfile", "-NonInteractive", "-Command", script])
        .output()?;
    let stdout = String::from_utf8_lossy(&output.stdout).to_string();
    let stderr = String::from_utf8_lossy(&output.stderr).to_string();
    if !output.status.success() {
        bail!("powershell failed: {}", stderr.trim());
    }
    Ok(stdout.trim().to_string())
}

#[cfg(windows)]
#[derive(Debug, Clone)]
struct NativeApSupport {
    supported: bool,
    reason: Option<String>,
}

#[cfg(windows)]
fn set_hostednetwork_config(ssid: &str, password: &str) -> Result<()> {
    let _ = run_netsh(&["wlan", "set", "hostednetwork", "mode=allow"])?;
    let ssid_arg = format!("ssid={}", ssid);
    let key_arg = format!("key={}", password);
    let _ = run_netsh(&["wlan", "set", "hostednetwork", &ssid_arg, &key_arg, "keyUsage=persistent"])?;
    Ok(())
}

#[cfg(windows)]
fn start_hostednetwork() -> Result<()> {
    let _ = run_netsh(&["wlan", "start", "hostednetwork"])?;
    Ok(())
}

#[cfg(windows)]
fn stop_hostednetwork() -> Result<()> {
    let _ = run_netsh(&["wlan", "stop", "hostednetwork"])?;
    let _ = run_netsh(&["wlan", "set", "hostednetwork", "mode=disallow"])?;
    Ok(())
}

#[cfg(windows)]
fn test_native_ap_support() -> Result<NativeApSupport> {
    let script = r#"
$wifiAdapters = Get-NetAdapter | Where-Object {
  $_.PhysicalMediaType -eq 'Native 802.11' -or
  $_.InterfaceDescription -like '*Wireless*' -or
  $_.InterfaceDescription -like '*Wi-Fi*' -or
  $_.InterfaceDescription -like '*WLAN*'
}

if (-not $wifiAdapters) {
  Write-Output "SUPPORTED=0;REASON=No wireless adapters found"
  exit
}

$drivers = netsh wlan show drivers 2>&1
if ($drivers -match 'Hosted network supported\\s*:\\s*Yes') {
  $adapterName = ($wifiAdapters | Select-Object -First 1).Name
  Write-Output "SUPPORTED=1;ADAPTER=$adapterName"
} elseif ($drivers -match 'Hosted network supported\\s*:\\s*No') {
  Write-Output "SUPPORTED=0;REASON=WiFi driver does not support Hosted Network mode"
} else {
  Write-Output "SUPPORTED=0;REASON=Could not determine Hosted Network support"
}
"#;
    let out = run_powershell(script)?;
    let mut supported = false;
    let mut reason = None;
    for part in out.split(';') {
        let part = part.trim();
        if let Some(value) = part.strip_prefix("SUPPORTED=") {
            supported = value.trim() == "1";
        } else if let Some(value) = part.strip_prefix("REASON=") {
            if !value.trim().is_empty() {
                reason = Some(value.trim().to_string());
            }
        }
    }

    Ok(NativeApSupport {
        supported,
        reason,
    })
}

#[cfg(windows)]
fn get_ap_adapter_name() -> Result<Option<String>> {
    let script = r#"
$adapter = Get-NetAdapter | Where-Object {
  ($_.InterfaceDescription -like '*Microsoft Hosted Network Virtual Adapter*' -or
   $_.InterfaceDescription -like '*Microsoft Wi-Fi Direct Virtual Adapter*') -and
  $_.Status -eq 'Up'
} | Select-Object -First 1 -ExpandProperty Name

if (-not $adapter) {
  $ics = Get-NetIPAddress -AddressFamily IPv4 | Where-Object { $_.IPAddress -like '192.168.137.*' } | Select-Object -First 1 -ExpandProperty InterfaceAlias
  $adapter = $ics
}

if ($adapter) { Write-Output $adapter }
"#;
    let out = run_powershell(script)?;
    if out.trim().is_empty() {
        Ok(None)
    } else {
        Ok(Some(out))
    }
}

#[cfg(windows)]
fn get_ap_ip_address(adapter: Option<&str>) -> Result<String> {
    let script = if let Some(name) = adapter {
        let escaped = name.replace('\'', "''");
        format!(
            "Get-NetIPAddress -InterfaceAlias '{}' -AddressFamily IPv4 | Select-Object -First 1 -ExpandProperty IPAddress",
            escaped
        )
    } else {
        "Get-NetIPAddress -AddressFamily IPv4 | Where-Object { $_.IPAddress -like '192.168.137.*' } | Select-Object -First 1 -ExpandProperty IPAddress".to_string()
    };

    let out = run_powershell(&script)?;
    if out.trim().is_empty() {
        Ok("192.168.137.1".to_string())
    } else {
        Ok(out.trim().to_string())
    }
}

#[cfg(windows)]
fn set_dns_servers(adapter: &str, servers: &[&str]) -> Result<()> {
    let escaped = adapter.replace('\'', "''");
    let list = servers
        .iter()
        .map(|s| format!("'{}'", s))
        .collect::<Vec<_>>()
        .join(", ");
    let script = format!(
        "Set-DnsClientServerAddress -InterfaceAlias '{}' -ServerAddresses @({})",
        escaped, list
    );
    let _ = run_powershell(&script)?;
    Ok(())
}

#[cfg(windows)]
fn reset_dns_servers(adapter: &str) -> Result<()> {
    let escaped = adapter.replace('\'', "''");
    let script = format!(
        "Set-DnsClientServerAddress -InterfaceAlias '{}' -ResetServerAddresses",
        escaped
    );
    let _ = run_powershell(&script)?;
    Ok(())
}

#[cfg(windows)]
fn ensure_firewall_rules(ssid: &str) -> Result<()> {
    let escaped = ssid.replace('\'', "''");
    let script = format!(
        r#"
$ruleName = "Forensic-AP-{ssid}"
$existing = Get-NetFirewallRule -DisplayName $ruleName -ErrorAction SilentlyContinue
if (-not $existing) {{
  New-NetFirewallRule -DisplayName $ruleName -Direction Inbound -Action Allow -Profile Any -Protocol TCP -LocalPort 53682 | Out-Null
  New-NetFirewallRule -DisplayName "$ruleName-UDP" -Direction Inbound -Action Allow -Profile Any -Protocol UDP -LocalPort 53 | Out-Null
}}
"#,
        ssid = escaped
    );
    let _ = run_powershell(&script)?;
    Ok(())
}

#[cfg(windows)]
fn remove_firewall_rules() -> Result<()> {
    let script = r#"
$rules = Get-NetFirewallRule -DisplayName 'Forensic-AP-*' -ErrorAction SilentlyContinue
if ($rules) { $rules | Remove-NetFirewallRule -ErrorAction SilentlyContinue }
"#;
    let _ = run_powershell(script)?;
    Ok(())
}

#[cfg(windows)]
fn parse_status(output: &str) -> ForensicAccessPointStatus {
    let mut active = false;
    let mut ssid = None;
    let mut clients = 0u32;

    for line in output.lines() {
        let trimmed = line.trim();
        if trimmed.starts_with("Status") && trimmed.contains("Started") {
            active = true;
        }
        if trimmed.starts_with("SSID name") {
            if let Some(idx) = trimmed.find(':') {
                let value = trimmed[idx + 1..].trim().trim_matches('"');
                if !value.is_empty() {
                    ssid = Some(value.to_string());
                }
            }
        }
        if trimmed.starts_with("Number of clients") {
            if let Some(idx) = trimmed.find(':') {
                let value = trimmed[idx + 1..].trim();
                clients = value.parse::<u32>().unwrap_or(0);
            }
        }
    }

    let adapter = get_ap_adapter_name().ok().flatten();
    let ip_address = adapter
        .as_deref()
        .and_then(|name| get_ap_ip_address(Some(name)).ok());

    ForensicAccessPointStatus {
        active,
        ssid,
        connected_clients: clients,
        adapter_name: adapter,
        ip_address,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_generate_password() {
        let pw = generate_password();
        assert_eq!(pw.len(), 16);
    }

    #[test]
    fn test_wifi_qr_string() {
        let s = wifi_qr_string("FORENSIC-AP", "Password123");
        assert_eq!(s, "WIFI:T:WPA;S:FORENSIC-AP;P:Password123;;");
    }
}
