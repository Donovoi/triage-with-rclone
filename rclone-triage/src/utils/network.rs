//! Network helpers.

use anyhow::Result;
use std::net::UdpSocket;

/// Get a local IPv4 address that can be used for LAN access.
pub fn get_local_ip_address() -> Result<Option<String>> {
    #[cfg(windows)]
    {
        let output = std::process::Command::new("powershell")
            .args([
                "-NoProfile",
                "-NonInteractive",
                "-Command",
                "Get-NetIPAddress -AddressFamily IPv4 | Where-Object { $_.InterfaceAlias -notlike '*Loopback*' -and $_.IPAddress -notlike '169.254.*' } | Sort-Object -Property InterfaceIndex | Select-Object -First 1 -ExpandProperty IPAddress",
            ])
            .output();

        if let Ok(output) = output {
            if output.status.success() {
                let ip = String::from_utf8_lossy(&output.stdout).trim().to_string();
                if !ip.is_empty() {
                    return Ok(Some(ip));
                }
            }
        }
    }

    // Fallback: use a UDP socket to determine local interface
    let socket = UdpSocket::bind("0.0.0.0:0")?;
    if socket.connect("8.8.8.8:80").is_err() {
        return Ok(None);
    }
    let local_addr = socket.local_addr()?;
    Ok(Some(local_addr.ip().to_string()))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_get_local_ip_address() {
        // We just ensure it doesn't error.
        let _ = get_local_ip_address();
    }
}
