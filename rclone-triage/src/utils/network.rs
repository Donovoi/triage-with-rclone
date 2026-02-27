//! Network helpers.

use anyhow::Result;
use std::net::UdpSocket;

/// Get a local IPv4 address that can be used for LAN access.
pub fn get_local_ip_address() -> Result<Option<String>> {
    // Use a UDP socket to determine local interface (cross-platform, no actual data sent)
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
