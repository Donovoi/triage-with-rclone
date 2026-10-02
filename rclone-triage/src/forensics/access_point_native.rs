//! Native session ownership avoids `netsh force-start` surviving process exit.
use super::{ForensicAccessPointInfo, ForensicAccessPointStatus};
use anyhow::{bail, Context, Result};
use serde::Deserialize;
use std::ffi::c_void;
use std::sync::{Mutex, OnceLock};
use windows::core::BOOL;
use windows::Win32::Foundation::HANDLE;
use windows::Win32::NetworkManagement::WiFi::*;

static ACTIVE: OnceLock<Mutex<Option<Lease>>> = OnceLock::new();
fn active() -> &'static Mutex<Option<Lease>> {
    ACTIVE.get_or_init(|| Mutex::new(None))
}
fn checked(code: u32, operation: &str) -> Result<()> {
    if code != 0 {
        bail!("{} failed: Windows error {}", operation, code);
    }
    Ok(())
}

// The opaque handle is used only while the Lease is exclusively borrowed or
// behind ACTIVE's mutex. Storing its address avoids inventing Send for HANDLE.
struct Client(usize);
impl Client {
    fn open() -> Result<Self> {
        let mut negotiated = 0;
        let mut handle = HANDLE::default();
        unsafe {
            checked(
                WlanOpenHandle(2, None, &mut negotiated, &mut handle),
                "Open WLAN session",
            )?;
        }
        Ok(Self(handle.0 as usize))
    }
    fn handle(&self) -> HANDLE {
        HANDLE(self.0 as *mut c_void)
    }
    fn property(&self, opcode: WLAN_HOSTED_NETWORK_OPCODE) -> Result<Vec<u8>> {
        let mut len = 0;
        let mut data = std::ptr::null_mut();
        let mut value_type = WLAN_OPCODE_VALUE_TYPE::default();
        unsafe {
            checked(
                WlanHostedNetworkQueryProperty(
                    self.handle(),
                    opcode,
                    &mut len,
                    &mut data,
                    &mut value_type,
                    None,
                ),
                "Capture hosted-network settings",
            )?;
            if data.is_null() || len == 0 || len > 65536 {
                if !data.is_null() {
                    WlanFreeMemory(data);
                }
                bail!("Hosted-network settings could not be safely captured");
            }
            let bytes = std::slice::from_raw_parts(data as *const u8, len as usize).to_vec();
            WlanFreeMemory(data);
            Ok(bytes)
        }
    }
    fn set_property(&self, opcode: WLAN_HOSTED_NETWORK_OPCODE, bytes: &[u8]) -> Result<()> {
        unsafe {
            checked(
                WlanHostedNetworkSetProperty(
                    self.handle(),
                    opcode,
                    bytes.len() as u32,
                    bytes.as_ptr().cast(),
                    None,
                    None,
                ),
                "Set hosted-network property",
            )
        }
    }
    fn state(&self) -> Result<WLAN_HOSTED_NETWORK_STATUS> {
        let mut data = std::ptr::null_mut();
        unsafe {
            checked(
                WlanHostedNetworkQueryStatus(self.handle(), &mut data, None),
                "Query hosted-network state",
            )?;
            if data.is_null() {
                bail!("Hosted-network status is unavailable");
            }
            // PeerList is a variable-length trailing array (possibly empty).
            // Read only the fixed fields instead of copying an assumed peer.
            let result = WLAN_HOSTED_NETWORK_STATUS {
                HostedNetworkState: (*data).HostedNetworkState,
                IPDeviceID: (*data).IPDeviceID,
                dwNumberOfPeers: (*data).dwNumberOfPeers,
                ..Default::default()
            };
            WlanFreeMemory(data.cast());
            Ok(result)
        }
    }
}
impl Drop for Client {
    fn drop(&mut self) {
        unsafe {
            WlanCloseHandle(self.handle(), None);
        }
    }
}

struct SecondaryKey {
    bytes: Vec<u8>,
    passphrase: bool,
    persistent: bool,
}
impl SecondaryKey {
    fn capture(client: &Client) -> Result<Self> {
        let mut len = 0;
        let mut data = std::ptr::null_mut();
        let mut passphrase = BOOL::default();
        let mut persistent = BOOL::default();
        unsafe {
            checked(
                WlanHostedNetworkQuerySecondaryKey(
                    client.handle(),
                    &mut len,
                    &mut data,
                    &mut passphrase,
                    &mut persistent,
                    None,
                    None,
                ),
                "Capture previous hosted-network key",
            )?;
            if len > 65536 || (len > 0 && data.is_null()) {
                if !data.is_null() {
                    WlanFreeMemory(data.cast());
                }
                bail!("Invalid hosted-network key snapshot");
            }
            let bytes = if len == 0 {
                Vec::new()
            } else {
                std::slice::from_raw_parts(data, len as usize).to_vec()
            };
            if !data.is_null() {
                WlanFreeMemory(data.cast());
            }
            Ok(Self {
                bytes,
                passphrase: passphrase.as_bool(),
                persistent: persistent.as_bool(),
            })
        }
    }
    fn restore(&self, client: &Client) -> Result<()> {
        // The generated slice wrapper cannot represent the API's required NULL
        // pointer for deleting an absent original key. Use its exact ABI here.
        #[link(name = "wlanapi")]
        extern "system" {
            #[link_name = "WlanHostedNetworkSetSecondaryKey"]
            fn set_key(
                handle: HANDLE,
                len: u32,
                key: *const u8,
                passphrase: BOOL,
                persistent: BOOL,
                reason: *mut WLAN_HOSTED_NETWORK_REASON,
                reserved: *const c_void,
            ) -> u32;
        }
        unsafe {
            checked(
                set_key(
                    client.handle(),
                    self.bytes.len() as u32,
                    if self.bytes.is_empty() {
                        std::ptr::null()
                    } else {
                        self.bytes.as_ptr()
                    },
                    self.passphrase.into(),
                    self.persistent.into(),
                    std::ptr::null_mut(),
                    std::ptr::null(),
                ),
                "Restore hosted-network key",
            )
        }
    }
}
impl Drop for SecondaryKey {
    fn drop(&mut self) {
        self.bytes.fill(0);
    }
}

struct Lease {
    client: Client,
    connection: Vec<u8>,
    enabled: Vec<u8>,
    key: SecondaryKey,
    settings_changed: bool,
    started: bool,
    firewall_rule: Option<String>,
    id: String,
}
impl Lease {
    fn capture() -> Result<Self> {
        let client = Client::open()?;
        if client.state()?.HostedNetworkState == wlan_hosted_network_active {
            bail!("An existing hosted network is active; it will not be modified");
        }
        let connection = client.property(wlan_hosted_network_opcode_connection_settings)?;
        let enabled = client.property(wlan_hosted_network_opcode_enable)?;
        let key = SecondaryKey::capture(&client)?;
        Ok(Self {
            client,
            connection,
            enabled,
            key,
            settings_changed: false,
            started: false,
            firewall_rule: None,
            id: super::generate_password(),
        })
    }
    fn configure(&mut self, ssid: &str, password: &str) -> Result<()> {
        if self.connection.len() != std::mem::size_of::<WLAN_HOSTED_NETWORK_CONNECTION_SETTINGS>() {
            bail!("Unsupported hosted-network settings layout; no changes made");
        }
        let mut settings: WLAN_HOSTED_NETWORK_CONNECTION_SETTINGS =
            unsafe { std::ptr::read_unaligned(self.connection.as_ptr().cast()) };
        settings.hostedNetworkSSID.uSSIDLength = ssid.len() as u32;
        settings.hostedNetworkSSID.ucSSID.fill(0);
        settings.hostedNetworkSSID.ucSSID[..ssid.len()].copy_from_slice(ssid.as_bytes());
        self.settings_changed = true; // Set before first mutation so partial errors roll back.
        self.client
            .set_property(wlan_hosted_network_opcode_enable, &1i32.to_ne_bytes())?;
        let bytes = unsafe {
            std::slice::from_raw_parts(
                (&settings as *const WLAN_HOSTED_NETWORK_CONNECTION_SETTINGS).cast::<u8>(),
                std::mem::size_of_val(&settings),
            )
        };
        self.client
            .set_property(wlan_hosted_network_opcode_connection_settings, bytes)?;
        let mut key = password.as_bytes().to_vec();
        key.push(0);
        let result = unsafe {
            checked(
                WlanHostedNetworkSetSecondaryKey(
                    self.client.handle(),
                    &key,
                    true,
                    false,
                    None,
                    None,
                ),
                "Set temporary hosted-network key",
            )
        };
        key.fill(0);
        result?;
        unsafe {
            checked(
                WlanHostedNetworkStartUsing(self.client.handle(), None, None),
                "Start owned hosted-network session",
            )?;
        }
        self.started = true;
        Ok(())
    }
    fn restore(&mut self) -> Result<()> {
        let mut errors = Vec::new();
        if let Some(rule) = self.firewall_rule.as_ref() {
            let script = format!("Get-NetFirewallRule -Name {} -ErrorAction SilentlyContinue | Remove-NetFirewallRule -ErrorAction Stop", literal(rule));
            if collect_error(&mut errors, run_powershell(&script).map(|_| ())) {
                self.firewall_rule = None;
            }
        }
        if self.started {
            let result = unsafe {
                checked(
                    WlanHostedNetworkStopUsing(self.client.handle(), None, None),
                    "Stop owned hosted-network session",
                )
            };
            if collect_error(&mut errors, result) {
                self.started = false;
            }
        }
        if self.settings_changed && !self.started {
            let key_ok = collect_error(&mut errors, self.key.restore(&self.client));
            let connection_ok = collect_error(
                &mut errors,
                self.client.set_property(
                    wlan_hosted_network_opcode_connection_settings,
                    &self.connection,
                ),
            );
            let enabled_ok = collect_error(
                &mut errors,
                self.client
                    .set_property(wlan_hosted_network_opcode_enable, &self.enabled),
            );
            if key_ok && connection_ok && enabled_ok {
                self.settings_changed = false;
            }
        }
        if !errors.is_empty() {
            bail!("Access-point restoration incomplete: {}", errors.join("; "));
        }
        Ok(())
    }
}
impl Drop for Lease {
    fn drop(&mut self) {
        if let Err(error) = self.restore() {
            tracing::error!("{}", error);
        }
    }
}
fn collect_error(errors: &mut Vec<String>, result: Result<()>) -> bool {
    match result {
        Ok(()) => true,
        Err(error) => {
            errors.push(error.to_string());
            false
        }
    }
}
fn literal(value: &str) -> String {
    format!("'{}'", value.replace('\'', "''"))
}
fn run_powershell(script: &str) -> Result<String> {
    use std::os::windows::process::CommandExt;
    let script = format!("$ErrorActionPreference = 'Stop'; {script}");
    let output = std::process::Command::new("powershell")
        .args(["-NoProfile", "-NonInteractive", "-Command", &script])
        .creation_flags(0x08000000)
        .output()?;
    if !output.status.success() {
        bail!(
            "PowerShell failed: {}",
            String::from_utf8_lossy(&output.stderr).trim()
        );
    }
    Ok(String::from_utf8_lossy(&output.stdout).trim().to_owned())
}
#[derive(Deserialize)]
struct Adapter {
    name: String,
    ip: Option<String>,
}
fn adapter_for(client: &Client) -> Result<Adapter> {
    let guid = format!("{:?}", client.state()?.IPDeviceID);
    let script = format!("$a = Get-NetAdapter -IncludeHidden | Where-Object {{ $_.InterfaceGuid -eq [guid]{} }} | Select-Object -First 1; if (-not $a) {{ throw 'Hosted-network adapter identity unavailable' }}; $ip = Get-NetIPAddress -InterfaceIndex $a.InterfaceIndex -AddressFamily IPv4 -ErrorAction SilentlyContinue | Select-Object -First 1 -ExpandProperty IPAddress; @{{name=$a.Name;ip=$ip}} | ConvertTo-Json -Compress", literal(&guid));
    serde_json::from_str(&run_powershell(&script)?).context("Read exact hosted-network adapter")
}
pub(super) fn start(
    ssid: &str,
    password: &str,
    timeout_minutes: Option<u64>,
    mut on_status: impl FnMut(&str),
) -> Result<ForensicAccessPointInfo> {
    let timeout_seconds = timeout_minutes
        .filter(|value| *value > 0)
        .map(|minutes| {
            minutes
                .checked_mul(60)
                .ok_or_else(|| anyhow::anyhow!("Access-point timeout is too large"))
        })
        .transpose()?;
    let mut active = active()
        .lock()
        .map_err(|_| anyhow::anyhow!("Access-point journal lock poisoned"))?;
    if active.is_some() {
        bail!("This process already owns an access-point session; stop it first");
    }
    on_status("Capturing hosted-network settings before any changes...");
    let mut lease = Lease::capture()?;
    let setup = (|| -> Result<ForensicAccessPointInfo> {
        on_status("Starting process-owned access point...");
        lease.configure(ssid, password)?;
        let adapter = adapter_for(&lease.client)?;
        let ip_address = adapter.ip.ok_or_else(|| anyhow::anyhow!("Hosted-network adapter has no IPv4 address; configure connection sharing before using this feature"))?;
        let rule = format!("rclone-triage-{}", lease.id);
        lease.firewall_rule = Some(rule.clone());
        run_powershell(&format!("New-NetFirewallRule -Name {} -DisplayName {} -Direction Inbound -Action Allow -Profile Any -Protocol TCP -LocalPort 53682 -LocalAddress {} -InterfaceAlias {} -RemoteAddress LocalSubnet -ErrorAction Stop | Out-Null", literal(&rule), literal(&rule), literal(&ip_address), literal(&adapter.name)))?;
        Ok(ForensicAccessPointInfo {
            ssid: ssid.into(),
            password: password.into(),
            ip_address,
            dns_servers: Vec::new(),
            adapter_name: Some(adapter.name),
            dns_configured: false,
            dns_error: Some("Existing DNS settings preserved".into()),
        })
    })();
    let info = match setup {
        Ok(info) => info,
        Err(error) => {
            if let Err(rollback) = lease.restore() {
                *active = Some(lease); // Retain original settings for an explicit retry.
                bail!("Access-point setup failed: {error}; {rollback}");
            }
            return Err(error);
        }
    };
    let id = lease.id.clone();
    *active = Some(lease);
    drop(active);
    if let Some(seconds) = timeout_seconds {
        std::thread::spawn(move || {
            std::thread::sleep(std::time::Duration::from_secs(seconds));
            if let Err(error) = stop_owned(Some(&id)) {
                tracing::error!("Access-point timeout cleanup failed: {}", error);
            }
        });
    }
    on_status("Access point ready; existing DNS settings preserved.");
    Ok(info)
}
fn stop_owned(id: Option<&str>) -> Result<()> {
    let mut active = active()
        .lock()
        .map_err(|_| anyhow::anyhow!("Access-point journal lock poisoned"))?;
    if let Some(lease) = active.as_mut() {
        if id.is_some_and(|id| id != lease.id) {
            return Ok(());
        }
        lease.restore()?;
        *active = None;
    }
    Ok(())
}
pub(super) fn stop() -> Result<()> {
    stop_owned(None)
}
pub(super) fn status() -> Result<ForensicAccessPointStatus> {
    let client = Client::open()?;
    let state = client.state()?;
    let settings = client.property(wlan_hosted_network_opcode_connection_settings)?;
    let ssid = if settings.len() == std::mem::size_of::<WLAN_HOSTED_NETWORK_CONNECTION_SETTINGS>() {
        let settings: WLAN_HOSTED_NETWORK_CONNECTION_SETTINGS =
            unsafe { std::ptr::read_unaligned(settings.as_ptr().cast()) };
        let len = (settings.hostedNetworkSSID.uSSIDLength as usize).min(32);
        Some(String::from_utf8_lossy(&settings.hostedNetworkSSID.ucSSID[..len]).into_owned())
    } else {
        None
    };
    let adapter = adapter_for(&client).ok();
    Ok(ForensicAccessPointStatus {
        active: state.HostedNetworkState == wlan_hosted_network_active,
        ssid,
        connected_clients: state.dwNumberOfPeers,
        adapter_name: adapter.as_ref().map(|a| a.name.clone()),
        ip_address: adapter.and_then(|a| a.ip),
    })
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn quoted_values_do_not_expand_powershell_expressions() {
        assert_eq!(literal("ssid$(code)'name"), "'ssid$(code)''name'");
    }
    #[test]
    fn restoration_collects_failures_without_masking_later_steps() {
        let mut errors = Vec::new();
        assert!(!collect_error(&mut errors, Err(anyhow::anyhow!("first"))));
        assert!(collect_error(&mut errors, Ok(())));
        assert!(!collect_error(&mut errors, Err(anyhow::anyhow!("second"))));
        assert_eq!(errors, vec!["first", "second"]);
    }
}
