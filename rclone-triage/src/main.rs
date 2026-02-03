//! rclone-triage: Cloud Triage Tool
//!
//! A single-file Windows executable that embeds rclone and provides
//! a TUI interface for cloud data acquisition.

use rclone_triage::case::Case;
use rclone_triage::cleanup::Cleanup;
use rclone_triage::embedded;
use rclone_triage::files::list_path;
use rclone_triage::forensics::{
    generate_password, get_forensic_access_point_status, render_wifi_qr,
    open_onedrive_vault, start_forensic_access_point, stop_forensic_access_point,
    SystemStateSnapshot,
};
use rclone_triage::providers::auth::{authenticate_with_mobile, authenticate_with_rclone};
use rclone_triage::providers::CloudProvider;
use rclone_triage::rclone::{start_web_gui, RcloneConfig, RcloneRunner};
use rclone_triage::ui::App as TuiApp;
use anyhow::Result;
use clap::Parser;
use std::sync::{Arc, Mutex};

fn main() -> Result<()> {
    println!("rclone-triage v{}", env!("CARGO_PKG_VERSION"));

    let args = Cli::parse();
    let app_guard = AppGuard::new();

    // Capture initial system state before any operations
    let initial_state = SystemStateSnapshot::capture("Initial state before session").ok();

    // Ctrl+C handler for graceful shutdown
    {
        let cleanup = app_guard.cleanup.clone();
        let _ = ctrlc::set_handler(move || {
            if let Ok(mut cleanup) = cleanup.lock() {
                let _ = cleanup.execute();
            }
            std::process::exit(130);
        });
    }

    // Verify embedded binary
    embedded::verify_embedded_binary()?;

    // Extract embedded rclone
    let binary = embedded::ExtractedBinary::extract()?;
    app_guard.track_file(binary.path());
    if let Some(dir) = binary.temp_dir() {
        app_guard.track_dir(dir);
    }

    // Initialize session
    let case = Case::new(&args.name, args.output_dir.clone())?;
    println!("Session initialized: {}", case.session_id());

    if args.web_gui {
        let config = RcloneConfig::for_case(&case.output_dir)?;
        app_guard.track_env_value("RCLONE_CONFIG", config.original_env());
        let port = args.web_gui_port;
        let addr = format!("http://127.0.0.1:{}/", port);

        println!("Starting rclone Web GUI at {}", addr);
        let mut web = start_web_gui(
            binary.path(),
            Some(config.path()),
            port,
            args.web_gui_user.as_deref(),
            args.web_gui_pass.as_deref(),
        )?;
        println!("Press Ctrl+C to stop.");

        let status = web.wait()?;
        println!("Web GUI exited with status: {}", status);
        return Ok(());
    }

    if args.forensic_ap_start {
        let ssid = args
            .forensic_ap_ssid
            .clone()
            .unwrap_or_else(|| "FORENSIC-AP".to_string());
        let password = args
            .forensic_ap_password
            .clone()
            .unwrap_or_else(generate_password);

        let info = start_forensic_access_point(
            &ssid,
            &password,
            args.forensic_ap_timeout_minutes,
        )?;

        println!("Forensic Access Point started:");
        println!("  SSID: {}", info.ssid);
        println!("  Password: {}", info.password);
        println!("  IP: {}", info.ip_address);
        println!("  DNS: {}", info.dns_servers.join(", "));
        if let Some(adapter) = info.adapter_name {
            println!("  Adapter: {}", adapter);
        }
        if !info.dns_configured {
            if let Some(err) = info.dns_error {
                println!("  DNS warning: {}", err);
            }
        }
        if let Ok(qr) = render_wifi_qr(&ssid, &password) {
            println!("\nScan to connect:\n{}", qr);
        }
        return Ok(());
    }

    if args.forensic_ap_stop {
        stop_forensic_access_point(true)?;
        println!("Forensic Access Point stopped.");
        return Ok(());
    }

    if args.forensic_ap_status {
        let status = get_forensic_access_point_status()?;
        println!("Forensic Access Point status:");
        println!("  Active: {}", status.active);
        if let Some(ssid) = status.ssid {
            println!("  SSID: {}", ssid);
        }
        println!("  Clients: {}", status.connected_clients);
        if let Some(adapter) = status.adapter_name {
            println!("  Adapter: {}", adapter);
        }
        if let Some(ip) = status.ip_address {
            println!("  IP: {}", ip);
        }
        return Ok(());
    }

    if args.onedrive_vault {
        let mount_point = args
            .onedrive_vault_mount
            .clone()
            .unwrap_or_else(default_vault_mount);
        let destination = args
            .onedrive_vault_dest
            .clone()
            .unwrap_or_else(default_vault_destination);

        let result =
            open_onedrive_vault(&mount_point, &destination, !args.onedrive_vault_no_wait)?;

        println!("OneDrive Vault processed:");
        println!("  Mount: {:?}", result.mount_point);
        println!("  Destination: {:?}", result.destination);
        println!("  Files copied: {}", result.copied_files.len());
        println!("  BitLocker disabled: {}", result.bitlocker_disabled);
        for warning in result.warnings {
            println!("  Warning: {}", warning);
        }
        return Ok(());
    }

    // Optional TUI loop
    if args.tui {
        let mut app = TuiApp::new();
        app.set_cleanup(app_guard.cleanup.clone());
        rclone_triage::ui::runner::run_loop(&mut app)?;
        return Ok(());
    }

    // Minimal auth + listing wiring (CLI-driven)
    if let Some(provider_name) = args.provider.clone() {
        let parsed: Result<CloudProvider, _> = provider_name.parse();
        let known = parsed.ok();
        let display_name = known
            .map(|p| p.display_name().to_string())
            .unwrap_or_else(|| provider_name.clone());

        println!("Authenticating {}...", display_name);
        let config = RcloneConfig::for_case(&case.output_dir)?;
        app_guard.track_env_value("RCLONE_CONFIG", config.original_env());
        let runner = RcloneRunner::new(binary.path()).with_config(config.path());

        let remote_name = known
            .map(|p| p.short_name().to_string())
            .unwrap_or_else(|| provider_name.clone());
        if let Some(provider) = known {
            if args.mobile_auth {
                authenticate_with_mobile(provider, &config, &remote_name, args.mobile_auth_port)?;
            } else {
                authenticate_with_rclone(provider, &runner, &config, &remote_name)?;
            }
        } else {
            if args.mobile_auth {
                anyhow::bail!("Mobile auth only supported for known OAuth providers");
            }
            let args = ["config", "create", remote_name.as_str(), provider_name.as_str()];
            let output = runner.run(&args)?;
            if !output.success() {
                anyhow::bail!("Failed to authenticate: {}", output.stderr_string());
            }
            if !config.has_remote(&remote_name)? {
                anyhow::bail!("Remote {} was not created", remote_name);
            }
        }

        let listing = list_path(&runner, &format!("{}:", remote_name))?;
        println!("Listed {} entries", listing.len());
    }

    // Capture final state and report if verbose
    if let Some(initial) = initial_state {
        if let Ok(final_state) = SystemStateSnapshot::capture("Final state after session") {
            let diff = initial.diff(&final_state);
            if diff.has_changes() {
                println!("\nSystem state changes detected:");
                println!("{}", diff.generate_report());
            }
        }
    }

    Ok(())
}

/// Ensures cleanup is run on drop
struct AppGuard {
    cleanup: Arc<Mutex<Cleanup>>,
}

impl AppGuard {
    fn new() -> Self {
        Self {
            cleanup: Arc::new(Mutex::new(Cleanup::new())),
        }
    }

    fn track_file(&self, path: impl AsRef<std::path::Path>) {
        if let Ok(mut cleanup) = self.cleanup.lock() {
            cleanup.track_file(path);
        }
    }

    fn track_dir(&self, path: impl AsRef<std::path::Path>) {
        if let Ok(mut cleanup) = self.cleanup.lock() {
            cleanup.track_dir(path);
        }
    }

    fn track_env_value(&self, name: impl Into<String>, old_value: Option<String>) {
        if let Ok(mut cleanup) = self.cleanup.lock() {
            cleanup.track_env_value(name, old_value);
        }
    }
}

impl Drop for AppGuard {
    fn drop(&mut self) {
        if let Ok(mut cleanup) = self.cleanup.lock() {
            let _ = cleanup.execute();
        }
    }
}

/// CLI arguments
#[derive(Parser, Debug)]
#[command(author, version, about = "Cloud triage tool")]
struct Cli {
    /// Session name (folder name for output). Defaults to triage-YYYYMMDD-HHMMSS
    #[arg(long, short, default_value = "")]
    name: String,
    /// Output directory
    #[arg(long, short = 'o', default_value = ".")]
    output_dir: std::path::PathBuf,

    /// Cloud provider/backend to authenticate (e.g., drive, onedrive, s3)
    #[arg(long)]
    provider: Option<String>,

    /// Launch interactive TUI
    #[arg(long, default_value_t = false)]
    tui: bool,

    /// Use mobile authentication (QR code + local callback)
    #[arg(long, default_value_t = false)]
    mobile_auth: bool,

    /// Mobile auth callback port
    #[arg(long, default_value_t = 53682)]
    mobile_auth_port: u16,

    /// Start rclone Web GUI (rcd --rc-web-gui)
    #[arg(long, default_value_t = false)]
    web_gui: bool,

    /// Web GUI port
    #[arg(long, default_value_t = 5572)]
    web_gui_port: u16,

    /// Web GUI username (optional)
    #[arg(long)]
    web_gui_user: Option<String>,

    /// Web GUI password (optional)
    #[arg(long)]
    web_gui_pass: Option<String>,

    /// Start the forensic WiFi Access Point (Windows only)
    #[arg(long, default_value_t = false)]
    forensic_ap_start: bool,

    /// Stop the forensic WiFi Access Point (Windows only)
    #[arg(long, default_value_t = false)]
    forensic_ap_stop: bool,

    /// Show forensic WiFi Access Point status (Windows only)
    #[arg(long, default_value_t = false)]
    forensic_ap_status: bool,

    /// Forensic Access Point SSID
    #[arg(long)]
    forensic_ap_ssid: Option<String>,

    /// Forensic Access Point password
    #[arg(long)]
    forensic_ap_password: Option<String>,

    /// Forensic Access Point auto-shutdown timeout (minutes)
    #[arg(long)]
    forensic_ap_timeout_minutes: Option<u64>,

    /// Open OneDrive Personal Vault and copy VHDX (Windows only)
    #[arg(long, default_value_t = false)]
    onedrive_vault: bool,

    /// OneDrive vault mount point
    #[arg(long)]
    onedrive_vault_mount: Option<String>,

    /// OneDrive vault destination path
    #[arg(long)]
    onedrive_vault_dest: Option<String>,

    /// Skip waiting for user confirmation after Windows Hello
    #[arg(long, default_value_t = false)]
    onedrive_vault_no_wait: bool,
}

fn default_vault_mount() -> String {
    if cfg!(windows) {
        "C:\\OneDriveTemp\\".to_string()
    } else {
        "./OneDriveTemp".to_string()
    }
}

fn default_vault_destination() -> String {
    if cfg!(windows) {
        if let Ok(profile) = std::env::var("USERPROFILE") {
            return format!("{}\\Desktop\\OneDriveVault", profile);
        }
        "C:\\OneDriveVault".to_string()
    } else {
        "./OneDriveVault".to_string()
    }
}
