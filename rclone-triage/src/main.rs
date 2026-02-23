//! rclone-triage: Cloud Triage Tool
//!
//! A single-file Windows executable that embeds rclone and provides
//! a TUI interface for cloud data acquisition.

use anyhow::{bail, Result};
use clap::Parser;
use rclone_triage::case::Case;
use rclone_triage::cleanup::Cleanup;
use rclone_triage::embedded;
use rclone_triage::files::{list_path, ListPathOptions};
use rclone_triage::forensics::{
    generate_password, get_forensic_access_point_status, open_onedrive_vault, render_wifi_qr,
    start_forensic_access_point, stop_forensic_access_point, SystemStateSnapshot,
};
use rclone_triage::providers::auth::{
    authenticate_with_device_code, authenticate_with_mobile, authenticate_with_rclone,
};
use rclone_triage::providers::credentials::upsert_custom_oauth_credentials;
use rclone_triage::providers::discovery::providers_from_rclone;
use rclone_triage::providers::mobile::render_qr_code;
use rclone_triage::providers::{CloudProvider, ProviderAuthKind};
use rclone_triage::rclone::authorize::{
    parse_authorize_callback_input, send_local_authorize_callback, spawn_authorize,
    RunningAuthorize,
};
use rclone_triage::rclone::{start_web_gui, RcloneConfig, RcloneRunner};
use rclone_triage::ui::App as TuiApp;
use std::sync::{Arc, Mutex};
use std::time::Duration;

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

    // Optional TUI loop (default when no explicit CLI action is selected)
    if should_run_tui(&args) {
        let mut app = TuiApp::new();
        app.set_cleanup(app_guard.cleanup.clone());
        rclone_triage::ui::runner::run_loop(&mut app)?;
        return Ok(());
    }

    // Collect debug logs for troubleshooting
    if args.collect_logs {
        return collect_debug_logs(&args);
    }

    // Extract embedded rclone
    let binary = embedded::ExtractedBinary::extract()?;
    app_guard.track_file(binary.path());
    if let Some(dir) = binary.temp_dir() {
        app_guard.track_dir(dir);
    }

    // Initialize session
    let case = Case::new(&args.name, args.output_dir.clone())?;
    println!("Case initialized: {}", case.session_id());

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

        let info = start_forensic_access_point(&ssid, &password, args.forensic_ap_timeout_minutes)?;

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

        let result = open_onedrive_vault(&mount_point, &destination, !args.onedrive_vault_no_wait)?;

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

    if let Some(provider_key) = args.set_oauth_creds.clone() {
        let client_id = prompt_line("Client ID: ")?;
        let client_secret = prompt_line("Client Secret (optional): ")?;
        let secret = if client_secret.trim().is_empty() {
            None
        } else {
            Some(client_secret)
        };
        let path = upsert_custom_oauth_credentials(
            &provider_key,
            client_id,
            secret,
            args.oauth_config_path.map(std::path::PathBuf::from),
        )?;
        println!("Saved OAuth credentials to {:?}", path);
        return Ok(());
    }

    if let Some(remote_name) = args.show_oauth_creds.clone() {
        let config_path = resolve_rclone_config_path(&args)?;
        let config = RcloneConfig::open_existing(&config_path)?;
        let creds = config.get_oauth_credentials(&remote_name)?;

        println!("Remote: {}", creds.remote_name);
        println!("Config: {:?}", config_path);
        println!(
            "Client ID: {}",
            creds.client_id.as_deref().unwrap_or("<none>")
        );
        println!(
            "Client Secret: {}",
            creds.client_secret.as_deref().unwrap_or("<none>")
        );
        println!("Has Client ID: {}", creds.has_client_id);
        println!("Has Client Secret: {}", creds.has_client_secret);
        println!(
            "Is Using Custom Credentials: {}",
            creds.is_using_custom_credentials
        );
        println!(
            "Using Default rclone Credentials: {}",
            creds.using_default_rclone_credentials
        );
        return Ok(());
    }

    // Minimal auth + listing wiring (CLI-driven)
    // CLI download from CSV/XLSX queue
    if let Some(ref queue_path_str) = args.download {
        return cli_download_from_queue(
            &binary,
            &case,
            queue_path_str,
            args.remote.as_deref(),
            &app_guard,
        );
    }

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

        let base_remote = known
            .map(|p| p.short_name().to_string())
            .unwrap_or_else(|| provider_name.clone());
        let remote_name = config.next_available_remote_name(&base_remote)?;
        if remote_name != base_remote {
            println!(
                "Remote '{}' already exists; using '{}'",
                base_remote, remote_name
            );
        }
        if let Some(provider) = known {
            if args.device_code {
                authenticate_with_device_code(provider, &config, &remote_name)?;
            } else if args.mobile_auth {
                authenticate_with_mobile(provider, &config, &remote_name, args.mobile_auth_port)?;
            } else {
                authenticate_with_rclone(provider, &runner, &config, &remote_name)?;
            }
        } else {
            if args.device_code {
                anyhow::bail!("Device code flow is only supported for known OAuth providers");
            }

            // Best-effort classification: avoid attempting OAuth flows on backends that are clearly
            // key-based or user/pass. (Users can still use an existing rclone config for those.)
            let auth_kind = providers_from_rclone(&runner)
                .ok()
                .and_then(|d| {
                    d.providers
                        .into_iter()
                        .find(|p| p.id.eq_ignore_ascii_case(provider_name.as_str()))
                })
                .map(|p| p.auth_kind)
                .unwrap_or(ProviderAuthKind::Unknown);

            match auth_kind {
                ProviderAuthKind::KeyBased | ProviderAuthKind::UserPass => {
                    println!(
                        "Backend '{}' uses {:?} authentication. Entering manual configuration.",
                        provider_name, auth_kind
                    );
                    cli_manual_config(
                        &runner,
                        &config,
                        &provider_name,
                        &remote_name,
                        &binary,
                    )?;
                }
                ProviderAuthKind::Unknown => {
                    eprintln!(
                        "Warning: backend '{}' auth type is unknown; attempting OAuth authorize (best effort).",
                        provider_name
                    );
                }
                ProviderAuthKind::OAuth => {}
            }

            // Unknown backend: best-effort OAuth via `rclone authorize <backend>`.
            if args.mobile_auth {
                let mut running = spawn_authorize(&runner, provider_name.as_str(), true)?;
                let auth_url = running
                    .wait_for_auth_url(Duration::from_secs(20))?
                    .ok_or_else(|| {
                        anyhow::anyhow!("rclone authorize did not produce an auth URL")
                    })?;

                println!("Open on phone: {}", auth_url);
                if let Ok(qr) = render_qr_code(&auth_url) {
                    println!("\nScan this QR code:\n{}", qr);
                }
                println!();
                println!("After login, copy/paste the final redirect URL (it may fail to load), or paste only the code value.");

                let pasted = prompt_line("Paste redirect URL (or code): ")?;
                let cb = parse_authorize_callback_input(&pasted)?;

                let redirect_uri = running
                    .redirect_uri()
                    .ok_or_else(|| anyhow::anyhow!("Missing redirect_uri in authorize output"))?;
                let state = cb.state.as_deref().or(running.expected_state());
                send_local_authorize_callback(redirect_uri, &cb.code, state)?;

                finish_authorize(running, &config, &remote_name)?;
            } else {
                let running = spawn_authorize(&runner, provider_name.as_str(), false)?;
                finish_authorize(running, &config, &remote_name)?;
            }
        }

        let include_hashes = known
            .map(|provider| !provider.hash_types().is_empty())
            .unwrap_or(false);
        let listing = list_path(
            &runner,
            &format!("{}:", remote_name),
            if include_hashes {
                ListPathOptions::with_hashes()
            } else {
                ListPathOptions::without_hashes()
            },
        )?;
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

fn should_run_tui(args: &Cli) -> bool {
    if args.tui {
        return true;
    }

    let has_cli_action = args.web_gui
        || args.forensic_ap_start
        || args.forensic_ap_stop
        || args.forensic_ap_status
        || args.onedrive_vault
        || args.set_oauth_creds.is_some()
        || args.show_oauth_creds.is_some()
        || args.provider.is_some()
        || args.download.is_some()
        || args.collect_logs;

    !has_cli_action
}

fn resolve_rclone_config_path(args: &Cli) -> Result<std::path::PathBuf> {
    if let Some(path) = args.rclone_config_path.as_ref() {
        return Ok(std::path::PathBuf::from(path));
    }

    if let Ok(path) = std::env::var("RCLONE_CONFIG") {
        let trimmed = path.trim();
        if !trimmed.is_empty() {
            return Ok(std::path::PathBuf::from(trimmed));
        }
    }

    let case_path = args.output_dir.join("config").join("rclone.conf");
    if case_path.exists() {
        return Ok(case_path);
    }

    if let Some(config_dir) = dirs::config_dir() {
        let default_path = config_dir.join("rclone").join("rclone.conf");
        if default_path.exists() {
            return Ok(default_path);
        }
    }

    bail!("No rclone config file found. Use --rclone-config or set RCLONE_CONFIG.");
}

/// Wait for a running `rclone authorize` process to finish, extract the token,
/// and persist the remote in the config.
fn finish_authorize(
    running: RunningAuthorize,
    config: &RcloneConfig,
    remote_name: &str,
) -> Result<()> {
    let finished = running.wait(Some(Duration::from_secs(300)))?;
    if finished.timed_out {
        bail!("rclone authorize timed out waiting for completion");
    }
    if finished.status != 0 {
        bail!(
            "rclone authorize failed (exit {}): {}",
            finished.status,
            finished.stderr.join("\n")
        );
    }
    let token = finished
        .token_json
        .ok_or_else(|| anyhow::anyhow!("Failed to extract token JSON from rclone output"))?;

    config.set_remote(remote_name, &finished.backend, &[("token", token.as_str())])?;
    if !config.has_remote(remote_name)? {
        bail!("Remote {} was not created", remote_name);
    }
    Ok(())
}

/// Download files from a CSV/XLSX queue via CLI (no TUI needed).
fn cli_download_from_queue(
    binary: &rclone_triage::embedded::ExtractedBinary,
    case: &Case,
    queue_path_str: &str,
    remote_override: Option<&str>,
    app_guard: &AppGuard,
) -> Result<()> {
    use rclone_triage::files::{
        read_download_queue, DownloadMode, DownloadQueue, DownloadRequest,
    };

    let queue_path = std::path::PathBuf::from(queue_path_str);
    if !queue_path.exists() {
        bail!("Queue file not found: {:?}", queue_path);
    }

    println!("Loading download queue from {:?}...", queue_path);
    let entries = read_download_queue(&queue_path)?;
    if entries.is_empty() {
        bail!("Queue file is empty or has no usable entries");
    }
    println!("Found {} files in queue", entries.len());

    // Set up config
    let config = RcloneConfig::for_case(&case.output_dir)?;
    app_guard.track_env_value("RCLONE_CONFIG", config.original_env());
    let runner = RcloneRunner::new(binary.path()).with_config(config.path());

    // Determine remote name
    let remote_name = if let Some(name) = remote_override {
        name.to_string()
    } else {
        // Try to find a remote in the config
        let parsed = config.parse()?;
        let remotes: Vec<String> = parsed.remotes.iter().map(|s| s.name.clone()).collect();
        if remotes.is_empty() {
            bail!(
                "No remotes found in config {:?}. Authenticate first with --provider, or specify --remote.",
                config.path()
            );
        }
        if remotes.len() == 1 {
            println!("Using remote: {}", remotes[0]);
            remotes[0].clone()
        } else {
            println!("Available remotes:");
            for (i, r) in remotes.iter().enumerate() {
                println!("  {}. {}", i + 1, r);
            }
            let choice = prompt_line("Select remote number: ")?;
            let idx: usize = choice
                .trim()
                .parse::<usize>()
                .map_err(|_| anyhow::anyhow!("Invalid number"))?;
            if idx == 0 || idx > remotes.len() {
                bail!("Invalid remote number");
            }
            remotes[idx - 1].clone()
        }
    };

    // Build downloads directory
    let downloads_dir = case.output_dir.join(&case.name).join("downloads");
    std::fs::create_dir_all(&downloads_dir)?;

    // Build download queue
    let mut queue = DownloadQueue::new();
    queue.set_verify_hashes(true);
    for entry in &entries {
        let normalized = entry
            .path
            .trim()
            .trim_start_matches(&format!("{}:", remote_name.trim_end_matches(':')))
            .trim_start_matches(['/', '\\'])
            .to_string();
        if normalized.is_empty() {
            continue;
        }
        let source = format!("{}:{}", remote_name.trim_end_matches(':'), normalized);
        let dest_path = downloads_dir.join(&normalized);
        if let Some(parent) = dest_path.parent() {
            let _ = std::fs::create_dir_all(parent);
        }
        queue.add(DownloadRequest {
            source,
            destination: dest_path.to_string_lossy().to_string(),
            mode: DownloadMode::CopyTo,
            expected_hash: entry.hash.clone(),
            expected_hash_type: entry.hash_type.clone(),
            expected_size: entry.size,
        });
    }

    let total = queue.requests.len();
    println!("Downloading {} files to {:?}...", total, downloads_dir);

    let results = queue.download_all_with_progress(&runner, |progress| {
        println!("{}", progress.status);
    });

    let mut successes = 0;
    let mut failures = Vec::new();
    for result in &results {
        if result.success {
            successes += 1;
        } else {
            failures.push(format!(
                "  {} - {}",
                result.source,
                result.error.as_deref().unwrap_or("unknown error")
            ));
        }
    }

    println!("\nDownload complete: {}/{} succeeded", successes, total);
    if !failures.is_empty() {
        println!("Failed downloads:");
        for f in &failures {
            println!("{}", f);
        }
    }

    Ok(())
}

/// Interactive CLI manual configuration for non-OAuth backends.
fn cli_manual_config(
    runner: &RcloneRunner,
    config: &RcloneConfig,
    backend: &str,
    remote_name: &str,
    binary: &rclone_triage::embedded::ExtractedBinary,
) -> Result<()> {
    use rclone_triage::providers::schema::provider_schema_from_rclone;

    let rclone_runner = RcloneRunner::new(binary.path());
    let schema = provider_schema_from_rclone(&rclone_runner, backend).ok().flatten();

    let mut options: Vec<(String, String)> = Vec::new();

    // Prompt required options from schema (if available)
    if let Some(ref schema) = schema {
        let required: Vec<_> = schema.options.iter().filter(|o| o.required).collect();
        for opt in &required {
            let default = opt.default_string();
            let default_hint = default
                .as_deref()
                .filter(|d| !d.is_empty())
                .map(|d| format!(" [default: {}]", d))
                .unwrap_or_default();
            let help = opt.help_text();
            if !help.is_empty() {
                println!("  {}: {}", opt.name, help);
            }
            let value = prompt_line(&format!("{}{}: ", opt.name, default_hint))?;
            let value = if value.trim().is_empty() {
                default.unwrap_or_default()
            } else {
                value
            };
            if value.trim().is_empty() && opt.required {
                bail!("Required option '{}' cannot be empty", opt.name);
            }
            // Obscure passwords
            let final_value = if opt.is_password || is_password_key(&opt.name) {
                obscure_value_with_rclone(runner, &value)?
            } else {
                value
            };
            options.push((opt.name.clone(), final_value));
        }
    }

    // Allow additional free-form options
    println!("Enter additional options (key=value). Blank key to finish.");
    loop {
        let key = prompt_line("Option key (blank to finish): ")?;
        if key.trim().is_empty() {
            break;
        }
        let value = prompt_line(&format!("{}: ", key.trim()))?;
        let schema_opt = schema.as_ref().and_then(|s| {
            s.options
                .iter()
                .find(|o| o.name.eq_ignore_ascii_case(key.trim()))
        });
        let needs_obscure = schema_opt.map(|o| o.is_password).unwrap_or(false)
            || is_password_key(key.trim());
        let final_value = if needs_obscure {
            obscure_value_with_rclone(runner, &value)?
        } else {
            value
        };
        options.push((key.trim().to_string(), final_value));
    }

    let options_ref: Vec<(&str, &str)> = options
        .iter()
        .map(|(k, v)| (k.as_str(), v.as_str()))
        .collect();
    config.set_remote(remote_name, backend, &options_ref)?;
    if !config.has_remote(remote_name)? {
        bail!("Remote {} was not created", remote_name);
    }
    println!("Remote '{}' configured for backend '{}'.", remote_name, backend);
    Ok(())
}

fn is_password_key(key: &str) -> bool {
    let k = key.trim().to_ascii_lowercase();
    matches!(k.as_str(), "pass" | "password")
        || k.ends_with("_pass")
        || k.ends_with("_password")
}

fn obscure_value_with_rclone(runner: &RcloneRunner, value: &str) -> Result<String> {
    let output = runner.run(&["obscure", value])?;
    if !output.success() {
        bail!("rclone obscure failed: {}", output.stderr_string());
    }
    output
        .stdout
        .iter()
        .find_map(|line| {
            let trimmed = line.trim();
            if trimmed.is_empty() {
                None
            } else {
                Some(trimmed.to_string())
            }
        })
        .ok_or_else(|| anyhow::anyhow!("rclone obscure returned no output"))
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

/// Collect debug logs, compress into a tarball, and optionally share via Tailscale.
fn collect_debug_logs(args: &Cli) -> Result<()> {
    use std::io::Write;

    let timestamp = chrono::Utc::now().format("%Y%m%d-%H%M%S").to_string();
    let staging = std::path::PathBuf::from(format!("/tmp/rclone-triage-logs-{}", timestamp));
    std::fs::create_dir_all(&staging)?;

    println!("Collecting debug logs...");

    // 1. System info
    let mut sys_info = String::new();
    sys_info.push_str(&format!("Date: {}\n", chrono::Utc::now()));
    sys_info.push_str(&format!(
        "OS: {} {}\n",
        std::env::consts::OS,
        std::env::consts::ARCH
    ));
    if let Ok(hostname) = std::fs::read_to_string("/etc/hostname") {
        sys_info.push_str(&format!("Hostname: {}\n", hostname.trim()));
    }
    if let Ok(user) = std::env::var("USER") {
        sys_info.push_str(&format!("User: {}\n", user));
    }
    // Filtered env vars
    sys_info.push_str("\nRelevant environment:\n");
    for (key, val) in std::env::vars() {
        if key.starts_with("RCLONE_") || key == "PATH" || key == "HOME" || key == "SHELL" {
            sys_info.push_str(&format!("  {}={}\n", key, val));
        }
    }
    std::fs::write(staging.join("system-info.txt"), &sys_info)?;
    println!("  [+] System info");

    // 2. rclone-triage version
    let triage_info = format!(
        "rclone-triage v{}\nOS: {} {}\n",
        env!("CARGO_PKG_VERSION"),
        std::env::consts::OS,
        std::env::consts::ARCH,
    );
    std::fs::write(staging.join("triage-info.txt"), &triage_info)?;
    println!("  [+] Tool version");

    // 3. Find and collect case directory
    let case_dir = find_latest_case_dir(&args.output_dir);
    if let Some(ref case) = case_dir {
        println!("  [+] Found case: {}", case.display());

        // Copy logs
        let logs_src = case.join("logs");
        if logs_src.is_dir() {
            let logs_dst = staging.join("logs");
            std::fs::create_dir_all(&logs_dst)?;
            copy_dir_contents(&logs_src, &logs_dst)?;
            println!("  [+] Forensic logs");
        }

        // Copy config (redacted)
        let config_src = case.join("config");
        if config_src.is_dir() {
            let config_dst = staging.join("config");
            std::fs::create_dir_all(&config_dst)?;
            for entry in std::fs::read_dir(&config_src)? {
                let entry = entry?;
                if entry.file_type()?.is_file() {
                    let content = std::fs::read_to_string(entry.path()).unwrap_or_default();
                    let redacted = redact_secrets(&content);
                    std::fs::write(config_dst.join(entry.file_name()), redacted)?;
                }
            }
            println!("  [+] Config (secrets redacted)");
        }

        // Copy forensic report
        let report = case.join("forensic_report.txt");
        if report.is_file() {
            std::fs::copy(&report, staging.join("forensic_report.txt"))?;
            println!("  [+] Forensic report");
        }

        // Listing samples (first 50 lines)
        let listings_src = case.join("listings");
        if listings_src.is_dir() {
            let listings_dst = staging.join("listings");
            std::fs::create_dir_all(&listings_dst)?;
            for entry in std::fs::read_dir(&listings_src)? {
                let entry = entry?;
                let name = entry.file_name();
                if entry.file_type()?.is_file() {
                    let content = std::fs::read_to_string(entry.path()).unwrap_or_default();
                    let sample: String = content.lines().take(51).collect::<Vec<_>>().join("\n");
                    std::fs::write(listings_dst.join(name), sample)?;
                }
            }
            println!("  [+] Listing samples");
        }
    } else {
        println!(
            "  [!] No case directory found (searched {})",
            args.output_dir.display()
        );
    }

    // 4. README for LLM context
    let mut readme = String::new();
    readme.push_str("# rclone-triage Debug Log Bundle\n\n");
    readme.push_str(&format!("Generated: {}\n\n", chrono::Utc::now()));
    readme.push_str("## Files\n\n");
    readme.push_str("- system-info.txt   — OS, env vars\n");
    readme.push_str("- triage-info.txt   — Tool version\n");
    readme.push_str("- logs/             — Hash-chained forensic logs\n");
    readme.push_str("- config/           — rclone config (secrets redacted)\n");
    readme.push_str("- listings/         — First 50 lines of listing CSVs\n");
    readme.push_str("- forensic_report.txt — Session report\n\n");
    readme.push_str("## Instructions\n\n");
    readme.push_str("Share the .tar.gz with an LLM for debugging.\n");
    readme.push_str("All secrets/tokens have been redacted.\n");
    std::fs::write(staging.join("README.md"), &readme)?;

    // 5. Create .tar.gz
    let archive_path = format!("/tmp/rclone-triage-logs-{}.tar.gz", timestamp);
    let tar_gz = std::fs::File::create(&archive_path)?;
    let enc = flate2::write::GzEncoder::new(tar_gz, flate2::Compression::default());
    let mut tar = tar::Builder::new(enc);
    tar.append_dir_all(format!("rclone-triage-logs-{}", timestamp), &staging)?;
    tar.finish()?;

    let size = std::fs::metadata(&archive_path)?.len();
    println!("\nLog bundle: {} ({} bytes)", archive_path, size);

    // 6. Tailscale sharing
    if which_exists("tailscale") {
        println!("\nTailscale detected. Checking peers...");
        let output = std::process::Command::new("tailscale")
            .args(["status", "--json"])
            .output();
        if let Ok(output) = output {
            if output.status.success() {
                if let Ok(json) = serde_json::from_slice::<serde_json::Value>(&output.stdout) {
                    let mut peers = Vec::new();
                    if let Some(peer_map) = json.get("Peer").and_then(|p| p.as_object()) {
                        for (_key, peer) in peer_map {
                            let online = peer
                                .get("Online")
                                .and_then(|v| v.as_bool())
                                .unwrap_or(false);
                            if online {
                                let name = peer
                                    .get("HostName")
                                    .and_then(|v| v.as_str())
                                    .unwrap_or("unknown");
                                let ip = peer
                                    .get("TailscaleIPs")
                                    .and_then(|v| v.as_array())
                                    .and_then(|a| a.first())
                                    .and_then(|v| v.as_str())
                                    .unwrap_or("");
                                peers.push((name.to_string(), ip.to_string()));
                            }
                        }
                    }
                    if !peers.is_empty() {
                        println!("Online peers:");
                        for (name, ip) in &peers {
                            println!("  {} ({})", name, ip);
                        }
                        print!("\nSend to peer (hostname, or Enter to skip): ");
                        std::io::stdout().flush()?;
                        let target = prompt_line("")?;
                        if !target.is_empty() {
                            println!("Sending to {}...", target);
                            let send = std::process::Command::new("tailscale")
                                .args(["file", "cp", &archive_path, &format!("{}:", target)])
                                .status();
                            match send {
                                Ok(s) if s.success() => {
                                    println!("Sent! Peer can accept with: tailscale file get .");
                                }
                                _ => {
                                    println!(
                                        "Send failed. Manual: tailscale file cp {} {}:",
                                        archive_path, target
                                    );
                                }
                            }
                        }
                    } else {
                        println!("No online peers found.");
                    }
                }
            }
        }
    }

    println!("\nManual share options:");
    println!("  tailscale file cp {} <peer>:", archive_path);
    println!("  scp {} user@host:/path/", archive_path);

    Ok(())
}

fn find_latest_case_dir(base: &std::path::Path) -> Option<std::path::PathBuf> {
    let mut candidates: Vec<_> = std::fs::read_dir(base)
        .ok()?
        .filter_map(|e| e.ok())
        .filter(|e| {
            e.file_type().map(|t| t.is_dir()).unwrap_or(false)
                && e.file_name().to_string_lossy().starts_with("triage-")
        })
        .collect();
    candidates.sort_by(|a, b| {
        b.metadata()
            .and_then(|m| m.modified())
            .unwrap_or(std::time::SystemTime::UNIX_EPOCH)
            .cmp(
                &a.metadata()
                    .and_then(|m| m.modified())
                    .unwrap_or(std::time::SystemTime::UNIX_EPOCH),
            )
    });
    candidates.first().map(|e| e.path())
}

fn copy_dir_contents(src: &std::path::Path, dst: &std::path::Path) -> Result<()> {
    for entry in std::fs::read_dir(src)? {
        let entry = entry?;
        let dest_path = dst.join(entry.file_name());
        if entry.file_type()?.is_dir() {
            std::fs::create_dir_all(&dest_path)?;
            copy_dir_contents(&entry.path(), &dest_path)?;
        } else {
            std::fs::copy(entry.path(), &dest_path)?;
        }
    }
    Ok(())
}

fn redact_secrets(content: &str) -> String {
    let mut output = String::with_capacity(content.len());
    for line in content.lines() {
        let lower = line.to_lowercase();
        if lower.contains("token")
            || lower.contains("secret")
            || lower.contains("password")
            || lower.contains("pass =")
            || lower.contains("access_token")
            || lower.contains("refresh_token")
        {
            if let Some(eq_pos) = line.find('=') {
                output.push_str(&line[..=eq_pos]);
                output.push_str(" <REDACTED>");
            } else {
                output.push_str(line);
            }
        } else {
            output.push_str(line);
        }
        output.push('\n');
    }
    output
}

fn which_exists(cmd: &str) -> bool {
    std::process::Command::new("which")
        .arg(cmd)
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .status()
        .map(|s| s.success())
        .unwrap_or(false)
}

/// CLI arguments
#[derive(Parser, Debug)]
#[command(author, version, about = "Cloud triage tool")]
struct Cli {
    /// Case name (folder name for output). Defaults to triage-YYYYMMDD-HHMMSS
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

    /// Use OAuth device code flow (supported providers only)
    #[arg(long, default_value_t = false)]
    device_code: bool,

    /// Download files from a CSV/XLSX queue file (requires --provider and existing config)
    #[arg(long)]
    download: Option<String>,

    /// Remote name to use for download (if multiple remotes exist)
    #[arg(long)]
    remote: Option<String>,

    /// Set custom OAuth credentials for a provider/backend (interactive)
    #[arg(long)]
    set_oauth_creds: Option<String>,

    /// Override custom OAuth config path
    #[arg(long)]
    oauth_config_path: Option<String>,

    /// Show OAuth credentials for a configured remote (no secrets printed)
    #[arg(long)]
    show_oauth_creds: Option<String>,

    /// Override rclone config path for credential inspection
    #[arg(long)]
    rclone_config_path: Option<String>,

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

    /// Collect debug logs, compress, and optionally share via Tailscale
    #[arg(long, default_value_t = false)]
    collect_logs: bool,
}

fn prompt_line(prompt: &str) -> Result<String> {
    use std::io::{self, Write};
    let mut stdout = io::stdout();
    stdout.write_all(prompt.as_bytes())?;
    stdout.flush()?;
    let mut input = String::new();
    io::stdin().read_line(&mut input)?;
    Ok(input.trim().to_string())
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

#[cfg(test)]
mod tests {
    use super::*;

    fn default_cli() -> Cli {
        Cli {
            name: "".to_string(),
            output_dir: std::path::PathBuf::from("."),
            provider: None,
            tui: false,
            mobile_auth: false,
            mobile_auth_port: 53682,
            device_code: false,
            download: None,
            remote: None,
            set_oauth_creds: None,
            oauth_config_path: None,
            show_oauth_creds: None,
            rclone_config_path: None,
            web_gui: false,
            web_gui_port: 5572,
            web_gui_user: None,
            web_gui_pass: None,
            forensic_ap_start: false,
            forensic_ap_stop: false,
            forensic_ap_status: false,
            forensic_ap_ssid: None,
            forensic_ap_password: None,
            forensic_ap_timeout_minutes: None,
            onedrive_vault: false,
            onedrive_vault_mount: None,
            onedrive_vault_dest: None,
            onedrive_vault_no_wait: false,
            collect_logs: false,
        }
    }

    #[test]
    fn test_should_run_tui_default_true() {
        let args = default_cli();
        assert!(should_run_tui(&args));
    }

    #[test]
    fn test_should_run_tui_explicit_flag_true() {
        let mut args = default_cli();
        args.tui = true;
        assert!(should_run_tui(&args));
    }

    #[test]
    fn test_should_run_tui_provider_false() {
        let mut args = default_cli();
        args.provider = Some("drive".to_string());
        assert!(!should_run_tui(&args));
    }

    #[test]
    fn test_should_run_tui_web_gui_false() {
        let mut args = default_cli();
        args.web_gui = true;
        assert!(!should_run_tui(&args));
    }

    #[test]
    fn test_should_run_tui_forensic_ap_false() {
        let mut args = default_cli();
        args.forensic_ap_start = true;
        assert!(!should_run_tui(&args));
    }

    #[test]
    fn test_should_run_tui_onedrive_vault_false() {
        let mut args = default_cli();
        args.onedrive_vault = true;
        assert!(!should_run_tui(&args));
    }

    #[test]
    fn test_should_run_tui_set_oauth_creds_false() {
        let mut args = default_cli();
        args.set_oauth_creds = Some("drive".to_string());
        assert!(!should_run_tui(&args));
    }

    #[test]
    fn test_should_run_tui_show_oauth_creds_false() {
        let mut args = default_cli();
        args.show_oauth_creds = Some("remote".to_string());
        assert!(!should_run_tui(&args));
    }
}
