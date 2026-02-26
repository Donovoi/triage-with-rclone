//! Basic TUI runner
//!
//! Sets up terminal backend and renders a single frame.

use anyhow::{bail, Result};
use crossterm::event::{
    self, DisableBracketedPaste, DisableMouseCapture, EnableBracketedPaste, EnableMouseCapture,
    Event, KeyCode, KeyEvent, KeyEventKind,
    MouseButton, MouseEvent, MouseEventKind,
};
use crossterm::execute;
use crossterm::terminal::{
    disable_raw_mode, enable_raw_mode, EnterAlternateScreen, LeaveAlternateScreen,
};
use ratatui::backend::CrosstermBackend;
use ratatui::Terminal;
use chrono::Local;
use std::collections::HashSet;
use std::io::stdout;
use std::path::{Path, PathBuf};
use std::time::{Duration, Instant, SystemTime};

use crate::ui::{render::render_state, App};

fn format_provider_stats(
    stats: &crate::providers::discovery::ProviderDiscoveryStats,
    kept: usize,
) -> String {
    let excluded = stats.excluded_total();
    let mut details = Vec::new();
    if stats.excluded_bad > 0 {
        details.push(format!("{} bad", stats.excluded_bad));
    }
    if stats.excluded_no_prefix > 0 {
        details.push(format!("{} no-prefix", stats.excluded_no_prefix));
    }
    if stats.excluded_duplicates > 0 {
        details.push(format!("{} duplicate", stats.excluded_duplicates));
    }
    let detail_text = if details.is_empty() {
        "none".to_string()
    } else {
        details.join(", ")
    };
    format!(
        "Total: {} (shown {}, OAuth {}, non-oauth {}, excluded {}: {}).",
        stats.total,
        kept,
        stats.oauth_capable,
        stats.non_oauth,
        excluded,
        detail_text
    )
}

fn apply_discovered_providers(
    app: &mut App,
    discovery: crate::providers::discovery::ProviderDiscoveryResult,
) {
    // Keep everything rclone reports (after `providers_from_rclone_json` filtering), so users can
    // still select key-based/manual backends when they already have an authenticated config.
    //
    // Auth flows are gated later by `auth_kind` to avoid offering OAuth/mobile auth on backends
    // that require API keys or other manual configuration.
    let mut providers = discovery.providers;

    if !providers.is_empty() {
        let stats_summary = format_provider_stats(&discovery.stats, providers.len());
        crate::providers::ProviderEntry::sort_entries(&mut providers);
        app.provider.entries = providers;
        if app.provider.selected >= app.provider.entries.len() {
            app.provider.selected = 0;
        }
        app.provider.checked = vec![false; app.provider.entries.len()];
        app.provider.status = format!(
            "Loaded {} providers from rclone. {}",
            app.provider.entries.len(),
            stats_summary
        );
        record_provider_refresh(app, None);
    } else {
        let stats_summary = format_provider_stats(&discovery.stats, 0);
        app.provider.status = format!(
            "No supported providers found; using defaults. {}",
            stats_summary
        );
        app.log_info("No supported providers found; using defaults");
        record_provider_refresh(
            app,
            Some("No supported providers found.".to_string()),
        );
    }
}

fn record_provider_refresh(app: &mut App, error: Option<String>) {
    app.provider.last_updated = Some(Local::now());
    app.provider.last_error = error;
}

fn resolve_download_queue_path(app: &App) -> Result<PathBuf> {
    let env_candidates = ["RCLONE_TRIAGE_DOWNLOAD_QUEUE", "RCLONE_TRIAGE_QUEUE_PATH"];
    for key in env_candidates {
        if let Ok(value) = std::env::var(key) {
            let trimmed = value.trim();
            if !trimmed.is_empty() {
                return Ok(PathBuf::from(trimmed));
            }
        }
    }

    if let Some(dirs) = &app.forensics.directories {
        if let Some(path) = find_queue_candidate(&dirs.listings) {
            return Ok(path);
        }
        let hint = dirs.listings.join("queue.xlsx");
        bail!(
            "No CSV/XLSX queue found in {:?}. Place a queue file at {:?} or set RCLONE_TRIAGE_DOWNLOAD_QUEUE.",
            dirs.listings,
            hint
        );
    }

    bail!("Case directory not initialized; cannot locate download queue file.");
}

fn find_queue_candidate(dir: &Path) -> Option<PathBuf> {
    let entries = std::fs::read_dir(dir).ok()?;
    let mut candidates = Vec::new();
    for entry in entries.flatten() {
        let path = entry.path();
        let ext = path
            .extension()
            .and_then(|e| e.to_str())
            .unwrap_or("")
            .to_lowercase();
        if ext != "xlsx" && ext != "csv" {
            continue;
        }
        let name = path.file_name().and_then(|n| n.to_str()).unwrap_or("");
        let score = score_queue_name(name);
        let modified = entry
            .metadata()
            .and_then(|m| m.modified())
            .unwrap_or(SystemTime::UNIX_EPOCH);
        candidates.push(QueueCandidate {
            score,
            modified,
            path,
        });
    }

    candidates.sort_by(|a, b| {
        b.score
            .cmp(&a.score)
            .then_with(|| b.modified.cmp(&a.modified))
    });

    candidates.first().map(|c| c.path.clone())
}

struct QueueCandidate {
    score: i32,
    modified: SystemTime,
    path: PathBuf,
}

fn score_queue_name(name: &str) -> i32 {
    let lowered = name.to_lowercase();
    let mut score = 0;
    if lowered.contains("todownload") || lowered.contains("to_download") {
        score += 3;
    }
    if lowered.contains("queue") {
        score += 2;
    }
    if lowered.contains("selection") {
        score += 1;
    }
    if lowered.ends_with(".xlsx") {
        score += 1;
    }
    score
}

fn normalize_queue_path(path: &str, remote_name: &str) -> String {
    let mut candidate = path.trim().to_string();
    let remote = remote_name.trim_end_matches(':');
    let prefix = format!("{}:", remote);
    if candidate.to_lowercase().starts_with(&prefix.to_lowercase()) {
        candidate = candidate[prefix.len()..].to_string();
    }
    candidate.trim_start_matches(['/', '\\']).to_string()
}

fn apply_queue_entries(
    app: &mut App,
    entries: Vec<crate::files::DownloadQueueEntry>,
    remote_name: &str,
) -> Result<usize> {
    let mut seen = HashSet::new();
    let mut full_entries = Vec::new();

    for entry in entries {
        let normalized = normalize_queue_path(&entry.path, remote_name);
        if normalized.is_empty() || !seen.insert(normalized.clone()) {
            continue;
        }

        full_entries.push(crate::files::FileEntry {
            path: normalized,
            size: entry.size.unwrap_or(0),
            modified: None,
            is_dir: false,
            hash: entry.hash,
            hash_type: entry.hash_type,
        });
    }

    if full_entries.is_empty() {
        bail!("Queue contained no usable file paths");
    }

    app.files.entries_full = full_entries.clone();
    app.files.entries = full_entries.iter().map(|e| e.path.clone()).collect();
    app.files.to_download = app.files.entries.clone();
    app.files.selected = 0;

    Ok(app.files.to_download.len())
}

fn try_refresh_providers(app: &mut App) {
    let allow = std::env::var("RCLONE_TRIAGE_DYNAMIC_PROVIDERS")
        .map(|v| v != "0")
        .unwrap_or(true);

    if !allow {
        app.provider.status = format!(
            "Provider refresh disabled by RCLONE_TRIAGE_DYNAMIC_PROVIDERS=0. Using built-in providers ({}).",
            app.provider.entries.len()
        );
        record_provider_refresh(
            app,
            Some("Provider refresh disabled by RCLONE_TRIAGE_DYNAMIC_PROVIDERS=0.".to_string()),
        );
        return;
    }

    app.provider.status = "Refreshing providers...".to_string();

    let binary = match crate::embedded::ExtractedBinary::extract() {
        Ok(binary) => binary,
        Err(e) => {
            let message = format!("Provider discovery failed (extract): {}", e);
            app.provider.status = format!("Provider discovery failed: {}. Using built-in list.", e);
            app.log_error(message);
            record_provider_refresh(
                app,
                Some(format!("Provider discovery failed (extract): {}", e)),
            );
            return;
        }
    };

    app.cleanup_track_file(binary.path());
    if let Some(dir) = binary.temp_dir() {
        app.cleanup_track_dir(dir);
    }

    let runner = crate::rclone::RcloneRunner::new(binary.path());
    let discovery = match crate::providers::discovery::providers_from_rclone(&runner) {
        Ok(discovery) => discovery,
        Err(e) => {
            let message = format!("Provider discovery failed: {}", e);
            app.provider.status = format!("Provider discovery failed: {}. Using built-in list.", e);
            app.log_error(message.clone());
            record_provider_refresh(app, Some(message));
            return;
        }
    };

    apply_discovered_providers(app, discovery);
}


fn perform_csv_download_flow<B: ratatui::backend::Backend>(
    app: &mut App,
    terminal: &mut Terminal<B>,
) -> Result<()> {
    let Some(provider) = app.provider.chosen.clone() else {
        app.provider.status = "No provider selected.".to_string();
        return Ok(());
    };

    app.provider.status = "Loading CSV/XLSX download queue...".to_string();
    terminal.draw(|f| render_state(f, app))?;

    let queue_path = match resolve_download_queue_path(app) {
        Ok(path) => path,
        Err(e) => {
            app.provider.status = format!("Queue not found: {}", e);
            app.log_error(format!("Queue not found: {}", e));
            return Ok(());
        }
    };

    let queue_entries = match crate::files::read_download_queue(&queue_path) {
        Ok(entries) => entries,
        Err(e) => {
            app.provider.status = format!("Queue load failed: {}", e);
            app.log_error(format!("Queue load failed: {}", e));
            return Ok(());
        }
    };

    let config_dir = app
        .config_dir()
        .unwrap_or_else(|| std::path::PathBuf::from("."));
    app.track_env_var("RCLONE_CONFIG", "Set RCLONE_CONFIG for download queue");
    let config = match crate::rclone::RcloneConfig::for_case(&config_dir) {
        Ok(config) => config,
        Err(e) => {
            app.provider.status = format!("Queue failed (config): {}", e);
            app.log_error(format!("Queue failed (config): {}", e));
            return Ok(());
        }
    };
    app.cleanup_track_env_value("RCLONE_CONFIG", config.original_env());

    let remotes = match crate::ui::flows::remotes::resolve_provider_remotes(&config, &provider) {
        Ok(remotes) => remotes,
        Err(e) => {
            app.provider.status = format!("Queue failed (parse config): {}", e);
            app.log_error(format!("Queue failed (parse config): {}", e));
            return Ok(());
        }
    };

    if remotes.is_empty() {
        app.provider.status = format!(
            "No authenticated remotes found for {}. Copy a config to {:?} and retry.",
            provider.display_name(),
            config.path()
        );
        app.log_error(format!(
            "No authenticated remotes found for {}",
            provider.display_name()
        ));
        return Ok(());
    }

    let remote_name =
        match crate::ui::flows::remotes::choose_remote_or_prompt(app, &provider, remotes)? {
        Some(remote_name) => remote_name,
        None => return Ok(()),
    };

    app.remote.chosen = Some(remote_name.clone());
    let count = match apply_queue_entries(app, queue_entries, &remote_name) {
        Ok(count) => count,
        Err(e) => {
            app.provider.status = format!("Queue parse failed: {}", e);
            app.log_error(format!("Queue parse failed: {}", e));
            return Ok(());
        }
    };

    app.provider.status = format!("Loaded {} queued files from {:?}", count, queue_path);
    app.log_info(format!("Loaded {} queued files from {:?}", count, queue_path));

    app.state = crate::ui::AppState::Downloading;
    crate::ui::flows::download::perform_download_flow(app, terminal)?;
    Ok(())
}

fn perform_web_gui_flow<B: ratatui::backend::Backend>(
    app: &mut App,
    terminal: &mut Terminal<B>,
) -> Result<()> {
    app.menu_status = "Starting rclone Web GUI...".to_string();
    terminal.draw(|f| render_state(f, app))?;

    let binary = match crate::embedded::ExtractedBinary::extract() {
        Ok(binary) => binary,
        Err(e) => {
            app.menu_status = format!("Web GUI failed (extract): {}", e);
            app.log_error(format!("Web GUI failed (extract): {}", e));
            return Ok(());
        }
    };
    app.cleanup_track_file(binary.path());
    if let Some(dir) = binary.temp_dir() {
        app.cleanup_track_dir(dir);
    }

    let config_dir = app
        .config_dir()
        .unwrap_or_else(|| std::path::PathBuf::from("."));
    let config = match crate::rclone::RcloneConfig::for_case(&config_dir) {
        Ok(config) => config,
        Err(e) => {
            app.menu_status = format!("Web GUI failed (config): {}", e);
            app.log_error(format!("Web GUI failed (config): {}", e));
            return Ok(());
        }
    };
    app.cleanup_track_env_value("RCLONE_CONFIG", config.original_env());

    let port = 5572u16;
    match crate::rclone::start_web_gui(binary.path(), Some(config.path()), port, None, None) {
        Ok(web) => {
            let addr = format!("http://127.0.0.1:{}/", port);
            app.web_gui_process = Some(web);
            app.menu_status = format!(
                "rclone Web GUI started at {}\n\nOpen in your browser. It will run until you exit.",
                addr
            );
            app.log_info(format!("Started rclone Web GUI at {}", addr));
        }
        Err(e) => {
            app.menu_status = format!("Web GUI failed: {}", e);
            app.log_error(format!("Web GUI failed: {}", e));
        }
    }

    Ok(())
}

fn perform_update_tools_flow<B: ratatui::backend::Backend>(
    app: &mut App,
    terminal: &mut Terminal<B>,
) -> Result<()> {
    app.menu_status = "Checking tool status...".to_string();
    terminal.draw(|f| render_state(f, app))?;

    let mut lines = Vec::new();
    lines.push(format!(
        "rclone-triage version: {}",
        env!("CARGO_PKG_VERSION")
    ));
    lines.push("rclone: embedded in binary (no separate update needed)".to_string());

    // Check FUSE/WinFSP availability (needed for mount)
    match crate::embedded::ExtractedBinary::extract() {
        Ok(binary) => {
            app.cleanup_track_file(binary.path());
            if let Some(dir) = binary.temp_dir() {
                app.cleanup_track_dir(dir);
            }

            let manager = crate::rclone::MountManager::new(binary.path());
            match manager {
                Ok(m) => match m.check_fuse_available() {
                    Ok(true) => lines.push("FUSE/WinFSP: installed (mount available)".to_string()),
                    Ok(false) => {
                        lines.push("FUSE/WinFSP: NOT installed (mount will not work)".to_string());
                        #[cfg(windows)]
                        lines.push(
                            "  Install WinFSP from https://winfsp.dev/ to enable cloud mounting."
                                .to_string(),
                        );
                        #[cfg(target_os = "linux")]
                        lines.push(
                            "  Install fuse: sudo apt install fuse3 (or fuse)".to_string(),
                        );
                        #[cfg(target_os = "macos")]
                        lines.push(
                            "  Install macFUSE from https://osxfuse.github.io/".to_string(),
                        );
                    }
                    Err(e) => lines.push(format!("FUSE/WinFSP: check failed: {}", e)),
                },
                Err(e) => lines.push(format!("Mount manager: {}", e)),
            }

            // Show rclone version
            let runner = crate::rclone::RcloneRunner::new(binary.path());
            match runner.run(&["version"]) {
                Ok(output) => {
                    if let Some(first_line) = output.stdout.first() {
                        lines.push(format!("rclone version: {}", first_line.trim()));
                    }
                }
                Err(e) => lines.push(format!("rclone version check failed: {}", e)),
            }
        }
        Err(e) => lines.push(format!("Binary extraction failed: {}", e)),
    }

    app.menu_status = lines.join("\n");
    Ok(())
}

fn perform_configure_oauth_flow<B: ratatui::backend::Backend>(
    app: &mut App,
    terminal: &mut Terminal<B>,
) -> Result<()> {
    app.menu_status = "Configure custom OAuth credentials".to_string();
    terminal.draw(|f| render_state(f, app))?;

    let provider_key = match crate::ui::prompt::prompt_text_in_tui(
        app,
        terminal,
        "Provider Key",
        "Enter the provider/backend name (e.g. drive, onedrive, dropbox, box, s3).\n\nThis must match the rclone backend name.\n\nEnter submit | Esc cancel",
    )? {
        Some(v) if !v.trim().is_empty() => v.trim().to_string(),
        _ => {
            app.menu_status = "OAuth configuration cancelled.".to_string();
            return Ok(());
        }
    };

    let client_id = match crate::ui::prompt::prompt_text_in_tui(
        app,
        terminal,
        "Client ID",
        &format!(
            "Enter the OAuth Client ID for '{}'.\n\nThis is provided by the cloud provider's developer console.\n\nEnter submit | Esc cancel",
            provider_key
        ),
    )? {
        Some(v) if !v.trim().is_empty() => v.trim().to_string(),
        _ => {
            app.menu_status = "OAuth configuration cancelled.".to_string();
            return Ok(());
        }
    };

    let client_secret = match crate::ui::prompt::prompt_text_in_tui(
        app,
        terminal,
        "Client Secret",
        &format!(
            "Enter the OAuth Client Secret for '{}' (optional, leave blank if none).\n\nEnter submit | Esc cancel",
            provider_key
        ),
    )? {
        Some(v) if !v.trim().is_empty() => Some(v.trim().to_string()),
        Some(_) => None,
        None => {
            app.menu_status = "OAuth configuration cancelled.".to_string();
            return Ok(());
        }
    };

    match crate::providers::credentials::upsert_custom_oauth_credentials(
        &provider_key,
        client_id,
        client_secret,
        None,
    ) {
        Ok(path) => {
            app.menu_status = format!(
                "OAuth credentials saved for '{}' at {:?}",
                provider_key, path
            );
            app.log_info(format!(
                "Saved custom OAuth credentials for '{}' to {:?}",
                provider_key, path
            ));
        }
        Err(e) => {
            app.menu_status = format!("Failed to save OAuth credentials: {}", e);
            app.log_error(format!("Failed to save OAuth credentials: {}", e));
        }
    }

    Ok(())
}

fn perform_onedrive_vault_flow<B: ratatui::backend::Backend>(
    app: &mut App,
    terminal: &mut Terminal<B>,
) -> Result<()> {
    app.menu_status = "OneDrive Vault: preparing...".to_string();
    terminal.draw(|f| render_state(f, app))?;

    let mount_point = crate::ui::prompt::prompt_text_in_tui(
        app,
        terminal,
        "OneDrive Vault Mount Point",
        "Enter the mount point where the OneDrive vault is mounted.\n\nDefault (Windows): C:\\OneDriveTemp\\\nDefault (other): ./OneDriveTemp\n\nLeave blank for default.\n\nEnter submit | Esc cancel",
    )?;
    let mount_point = match mount_point {
        Some(v) if !v.trim().is_empty() => v,
        Some(_) | None => {
            if cfg!(windows) {
                "C:\\OneDriveTemp\\".to_string()
            } else {
                "./OneDriveTemp".to_string()
            }
        }
    };

    let destination = crate::ui::prompt::prompt_text_in_tui(
        app,
        terminal,
        "OneDrive Vault Destination",
        "Enter the destination path for copied VHDX files.\n\nDefault: Desktop/OneDriveVault (Windows) or ./OneDriveVault\n\nLeave blank for default.\n\nEnter submit | Esc cancel",
    )?;
    let destination = match destination {
        Some(v) if !v.trim().is_empty() => v,
        Some(_) | None => {
            if cfg!(windows) {
                std::env::var("USERPROFILE")
                    .map(|p| format!("{}\\Desktop\\OneDriveVault", p))
                    .unwrap_or_else(|_| "C:\\OneDriveVault".to_string())
            } else {
                "./OneDriveVault".to_string()
            }
        }
    };

    app.menu_status = "Opening OneDrive Vault (Windows Hello)...".to_string();
    terminal.draw(|f| render_state(f, app))?;

    match crate::forensics::open_onedrive_vault(&mount_point, &destination, true) {
        Ok(result) => {
            let mut lines = Vec::new();
            lines.push("OneDrive Vault processed:".to_string());
            lines.push(format!("  Mount: {:?}", result.mount_point));
            lines.push(format!("  Destination: {:?}", result.destination));
            lines.push(format!("  Files copied: {}", result.copied_files.len()));
            lines.push(format!("  BitLocker disabled: {}", result.bitlocker_disabled));
            for warning in &result.warnings {
                lines.push(format!("  Warning: {}", warning));
            }
            app.menu_status = lines.join("\n");
            app.log_info(format!(
                "OneDrive Vault: copied {} files to {:?}",
                result.copied_files.len(),
                result.destination
            ));
        }
        Err(e) => {
            app.menu_status = format!("OneDrive Vault failed: {}", e);
            app.log_error(format!("OneDrive Vault failed: {}", e));
        }
    }

    Ok(())
}

/// Run a basic TUI loop with simple key handling
///
/// Controls:
/// - Enter: next state
/// - Backspace: previous state
/// - q / Esc: quit
pub fn run_loop(app: &mut App) -> Result<()> {
    enable_raw_mode()?;
    let mut out = stdout();
    execute!(out, EnterAlternateScreen, EnableMouseCapture, EnableBracketedPaste)?;

    let backend = CrosstermBackend::new(out);
    let mut terminal = Terminal::new(backend)?;

    // Ensure terminal is restored even if we exit early
    struct TuiGuard;
    impl Drop for TuiGuard {
        fn drop(&mut self) {
            let _ = disable_raw_mode();
            let mut out = std::io::stdout();
            let _ = execute!(out, DisableBracketedPaste, DisableMouseCapture, LeaveAlternateScreen);
        }
    }
    let _guard = TuiGuard;

    // Always start at the main menu for a consistent entry flow.
    app.state = crate::ui::AppState::MainMenu;
    app.menu_selected = 0;
    app.selected_action = None;
    app.menu_status.clear();

    try_refresh_providers(app);

    let mut last_nav: Option<(KeyCode, Instant)> = None;

    loop {
        terminal.draw(|f| {
            render_state(f, app);
        })?;

        let area = terminal.size()?;
        if event::poll(Duration::from_millis(200))? {
            match event::read()? {
                Event::Key(key) => {
                    if !should_handle_key(&key) {
                        continue;
                    }
                    let now = Instant::now();
                    if matches!(key.code, KeyCode::Up | KeyCode::Down) {
                        if let Some((prev, at)) = last_nav {
                            if prev == key.code && now.duration_since(at) < Duration::from_millis(80)
                            {
                                continue;
                            }
                        }
                        last_nav = Some((key.code, now));
                    }

                    if handle_provider_help_key(app, &key) {
                        continue;
                    }

                    match key.code {
                    KeyCode::Char('q') | KeyCode::Esc => break,
                    KeyCode::Enter => {
                        if app.state == crate::ui::AppState::MainMenu {
                            if handle_main_menu_enter(app) {
                                break;
                            }
                        } else if app.state == crate::ui::AppState::AdditionalOptions {
                            if let Some(item) = app.additional_menu_selected_item() {
                                let action = item.action;
                                app.menu_status.clear();
                                match action {
                                    crate::ui::MenuAction::UpdateTools => {
                                        perform_update_tools_flow(app, &mut terminal)?;
                                    }
                                    crate::ui::MenuAction::ConfigureOAuth => {
                                        perform_configure_oauth_flow(app, &mut terminal)?;
                                    }
                                    crate::ui::MenuAction::ShowOAuthCredentials => {
                                        if let Err(e) = crate::ui::flows::exports::perform_show_oauth_credentials(app) {
                                            app.menu_status = format!(
                                                "Failed to load OAuth credentials: {}",
                                                e
                                            );
                                        }
                                    }
                                    crate::ui::MenuAction::ExportBrowserSessions => {
                                        if let Err(e) = crate::ui::flows::exports::perform_export_browser_sessions(app) {
                                            app.menu_status =
                                                format!("Failed to export browser sessions: {}", e);
                                        }
                                    }
                                    crate::ui::MenuAction::ExportDomainCookies => {
                                        if let Err(e) = crate::ui::flows::exports::perform_export_domain_cookies(app, &mut terminal) {
                                            app.menu_status =
                                                format!("Failed to export domain cookies: {}", e);
                                        }
                                    }
                                    crate::ui::MenuAction::OneDriveMenu => {
                                        app.state = crate::ui::AppState::OneDriveMenu;
                                    }
                                    crate::ui::MenuAction::StartWebGui => {
                                        perform_web_gui_flow(app, &mut terminal)?;
                                    }
                                    crate::ui::MenuAction::BackToMainMenu => {
                                        app.state = crate::ui::AppState::MainMenu;
                                    }
                                    _ => {}
                                }
                            }
                        } else if app.state == crate::ui::AppState::OneDriveMenu {
                            if let Some(item) = app.onedrive_menu_selected_item() {
                                let action = item.action;
                                app.menu_status.clear();
                                match action {
                                    crate::ui::MenuAction::OpenOneDriveVault => {
                                        perform_onedrive_vault_flow(app, &mut terminal)?;
                                    }
                                    crate::ui::MenuAction::BackToAdditionalOptions => {
                                        app.state = crate::ui::AppState::AdditionalOptions;
                                    }
                                    _ => {}
                                }
                            }
                        } else if app.state == crate::ui::AppState::ProviderSelect {
                            app.confirm_provider();
                            if app.provider.chosen.is_none() {
                                continue;
                            }

                            let needs_oauth = matches!(
                                app.selected_action,
                                Some(crate::ui::MenuAction::Authenticate)
                                    | Some(crate::ui::MenuAction::SmartAuth)
                                    | Some(crate::ui::MenuAction::MobileAuth)
                            );
                            let auth_kind = app.provider.chosen.as_ref().map(|p| p.auth_kind());
                            if needs_oauth {
                                match auth_kind {
                                    Some(crate::providers::ProviderAuthKind::KeyBased)
                                    | Some(crate::providers::ProviderAuthKind::UserPass) => {
                                        app.menu_status.clear();
                                        app.browser.chosen = None;
                                        app.state = crate::ui::AppState::Authenticating;
                                        crate::ui::flows::manual_config::perform_manual_config_flow(
                                            app,
                                            &mut terminal,
                                        )?;
                                        continue;
                                    }
                                    Some(crate::providers::ProviderAuthKind::Unknown) => {
                                        if let Some(provider) = app.provider.chosen.as_ref() {
                                            // Best-effort: allow trying OAuth even if we can't confidently classify the backend.
                                            app.menu_status = format!(
                                                "Backend '{}' auth type is unknown. Attempting OAuth anyway; if it fails, configure it in an rclone config and use Retrieve List / Mount / Download from CSV.",
                                                provider.display_name()
                                            );
                                        }
                                    }
                                    _ => {}
                                }
                            }
                            match app.selected_action {
                                Some(crate::ui::MenuAction::MobileAuth) => {
                                    app.state = crate::ui::AppState::MobileAuthFlow;
                                }
                                Some(crate::ui::MenuAction::SmartAuth) => {
                                    app.browser.chosen = None;
                                    app.state = crate::ui::AppState::Authenticating;
                                    crate::ui::flows::auth::perform_auth_flow(app, &mut terminal)?;
                                }
                                Some(crate::ui::MenuAction::RetrieveList) => {
                                    crate::ui::flows::list::perform_list_flow(app, &mut terminal)?;
                                }
                                Some(crate::ui::MenuAction::MountProvider) => {
                                    crate::ui::flows::mount::perform_mount_flow(app, &mut terminal)?;
                                }
                                Some(crate::ui::MenuAction::DownloadFromCsv) => {
                                    perform_csv_download_flow(app, &mut terminal)?;
                                }
                                _ => {
                                    if app
                                        .provider.chosen
                                        .as_ref()
                                        .and_then(|p| p.known)
                                        .is_some()
                                    {
                                        app.refresh_browsers();
                                        app.advance(); // Move to BrowserSelect
                                    } else {
                                        app.browser.chosen = None;
                                        app.state = crate::ui::AppState::Authenticating;
                                        crate::ui::flows::auth::perform_auth_flow(app, &mut terminal)?;
                                    }
                                }
                            }
                        } else if app.state == crate::ui::AppState::RemoteSelect {
                            if let Some(remote_name) = app.confirm_remote() {
                                app.provider.status = format!("Selected remote: {}", remote_name);
                                resume_remote_flow(app, &mut terminal)?;
                            }
                        } else if app.state == crate::ui::AppState::MobileAuthFlow {
                            if let Some(item) = app.mobile_flow_selected_item() {
                                match item.action {
                                    crate::ui::MenuAction::MobileAuthRedirect => {
                                        app.mobile_auth_flow =
                                            Some(crate::ui::MobileAuthFlow::Redirect);
                                        app.state = crate::ui::AppState::Authenticating;
                                        crate::ui::flows::auth::perform_auth_flow(app, &mut terminal)?;
                                    }
                                    crate::ui::MenuAction::MobileAuthRedirectWithAp => {
                                        app.mobile_auth_flow =
                                            Some(crate::ui::MobileAuthFlow::RedirectWithAccessPoint);
                                        app.state = crate::ui::AppState::Authenticating;
                                        crate::ui::flows::auth::perform_auth_flow(app, &mut terminal)?;
                                    }
                                    crate::ui::MenuAction::MobileAuthDeviceCode => {
                                        app.mobile_auth_flow = Some(crate::ui::MobileAuthFlow::DeviceCode);
                                        app.state = crate::ui::AppState::Authenticating;
                                        crate::ui::flows::auth::perform_auth_flow(app, &mut terminal)?;
                                    }
                                    crate::ui::MenuAction::BackToProviders => {
                                        app.state = crate::ui::AppState::ProviderSelect;
                                    }
                                    _ => {}
                                }
                            }
                        } else if app.state == crate::ui::AppState::BrowserSelect {
                            app.confirm_browser();
                            if !app.has_selected_browsers() {
                                continue;
                            }
                            app.advance(); // Move to Authenticating

                            if app.state == crate::ui::AppState::Authenticating {
                                crate::ui::flows::auth::perform_auth_flow(app, &mut terminal)?;
                            }
                        } else if app.state == crate::ui::AppState::PostAuthChoice {
                            let choice = match app.post_auth_selected {
                                0 => crate::ui::PostAuthAction::ListToCsv,
                                1 => crate::ui::PostAuthAction::MountAndBrowse,
                                _ => crate::ui::PostAuthAction::SkipToFileList,
                            };
                            app.post_auth_action = Some(choice);
                            match choice {
                                crate::ui::PostAuthAction::ListToCsv => {
                                    perform_post_auth_list(app, &mut terminal)?;
                                }
                                crate::ui::PostAuthAction::MountAndBrowse => {
                                    perform_post_auth_mount(app, &mut terminal)?;
                                }
                                crate::ui::PostAuthAction::SkipToFileList => {
                                    app.advance(); // PostAuthChoice → FileList
                                }
                            }
                        } else if app.state == crate::ui::AppState::FileList {
                            // Start download if files are selected
                            if !app.files.to_download.is_empty() {
                                app.advance(); // Move to Downloading
                                crate::ui::flows::download::perform_download_flow(app, &mut terminal)?;
                            }
                        } else {
                            app.advance();
                        }
                    }
                    KeyCode::Backspace => {
                        if app.state == crate::ui::AppState::RemoteSelect {
                            app.remote.options.clear();
                            app.remote.selected = 0;
                            app.back();
                        } else if app.state == crate::ui::AppState::FileList {
                            if matches!(
                                app.selected_action,
                                Some(crate::ui::MenuAction::RetrieveList)
                                    | Some(crate::ui::MenuAction::MountProvider)
                            ) {
                                app.state = crate::ui::AppState::ProviderSelect;
                            } else {
                                app.back();
                            }
                        } else {
                            app.back();
                        }
                    }
                    KeyCode::Up => {
                        if app.state == crate::ui::AppState::MainMenu {
                            app.menu_up();
                        } else if app.state == crate::ui::AppState::AdditionalOptions {
                            app.additional_menu_up();
                        } else if app.state == crate::ui::AppState::OneDriveMenu {
                            app.onedrive_menu_up();
                        } else if app.state == crate::ui::AppState::ProviderSelect {
                            app.provider_up();
                        } else if app.state == crate::ui::AppState::RemoteSelect {
                            app.remote_up();
                        } else if app.state == crate::ui::AppState::MobileAuthFlow {
                            app.mobile_flow_up();
                        } else if app.state == crate::ui::AppState::BrowserSelect {
                            app.browser_up();
                        } else if app.state == crate::ui::AppState::PostAuthChoice {
                            if app.post_auth_selected > 0 {
                                app.post_auth_selected -= 1;
                            } else {
                                app.post_auth_selected = 2;
                            }
                        } else if app.state == crate::ui::AppState::FileList {
                            app.file_up();
                        }
                    }
                    KeyCode::Down => {
                        if app.state == crate::ui::AppState::MainMenu {
                            app.menu_down();
                        } else if app.state == crate::ui::AppState::AdditionalOptions {
                            app.additional_menu_down();
                        } else if app.state == crate::ui::AppState::OneDriveMenu {
                            app.onedrive_menu_down();
                        } else if app.state == crate::ui::AppState::ProviderSelect {
                            app.provider_down();
                        } else if app.state == crate::ui::AppState::RemoteSelect {
                            app.remote_down();
                        } else if app.state == crate::ui::AppState::MobileAuthFlow {
                            app.mobile_flow_down();
                        } else if app.state == crate::ui::AppState::BrowserSelect {
                            app.browser_down();
                        } else if app.state == crate::ui::AppState::PostAuthChoice {
                            app.post_auth_selected = (app.post_auth_selected + 1) % 3;
                        } else if app.state == crate::ui::AppState::FileList {
                            app.file_down();
                        }
                    }
                    KeyCode::Char('r') => {
                        if app.state == crate::ui::AppState::ProviderSelect {
                            try_refresh_providers(app);
                        } else if app.state == crate::ui::AppState::Complete
                            && !app.download.failures.is_empty()
                        {
                            app.files.to_download = app.download.failures.clone();
                            app.download.failures.clear();
                            app.download.status = "Retrying failed downloads...".to_string();
                            app.state = crate::ui::AppState::Downloading;
                            crate::ui::flows::download::perform_download_flow(app, &mut terminal)?;
                        }
                    }
                    KeyCode::Char('m') => {
                        if app.state == crate::ui::AppState::FileList {
                            if app.mounted_remote.is_some() {
                                app.log_info("Remote already mounted for GUI selection");
                                continue;
                            }

                            let binary = match crate::embedded::ExtractedBinary::extract() {
                                Ok(binary) => binary,
                                Err(e) => {
                                    app.log_error(format!("Mount failed (extract): {}", e));
                                    continue;
                                }
                            };
                            app.cleanup_track_file(binary.path());
                            if let Some(dir) = binary.temp_dir() {
                                app.cleanup_track_dir(dir);
                            }

                            let config_dir = app
                                .config_dir()
                                .unwrap_or_else(|| std::path::PathBuf::from("."));
                            app.track_env_var("RCLONE_CONFIG", "Set RCLONE_CONFIG for mount");
                            let config = match crate::rclone::RcloneConfig::for_case(&config_dir) {
                                Ok(config) => config,
                                Err(e) => {
                                    app.log_error(format!("Mount failed (config): {}", e));
                                    continue;
                                }
                            };
                            app.cleanup_track_env_value("RCLONE_CONFIG", config.original_env());

                            let remote_name = app
                                .remote.chosen
                                .clone()
                                .or_else(|| app.provider.chosen.as_ref().map(|p| p.short_name().to_string()));
                            let Some(remote_name) = remote_name else {
                                app.log_error("Mount failed: no remote selected");
                                continue;
                            };

                            let mut manager = match crate::rclone::MountManager::new(binary.path()) {
                                Ok(manager) => manager.with_config(config.path()),
                                Err(e) => {
                                    app.log_error(format!("Mount failed: {}", e));
                                    continue;
                                }
                            };

                            // Keep mount points and caches inside the case directory to reduce system footprint.
                            if let Some(ref dirs) = app.forensics.directories {
                                let mount_base = dirs.base.join("mounts");
                                let cache_dir = dirs.base.join("cache").join("rclone");

                                if let Err(e) = std::fs::create_dir_all(&mount_base) {
                                    app.log_error(format!(
                                        "Mount failed (mount dir {:?}): {}",
                                        mount_base, e
                                    ));
                                    continue;
                                }
                                app.track_file(&mount_base, "Created mount base directory inside case");

                                if let Err(e) = std::fs::create_dir_all(&cache_dir) {
                                    app.log_error(format!(
                                        "Mount failed (cache dir {:?}): {}",
                                        cache_dir, e
                                    ));
                                    continue;
                                }
                                app.track_file(&cache_dir, "Created rclone cache directory inside case");

                                manager = manager.with_mount_base(&mount_base).with_cache_dir(&cache_dir);
                            }

                            match manager.mount_and_explore(&remote_name, None) {
                                Ok(mounted) => {
                                    let mount_path = mounted.mount_point().to_path_buf();
                                    app.mounted_remote = Some(mounted);
                                    app.log_info(format!("Mounted remote at {:?}", mount_path));
                                    if let Some(path) = app.selection_file_path() {
                                        app.log_info(format!(
                                            "Create selection file at {:?} (one path per line), then press 'i' to load.",
                                            path
                                        ));
                                    } else {
                                        app.log_info("No selection file path available");
                                    }
                                }
                                Err(e) => {
                                    app.log_error(format!("Mount failed: {}", e));
                                }
                            }
                        }
                    }
                    KeyCode::Char('u') => {
                        if app.state == crate::ui::AppState::FileList {
                            app.unmount_remote();
                            app.log_info("Unmounted remote");
                        }
                    }
                    KeyCode::Char('i') => {
                        if app.state == crate::ui::AppState::FileList {
                            if let Some(path) = app.selection_file_path() {
                                match app.load_selection_from_file(&path) {
                                    Ok(count) => {
                                        app.log_info(format!(
                                            "Loaded {} selected files from {:?}",
                                            count, path
                                        ));
                                    }
                                    Err(e) => {
                                        app.log_error(format!(
                                            "Failed to load selection from {:?}: {}",
                                            path, e
                                        ));
                                    }
                                }
                            } else {
                                app.log_error("Selection file path not available");
                            }
                        }
                    }
                    KeyCode::Char(' ') => {
                        // Space toggles file selection
                        if app.state == crate::ui::AppState::ProviderSelect {
                            app.toggle_provider_selection();
                        } else if app.state == crate::ui::AppState::BrowserSelect {
                            app.toggle_browser_selection();
                        } else if app.state == crate::ui::AppState::FileList {
                            app.toggle_file_download();
                        }
                    }
                    KeyCode::Char('a') => {
                        // 'a' selects all files
                        if app.state == crate::ui::AppState::FileList {
                            app.select_all_files();
                        }
                    }
                    KeyCode::Tab => app.toggle_file_download(),
                    KeyCode::Char(_ch) => {}
                        _ => {}
                    }
                }
                Event::Mouse(mouse) => {
                    let area_rect = ratatui::layout::Rect::new(0, 0, area.width, area.height);
                    handle_mouse_event(app, area_rect, mouse);
                }
                _ => {}
            }
        }

        if app.exit_requested {
            break;
        }
    }

    Ok(())
}

fn should_handle_key(key: &KeyEvent) -> bool {
    key.kind == KeyEventKind::Press
}

fn handle_main_menu_enter(app: &mut App) -> bool {
    if app.menu_selected >= app.menu_items.len() {
        return false;
    }

    let action = app.menu_items[app.menu_selected].action;
    app.selected_action = Some(action);
    app.menu_status.clear();

    match action {
        crate::ui::MenuAction::Exit => {
            app.exit_requested = true;
            true
        }
        crate::ui::MenuAction::AdditionalOptions => {
            app.state = crate::ui::AppState::AdditionalOptions;
            false
        }
        _ => {
            // Initialize case and go directly to provider selection.
            let output_dir = std::env::current_dir()
                .unwrap_or_else(|_| std::path::PathBuf::from("."));
            if let Err(e) = app.init_case(output_dir) {
                app.auth_status = format!("Failed to create case: {}", e);
                app.menu_status = format!("Failed to create case: {}", e);
            } else {
                app.state = crate::ui::AppState::ProviderSelect;
                try_refresh_providers(app);
            }
            false
        }
    }
}

fn resume_remote_flow<B: ratatui::backend::Backend>(
    app: &mut App,
    terminal: &mut Terminal<B>,
) -> Result<()> {
    app.state = crate::ui::AppState::ProviderSelect;
    match app.selected_action {
        Some(crate::ui::MenuAction::RetrieveList) => crate::ui::flows::list::perform_list_flow(app, terminal),
        Some(crate::ui::MenuAction::MountProvider) => crate::ui::flows::mount::perform_mount_flow(app, terminal),
        Some(crate::ui::MenuAction::DownloadFromCsv) => perform_csv_download_flow(app, terminal),
        _ => Ok(()),
    }
}

fn handle_provider_help_key(app: &mut App, key: &KeyEvent) -> bool {
    if app.state != crate::ui::AppState::ProviderSelect {
        return false;
    }

    if app.provider.show_help {
        match key.code {
            KeyCode::Char('q') => false,
            KeyCode::Char('?') | KeyCode::Char('h') | KeyCode::Esc => {
                app.provider.show_help = false;
                true
            }
            _ => true,
        }
    } else {
        match key.code {
            KeyCode::Char('?') | KeyCode::Char('h') => {
                app.provider.show_help = true;
                true
            }
            _ => false,
        }
    }
}

fn handle_mouse_event(app: &mut App, area: ratatui::layout::Rect, mouse: MouseEvent) {
    match mouse.kind {
        MouseEventKind::ScrollUp => match app.state {
            crate::ui::AppState::MainMenu => app.menu_up(),
            crate::ui::AppState::AdditionalOptions => app.additional_menu_up(),
            crate::ui::AppState::OneDriveMenu => app.onedrive_menu_up(),
            crate::ui::AppState::ProviderSelect => app.provider_up(),
            crate::ui::AppState::RemoteSelect => app.remote_up(),
            crate::ui::AppState::MobileAuthFlow => app.mobile_flow_up(),
            crate::ui::AppState::BrowserSelect => app.browser_up(),
            crate::ui::AppState::PostAuthChoice => {
                if app.post_auth_selected > 0 { app.post_auth_selected -= 1; } else { app.post_auth_selected = 2; }
            }
            crate::ui::AppState::FileList => app.file_up(),
            _ => {}
        },
        MouseEventKind::ScrollDown => match app.state {
            crate::ui::AppState::MainMenu => app.menu_down(),
            crate::ui::AppState::AdditionalOptions => app.additional_menu_down(),
            crate::ui::AppState::OneDriveMenu => app.onedrive_menu_down(),
            crate::ui::AppState::ProviderSelect => app.provider_down(),
            crate::ui::AppState::RemoteSelect => app.remote_down(),
            crate::ui::AppState::MobileAuthFlow => app.mobile_flow_down(),
            crate::ui::AppState::BrowserSelect => app.browser_down(),
            crate::ui::AppState::PostAuthChoice => {
                app.post_auth_selected = (app.post_auth_selected + 1) % 3;
            }
            crate::ui::AppState::FileList => app.file_down(),
            _ => {}
        },
        MouseEventKind::Down(MouseButton::Left) => match app.state {
            crate::ui::AppState::MainMenu => {
                let list_area = main_menu_list_area(area);
                if let Some(index) = list_index_from_click(list_area, mouse.row) {
                    if index < app.menu_items.len() {
                        app.menu_selected = index;
                        handle_main_menu_enter(app);
                    }
                }
            }
            crate::ui::AppState::AdditionalOptions => {
                let list_area = main_menu_list_area(area);
                if let Some(index) = list_index_from_click(list_area, mouse.row) {
                    if index < app.additional_menu_items.len() {
                        app.additional_menu_selected = index;
                    }
                }
            }
            crate::ui::AppState::OneDriveMenu => {
                let list_area = main_menu_list_area(area);
                if let Some(index) = list_index_from_click(list_area, mouse.row) {
                    if index < app.onedrive_menu_items.len() {
                        app.onedrive_menu_selected = index;
                    }
                }
            }
            crate::ui::AppState::ProviderSelect => {
                let list_area = provider_list_area(area);
                if let Some(index) = list_index_from_click(list_area, mouse.row) {
                    if index < app.provider.entries.len() {
                        app.provider.selected = index;
                    }
                }
            }
            crate::ui::AppState::RemoteSelect => {
                let list_area = main_menu_list_area(area);
                if let Some(index) = list_index_from_click(list_area, mouse.row) {
                    if index < app.remote.options.len() {
                        app.remote.selected = index;
                    }
                }
            }
            crate::ui::AppState::BrowserSelect => {
                if let Some(index) = list_index_from_click(area, mouse.row) {
                    if index < app.browser.entries.len() + 1 {
                        app.browser.selected = index;
                    }
                }
            }
            crate::ui::AppState::MobileAuthFlow => {
                let list_area = main_menu_list_area(area);
                if let Some(index) = list_index_from_click(list_area, mouse.row) {
                    if index < app.mobile_flow_items.len() {
                        app.mobile_flow_selected = index;
                    }
                }
            }
            crate::ui::AppState::FileList => {
                if let Some(index) = list_index_from_click(area, mouse.row) {
                    if index < app.files.entries.len() {
                        app.files.selected = index;
                    }
                }
            }
            _ => {}
        },
        _ => {}
    }
}

fn provider_list_area(area: ratatui::layout::Rect) -> ratatui::layout::Rect {
    let chunks = ratatui::layout::Layout::default()
        .direction(ratatui::layout::Direction::Vertical)
        .constraints([ratatui::layout::Constraint::Min(3), ratatui::layout::Constraint::Length(4)])
        .split(area);
    let columns = ratatui::layout::Layout::default()
        .direction(ratatui::layout::Direction::Horizontal)
        .constraints([
            ratatui::layout::Constraint::Percentage(65),
            ratatui::layout::Constraint::Percentage(35),
        ])
        .split(chunks[0]);
    columns[0]
}

fn main_menu_list_area(area: ratatui::layout::Rect) -> ratatui::layout::Rect {
    let chunks = ratatui::layout::Layout::default()
        .direction(ratatui::layout::Direction::Vertical)
        .constraints([ratatui::layout::Constraint::Min(3), ratatui::layout::Constraint::Length(4)])
        .split(area);
    chunks[0]
}

fn list_index_from_click(area: ratatui::layout::Rect, row: u16) -> Option<usize> {
    if area.height < 2 {
        return None;
    }
    let content_start = area.y.saturating_add(1);
    let content_end = area.y + area.height - 1;
    if row < content_start || row >= content_end {
        return None;
    }
    Some((row - content_start) as usize)
}

/// Execute the "List files to CSV" post-auth action using the already-authenticated remote.
fn perform_post_auth_list<B: ratatui::backend::Backend>(
    app: &mut App,
    terminal: &mut Terminal<B>,
) -> Result<()> {
    let Some(remote_name) = app.remote.chosen.clone() else {
        app.auth_status = "No remote available. Try authenticating again.".to_string();
        app.advance(); // → FileList (empty)
        return Ok(());
    };
    let provider = app.provider.chosen.clone();

    app.auth_status = "Extracting rclone...".to_string();
    terminal.draw(|f| crate::ui::render::render_state(f, app))?;

    let binary = crate::embedded::ExtractedBinary::extract()?;
    app.cleanup_track_file(binary.path());
    if let Some(dir) = binary.temp_dir() {
        app.cleanup_track_dir(dir);
    }

    let config_dir = app
        .config_dir()
        .unwrap_or_else(|| std::path::PathBuf::from("."));
    let config = crate::rclone::RcloneConfig::for_case(&config_dir)?;
    let runner = crate::rclone::RcloneRunner::new(binary.path()).with_config(config.path());

    let include_hashes = provider
        .as_ref()
        .and_then(|p| p.known)
        .map(|known| !known.hash_types().is_empty())
        .unwrap_or_else(|| {
            if let Some(ref p) = provider {
                matches!(
                    crate::providers::features::provider_supports_hashes(p),
                    Ok(Some(true))
                )
            } else {
                false
            }
        });

    let list_options = if include_hashes {
        crate::files::listing::ListPathOptions::with_hashes()
    } else {
        crate::files::listing::ListPathOptions::without_hashes()
    };

    let target = format!("{}:", remote_name);
    let short = provider
        .as_ref()
        .map(|p| p.short_name().to_string())
        .unwrap_or_else(|| remote_name.clone());

    // Prefer large CSV streaming listing — better for thousands of files.
    let max_in_memory: usize = std::env::var("RCLONE_TRIAGE_LARGE_LISTING_IN_MEMORY")
        .ok()
        .and_then(|v| v.parse().ok())
        .unwrap_or(50_000);

    if let Some(ref dirs) = app.forensics.directories {
        let csv_path = dirs.listings.join(format!("{}_files.csv", short));

        app.auth_status = "Listing files... (0 found)".to_string();
        terminal.draw(|f| crate::ui::render::render_state(f, app))?;

        let listing_result = crate::files::listing::list_path_large_to_csv_with_progress(
            &runner,
            &target,
            list_options,
            &csv_path,
            max_in_memory,
            |count| {
                app.auth_status = format!("Listing files... ({} found)", count);
                let _ = terminal.draw(|f| crate::ui::render::render_state(f, app));
            },
        );

        match listing_result {
            Ok(result) => {
                app.log_info(format!("Exported listing to {:?}", csv_path));
                app.track_file(&csv_path, "Exported file listing CSV");

                app.files.entries_full = result.entries.clone();
                app.files.entries = result.entries.iter().map(|e| e.path.clone()).collect();

                // Also export XLSX
                if let Some(ref dirs) = app.forensics.directories {
                    let xlsx_path = dirs.listings.join(format!("{}_files.xlsx", short));
                    if let Err(e) = crate::files::export::export_listing_xlsx(&result.entries, &xlsx_path) {
                        app.log_error(format!("Excel export failed: {}", e));
                    } else {
                        app.log_info(format!("Exported listing to {:?}", xlsx_path));
                        app.track_file(&xlsx_path, "Exported file listing Excel");
                    }
                }

                let shown = app.files.entries.len();
                if result.truncated {
                    app.auth_status = format!(
                        "Found {} files (showing first {}). CSV: {:?}",
                        result.total_entries, shown, csv_path
                    );
                } else {
                    app.auth_status = format!("Found {} files. CSV: {:?}", result.total_entries, csv_path);
                }
            }
            Err(e) => {
                app.log_error(format!("File listing failed: {}", e));
                app.auth_status = format!("Listing failed: {}", e);
            }
        }
    } else {
        // No case directories — fall back to in-memory listing.
        app.auth_status = "Listing files... (0 found)".to_string();
        terminal.draw(|f| crate::ui::render::render_state(f, app))?;

        let listing_result = crate::files::listing::list_path_with_progress(
            &runner,
            &target,
            list_options,
            |count| {
                app.auth_status = format!("Listing files... ({} found)", count);
                let _ = terminal.draw(|f| crate::ui::render::render_state(f, app));
            },
        );

        match listing_result {
            Ok(entries) => {
                app.files.entries_full = entries.clone();
                app.files.entries = entries.iter().map(|e| e.path.clone()).collect();
                app.auth_status = format!("Found {} files", app.files.entries.len());
            }
            Err(e) => {
                app.log_error(format!("File listing failed: {}", e));
                app.auth_status = format!("Listing failed: {}", e);
            }
        }
    }

    app.advance(); // PostAuthChoice → FileList
    Ok(())
}

/// Execute the "Mount as drive" post-auth action using the already-authenticated remote.
///
/// Runs the file listing FIRST (to avoid API contention with the mount process),
/// then mounts the remote for file explorer access.
fn perform_post_auth_mount<B: ratatui::backend::Backend>(
    app: &mut App,
    terminal: &mut Terminal<B>,
) -> Result<()> {
    let Some(remote_name) = app.remote.chosen.clone() else {
        app.auth_status = "No remote available. Try authenticating again.".to_string();
        app.advance(); // → FileList (empty)
        return Ok(());
    };

    app.auth_status = "Preparing mount...".to_string();
    terminal.draw(|f| crate::ui::render::render_state(f, app))?;

    let binary = crate::embedded::ExtractedBinary::extract()?;
    app.cleanup_track_file(binary.path());
    if let Some(dir) = binary.temp_dir() {
        app.cleanup_track_dir(dir);
    }

    let config_dir = app
        .config_dir()
        .unwrap_or_else(|| std::path::PathBuf::from("."));
    let config = crate::rclone::RcloneConfig::for_case(&config_dir)?;

    // --- Phase 1: Run file listing BEFORE mounting ---
    // This avoids API contention between the mount process and lsjson, which can
    // cause empty results on providers like Google Drive.
    let runner = crate::rclone::RcloneRunner::new(binary.path()).with_config(config.path());
    let provider = app.provider.chosen.clone();
    let include_hashes = provider
        .as_ref()
        .and_then(|p| p.known)
        .map(|known| !known.hash_types().is_empty())
        .unwrap_or(false);
    let list_options = if include_hashes {
        crate::files::listing::ListPathOptions::with_hashes()
    } else {
        crate::files::listing::ListPathOptions::without_hashes()
    };
    let target = format!("{}:", remote_name);
    let short = provider
        .as_ref()
        .map(|p| p.short_name().to_string())
        .unwrap_or_else(|| remote_name.clone());
    let max_in_memory: usize = std::env::var("RCLONE_TRIAGE_LARGE_LISTING_IN_MEMORY")
        .ok()
        .and_then(|v| v.parse().ok())
        .unwrap_or(50_000);

    app.files.entries.clear();
    app.files.entries_full.clear();
    app.files.to_download.clear();
    app.files.selected = 0;

    app.auth_status = "Listing files... (0 found)".to_string();
    terminal.draw(|f| crate::ui::render::render_state(f, app))?;

    if let Some(ref dirs) = app.forensics.directories {
        let csv_path = dirs.listings.join(format!("{}_files.csv", short));
        let listing_result = crate::files::listing::list_path_large_to_csv_with_progress(
            &runner,
            &target,
            list_options,
            &csv_path,
            max_in_memory,
            |count| {
                app.auth_status = format!("Listing files... ({} found)", count);
                let _ = terminal.draw(|f| crate::ui::render::render_state(f, app));
            },
        );
        match listing_result {
            Ok(result) => {
                // If fast-list returned 0 entries, retry without it — some providers
                // (notably Google Drive) may return empty results with --fast-list.
                if result.total_entries == 0 && list_options.fast_list {
                    tracing::warn!("Listing returned 0 entries with --fast-list, retrying without");
                    app.auth_status = "Retrying listing without fast-list...".to_string();
                    let _ = terminal.draw(|f| crate::ui::render::render_state(f, app));

                    let retry_options = list_options.without_fast_list();
                    let retry_result = crate::files::listing::list_path_large_to_csv_with_progress(
                        &runner,
                        &target,
                        retry_options,
                        &csv_path,
                        max_in_memory,
                        |count| {
                            app.auth_status = format!("Listing files... ({} found)", count);
                            let _ = terminal.draw(|f| crate::ui::render::render_state(f, app));
                        },
                    );
                    match retry_result {
                        Ok(retry) => {
                            populate_listing_results(app, &retry, &csv_path, &short);
                        }
                        Err(e) => {
                            app.log_error(format!("File listing retry failed: {}", e));
                            app.auth_status = format!("Listing failed: {}", e);
                        }
                    }
                } else {
                    populate_listing_results(app, &result, &csv_path, &short);
                }
            }
            Err(e) => {
                app.log_error(format!("File listing failed: {}", e));
                app.auth_status = format!("Listing failed: {}", e);
            }
        }
    } else {
        // No case directories — fall back to in-memory listing.
        let listing_result = crate::files::listing::list_path_with_progress(
            &runner,
            &target,
            list_options,
            |count| {
                app.auth_status = format!("Listing files... ({} found)", count);
                let _ = terminal.draw(|f| crate::ui::render::render_state(f, app));
            },
        );
        match listing_result {
            Ok(entries) => {
                if entries.is_empty() && list_options.fast_list {
                    tracing::warn!("Listing returned 0 entries with --fast-list, retrying without");
                    app.auth_status = "Retrying listing without fast-list...".to_string();
                    let _ = terminal.draw(|f| crate::ui::render::render_state(f, app));

                    let retry_options = list_options.without_fast_list();
                    match crate::files::listing::list_path_with_progress(
                        &runner,
                        &target,
                        retry_options,
                        |count| {
                            app.auth_status = format!("Listing files... ({} found)", count);
                            let _ = terminal.draw(|f| crate::ui::render::render_state(f, app));
                        },
                    ) {
                        Ok(retry_entries) => {
                            app.files.entries_full = retry_entries.clone();
                            app.files.entries = retry_entries.iter().map(|e| e.path.clone()).collect();
                            app.auth_status = format!("Found {} files", app.files.entries.len());
                        }
                        Err(e) => {
                            app.log_error(format!("File listing retry failed: {}", e));
                            app.auth_status = format!("Listing failed: {}", e);
                        }
                    }
                } else {
                    app.files.entries_full = entries.clone();
                    app.files.entries = entries.iter().map(|e| e.path.clone()).collect();
                    app.auth_status = format!("Found {} files", app.files.entries.len());
                }
            }
            Err(e) => {
                app.log_error(format!("File listing failed: {}", e));
                app.auth_status = format!("Listing failed: {}", e);
            }
        }
    }

    // --- Phase 2: Mount the remote for file explorer access ---
    let mut manager = match crate::rclone::MountManager::new(binary.path()) {
        Ok(manager) => manager.with_config(config.path()),
        Err(e) => {
            app.auth_status = format!("Found {} files. Mount failed: {}", app.files.entries.len(), e);
            app.log_error(format!("Mount failed: {}", e));
            app.advance(); // → FileList (listing results are still available)
            return Ok(());
        }
    };

    // Check FUSE/WinFSP availability and auto-install if missing
    match manager.check_fuse_available() {
        Ok(true) => {}
        Ok(false) => {
            app.auth_status = format!(
                "Found {} files. Mounting...",
                app.files.entries.len()
            );
            terminal.draw(|f| crate::ui::render::render_state(f, app))?;
            app.log_info("FUSE/WinFSP not detected — attempting auto-install");

            match manager.install_fuse() {
                Ok(true) => {
                    app.log_info("FUSE/WinFSP installed successfully");
                }
                Ok(false) | Err(_) => {
                    app.log_error("FUSE/WinFSP auto-install failed");
                    app.auth_status = format!(
                        "Found {} files. Mount skipped (FUSE/WinFSP not available).",
                        app.files.entries.len()
                    );
                    app.advance(); // → FileList (listing results are still available)
                    return Ok(());
                }
            }
        }
        Err(e) => {
            app.log_info(format!("FUSE check failed: {}", e));
        }
    }

    // Keep mount inside case directory
    if let Some(ref dirs) = app.forensics.directories {
        let mount_base = dirs.base.join("mounts");
        let cache_dir = dirs.base.join("cache").join("rclone");
        let _ = std::fs::create_dir_all(&mount_base);
        let _ = std::fs::create_dir_all(&cache_dir);
        app.track_file(&mount_base, "Created mount base directory inside case");
        app.track_file(&cache_dir, "Created rclone cache directory inside case");
        manager = manager.with_mount_base(&mount_base).with_cache_dir(&cache_dir);
    }

    app.auth_status = format!(
        "Found {} files. Mounting {}...",
        app.files.entries.len(),
        remote_name
    );
    terminal.draw(|f| crate::ui::render::render_state(f, app))?;

    match manager.mount_and_explore(&remote_name, None) {
        Ok(mounted) => {
            let mount_path = mounted.mount_point().to_path_buf();
            app.mounted_remote = Some(mounted);
            app.log_info(format!("Mounted {} at {:?}", remote_name, mount_path));
            if app.files.entries.is_empty() {
                app.auth_status = format!(
                    "Mounted at {:?}. Listing returned 0 files — check logs.",
                    mount_path
                );
            } else {
                app.auth_status = format!(
                    "Mounted at {:?}. {} files listed.",
                    mount_path,
                    app.files.entries.len()
                );
            }
        }
        Err(e) => {
            app.log_error(format!("Mount failed: {}", e));
            app.auth_status = format!(
                "Found {} files. Mount failed: {}",
                app.files.entries.len(),
                e
            );
            // Still advance — listing results are available for download.
        }
    }

    app.advance(); // PostAuthChoice → FileList
    Ok(())
}

/// Populate app state from a large listing result, including CSV/XLSX export tracking.
fn populate_listing_results(
    app: &mut App,
    result: &crate::files::listing::LargeListingResult,
    csv_path: &std::path::Path,
    short: &str,
) {
    app.log_info(format!("Exported listing to {:?}", csv_path));
    app.track_file(csv_path, "Exported file listing CSV");
    app.files.entries_full = result.entries.clone();
    app.files.entries = result.entries.iter().map(|e| e.path.clone()).collect();

    if let Some(ref dirs) = app.forensics.directories {
        let xlsx_path = dirs.listings.join(format!("{}_files.xlsx", short));
        if let Err(e) = crate::files::export::export_listing_xlsx(&result.entries, &xlsx_path) {
            app.log_error(format!("Excel export failed: {}", e));
        } else {
            app.log_info(format!("Exported listing to {:?}", xlsx_path));
            app.track_file(&xlsx_path, "Exported file listing Excel");
        }
    }

    let shown = app.files.entries.len();
    if result.truncated {
        app.auth_status = format!(
            "Found {} files (showing first {}). CSV: {:?}",
            result.total_entries, shown, csv_path
        );
    } else {
        app.auth_status = format!("Found {} files. CSV: {:?}", result.total_entries, csv_path);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ui::screens::welcome::WelcomeScreen;
    use crossterm::event::{KeyModifiers, MouseButton, MouseEvent, MouseEventKind};
    use std::io::IsTerminal;

    /// Run a basic one-frame TUI to validate rendering
    fn run_once() -> Result<()> {
        enable_raw_mode()?;
        let mut out = stdout();
        execute!(out, EnterAlternateScreen, EnableMouseCapture)?;

        let backend = CrosstermBackend::new(out);
        let mut terminal = Terminal::new(backend)?;

        terminal.draw(|f| {
            let size = f.area();
            let screen = WelcomeScreen;
            f.render_widget(screen, size);
        })?;

        execute!(terminal.backend_mut(), LeaveAlternateScreen)?;
        disable_raw_mode()?;

        Ok(())
    }

    #[test]
    fn test_run_once() {
        // We only test that the function builds and can be called without panicking.
        // In CI/headless environments, this may fail if no TTY is available.
        if !std::io::stdout().is_terminal() {
            return;
        }
        let _ = std::panic::catch_unwind(|| {
            let _ = run_once();
        });
    }

    #[test]
    fn test_refresh_providers_from_json_replaces_defaults() {
        let mut app = App::new();
        let original_len = app.provider.entries.len();

        let json = r#"
        [
          {"Name":"Amazon S3","Prefix":"s3","Options":[{"Name":"access_key_id"}]},
          {"Name":"Azure Blob","Prefix":"azureblob","Options":[{"Name":"client_id"}]},
          {"Name":"Backblaze B2","Prefix":"b2","Options":[{"Name":"application_key"}]},
          {"Name":"Google Drive","Prefix":"drive","Options":[{"Name":"client_secret"}]}
        ]
        "#;

        let discovery = crate::providers::discovery::providers_from_rclone_json(json).unwrap();
        apply_discovered_providers(&mut app, discovery);

        assert_ne!(app.provider.entries.len(), original_len);
        assert!(app.provider.entries.iter().any(|p| p.id == "s3"));
        assert!(app.provider.entries.iter().any(|p| p.id == "azureblob"));
        let b2 = app.provider.entries.iter().find(|p| p.id == "b2").unwrap();
        assert_eq!(
            b2.auth_kind(),
            crate::providers::ProviderAuthKind::KeyBased
        );
        assert!(app.provider.entries.iter().any(|p| p.id == "drive"));
    }

    #[test]
    fn test_should_handle_key_ignores_repeats() {
        let press = KeyEvent::new(KeyCode::Up, event::KeyModifiers::NONE);
        assert!(should_handle_key(&press));

        let repeat = KeyEvent {
            code: KeyCode::Down,
            modifiers: event::KeyModifiers::NONE,
            kind: KeyEventKind::Repeat,
            state: event::KeyEventState::NONE,
        };
        assert!(!should_handle_key(&repeat));
    }

    #[test]
    fn test_main_menu_click_advances() {
        let mut app = App::new();
        let area = ratatui::layout::Rect::new(0, 0, 100, 20);
        let list_area = main_menu_list_area(area);
        let click_row = list_area.y + 1;
        let click = MouseEvent {
            kind: MouseEventKind::Down(MouseButton::Left),
            column: list_area.x + 1,
            row: click_row,
            modifiers: KeyModifiers::NONE,
        };

        handle_mouse_event(&mut app, area, click);

        assert_eq!(app.state, crate::ui::AppState::ProviderSelect);
        assert_eq!(app.selected_action, Some(crate::ui::MenuAction::Authenticate));
    }

    #[test]
    fn test_main_menu_click_exit_sets_flag() {
        let mut app = App::new();
        let area = ratatui::layout::Rect::new(0, 0, 100, 20);
        let list_area = main_menu_list_area(area);
        let exit_index = app.menu_items.len() - 1;
        let click_row = list_area.y + 1 + exit_index as u16;
        let click = MouseEvent {
            kind: MouseEventKind::Down(MouseButton::Left),
            column: list_area.x + 1,
            row: click_row,
            modifiers: KeyModifiers::NONE,
        };

        handle_mouse_event(&mut app, area, click);

        assert!(app.exit_requested);
        assert_eq!(app.state, crate::ui::AppState::MainMenu);
        assert_eq!(app.selected_action, Some(crate::ui::MenuAction::Exit));
    }

    #[test]
    fn test_provider_list_area_respects_split() {
        let area = ratatui::layout::Rect::new(0, 0, 100, 20);
        let list_area = provider_list_area(area);
        assert_eq!(list_area.width, 65);
    }

    #[test]
    fn test_provider_help_toggle_consumes_keys() {
        let mut app = App::new();
        app.state = crate::ui::AppState::ProviderSelect;

        let open = KeyEvent::new(KeyCode::Char('?'), KeyModifiers::NONE);
        assert!(handle_provider_help_key(&mut app, &open));
        assert!(app.provider.show_help);

        let up = KeyEvent::new(KeyCode::Up, KeyModifiers::NONE);
        assert!(handle_provider_help_key(&mut app, &up));
        assert!(app.provider.show_help);

        let esc = KeyEvent::new(KeyCode::Esc, KeyModifiers::NONE);
        assert!(handle_provider_help_key(&mut app, &esc));
        assert!(!app.provider.show_help);
    }

    #[test]
    fn test_provider_help_does_not_consume_quit() {
        let mut app = App::new();
        app.state = crate::ui::AppState::ProviderSelect;
        app.provider.show_help = true;

        let quit = KeyEvent::new(KeyCode::Char('q'), KeyModifiers::NONE);
        assert!(!handle_provider_help_key(&mut app, &quit));
        assert!(app.provider.show_help);
    }

    #[test]
    fn test_main_menu_enter_additional_options() {
        let mut app = App::new();
        let index = app
            .menu_items
            .iter()
            .position(|item| item.action == crate::ui::MenuAction::AdditionalOptions)
            .unwrap();
        app.menu_selected = index;

        let exited = handle_main_menu_enter(&mut app);

        assert!(!exited);
        assert_eq!(app.state, crate::ui::AppState::AdditionalOptions);
        assert_eq!(
            app.selected_action,
            Some(crate::ui::MenuAction::AdditionalOptions)
        );
    }

    #[test]
    fn test_main_menu_enter_download_sets_status() {
        let mut app = App::new();
        let index = app
            .menu_items
            .iter()
            .position(|item| item.action == crate::ui::MenuAction::DownloadFromCsv)
            .unwrap();
        app.menu_selected = index;

        let exited = handle_main_menu_enter(&mut app);

        assert!(!exited);
        assert_eq!(app.state, crate::ui::AppState::ProviderSelect);
        assert_eq!(
            app.selected_action,
            Some(crate::ui::MenuAction::DownloadFromCsv)
        );
        assert!(app.menu_status.is_empty());
    }

    #[test]
    fn test_web_gui_field_default_none() {
        let app = App::new();
        assert!(app.web_gui_process.is_none());
    }

    #[test]
    fn test_normalize_queue_path_strips_remote_prefix() {
        assert_eq!(normalize_queue_path("drive:Documents/file.txt", "drive"), "Documents/file.txt");
        assert_eq!(normalize_queue_path("drive:Documents/file.txt", "drive:"), "Documents/file.txt");
        assert_eq!(normalize_queue_path("/Documents/file.txt", "drive"), "Documents/file.txt");
        assert_eq!(normalize_queue_path("Documents/file.txt", "drive"), "Documents/file.txt");
        assert_eq!(normalize_queue_path("  drive:file.txt  ", "drive"), "file.txt");
    }

    #[test]
    fn test_normalize_queue_path_empty() {
        assert_eq!(normalize_queue_path("", "drive"), "");
        assert_eq!(normalize_queue_path("   ", "drive"), "");
    }

    #[test]
    fn test_score_queue_name_ranking() {
        // "todownload" keyword should rank highest
        assert!(score_queue_name("todownload.xlsx") > score_queue_name("queue.csv"));
        assert!(score_queue_name("queue.xlsx") > score_queue_name("selection.csv"));
        assert!(score_queue_name("queue.xlsx") > score_queue_name("queue.csv"));
        // .xlsx gets +1 bonus
        assert!(score_queue_name("files.xlsx") > score_queue_name("files.csv"));
    }

    #[test]
    fn test_additional_menu_has_web_gui() {
        let app = App::new();
        let has_web_gui = app
            .additional_menu_items
            .iter()
            .any(|item| item.action == crate::ui::MenuAction::StartWebGui);
        assert!(has_web_gui, "Additional Options menu should include Start Web GUI");
    }
}
