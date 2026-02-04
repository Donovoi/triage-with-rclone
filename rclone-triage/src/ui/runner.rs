//! Basic TUI runner
//!
//! Sets up terminal backend and renders a single frame.

use anyhow::Result;
use crossterm::event::{
    self, DisableMouseCapture, EnableMouseCapture, Event, KeyCode, KeyEvent, KeyEventKind,
    MouseButton, MouseEvent, MouseEventKind,
};
use crossterm::execute;
use crossterm::terminal::{
    disable_raw_mode, enable_raw_mode, EnterAlternateScreen, LeaveAlternateScreen,
};
use ratatui::backend::CrosstermBackend;
use ratatui::Terminal;
use chrono::Local;
use std::io::stdout;
use std::time::{Duration, Instant};

use crate::ui::screens::welcome::WelcomeScreen;
use crate::ui::{render::render_state, App};

fn apply_discovered_providers(app: &mut App, providers: Vec<crate::providers::ProviderEntry>) {
    if !providers.is_empty() {
        app.providers = providers;
        if app.provider_selected >= app.providers.len() {
            app.provider_selected = 0;
        }
        app.provider_status = format!("Loaded {} providers from rclone.", app.providers.len());
        record_provider_refresh(app, None);
    } else {
        app.provider_status = "Provider discovery returned empty list; using defaults.".to_string();
        app.log_info("Provider discovery returned empty list; using defaults");
        record_provider_refresh(
            app,
            Some("Provider discovery returned empty list.".to_string()),
        );
    }
}

fn record_provider_refresh(app: &mut App, error: Option<String>) {
    app.provider_last_updated = Some(Local::now());
    app.provider_last_error = error;
}

fn refresh_providers_from_json(app: &mut App, json: &str) -> Result<()> {
    let providers = crate::providers::discovery::providers_from_rclone_json(json)?;
    apply_discovered_providers(app, providers);
    Ok(())
}

fn try_refresh_providers(app: &mut App) {
    let allow = std::env::var("RCLONE_TRIAGE_DYNAMIC_PROVIDERS")
        .map(|v| v != "0")
        .unwrap_or(true);

    if !allow {
        app.provider_status = format!(
            "Provider refresh disabled by RCLONE_TRIAGE_DYNAMIC_PROVIDERS=0. Using built-in providers ({}).",
            app.providers.len()
        );
        record_provider_refresh(
            app,
            Some("Provider refresh disabled by RCLONE_TRIAGE_DYNAMIC_PROVIDERS=0.".to_string()),
        );
        return;
    }

    app.provider_status = "Refreshing providers...".to_string();

    let binary = match crate::embedded::ExtractedBinary::extract() {
        Ok(binary) => binary,
        Err(e) => {
            let message = format!("Provider discovery failed (extract): {}", e);
            app.provider_status = format!("Provider discovery failed: {}. Using built-in list.", e);
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
    let output = match runner.run(&["config", "providers", "--json"]) {
        Ok(output) => output,
        Err(e) => {
            let message = format!("Provider discovery failed: {}", e);
            app.provider_status = format!("Provider discovery failed: {}. Using built-in list.", e);
            app.log_error(message.clone());
            record_provider_refresh(app, Some(message));
            return;
        }
    };

    if !output.success() {
        let stderr = output.stderr_string();
        app.provider_status =
            format!("Provider discovery failed: {}. Using built-in list.", stderr);
        app.log_error(format!("Provider discovery failed: {}", stderr));
        record_provider_refresh(
            app,
            Some(format!("Provider discovery failed: {}", stderr)),
        );
        return;
    }

    if let Err(e) = refresh_providers_from_json(app, &output.stdout_string()) {
        let message = format!("Provider discovery failed: {}", e);
        app.provider_status = format!("Provider discovery failed: {}. Using built-in list.", e);
        app.log_error(message.clone());
        record_provider_refresh(app, Some(message));
    } else {
        record_provider_refresh(app, None);
    }
}

/// Perform the authentication flow (extract binary, create config, auth, list files)
fn perform_auth_flow<B: ratatui::backend::Backend>(
    app: &mut App,
    terminal: &mut Terminal<B>,
) -> Result<()> {
    // Update status and redraw
    app.auth_status = "Extracting rclone...".to_string();
    terminal.draw(|f| render_state(f, app))?;

    let binary = crate::embedded::ExtractedBinary::extract()?;

    // Track the extracted binary
    app.track_file(binary.path(), "Extracted rclone binary to temp directory");
    app.cleanup_track_file(binary.path());
    if let Some(dir) = binary.temp_dir() {
        app.cleanup_track_dir(dir);
    }

    app.auth_status = "Creating config...".to_string();
    terminal.draw(|f| render_state(f, app))?;

    // Use case config directory if available, otherwise current dir
    let config_dir = app
        .config_dir()
        .unwrap_or_else(|| std::path::PathBuf::from("."));
    // Track env var change before config sets it
    app.track_env_var("RCLONE_CONFIG", "Set RCLONE_CONFIG for case config");
    let config = crate::rclone::RcloneConfig::for_case(&config_dir)?;

    // Track config file creation
    app.track_file(config.path(), "Created rclone config file");
    app.cleanup_track_env_value("RCLONE_CONFIG", config.original_env());

    let runner = crate::rclone::RcloneRunner::new(binary.path()).with_config(config.path());

    if let Some(provider) = app.chosen_provider.clone() {
        struct AuthOutcome {
            remote_name: String,
            user_info: Option<String>,
            was_silent: bool,
        }

        // If user selected a browser, use it; otherwise use smart auth (SSO + interactive)
        let auth_result: Result<AuthOutcome> = if let Some(known) = provider.known {
            if let Some(ref browser) = app.chosen_browser {
                app.auth_status = format!(
                    "Authenticating {} via {}...",
                    provider.display_name(),
                    browser.display_name()
                );
                terminal.draw(|f| render_state(f, app))?;

                crate::providers::auth::authenticate_with_browser_choice(
                    known, browser, &runner, &config,
                )
                .map(|result| AuthOutcome {
                    remote_name: result.remote_name,
                    user_info: result.user_info,
                    was_silent: result.was_silent,
                })
            } else {
                // Detect SSO sessions first
                let sso_status = crate::providers::auth::detect_sso_sessions(known);
                if sso_status.has_sessions {
                    app.auth_status = format!(
                        "Found existing {} sessions - attempting SSO...",
                        provider.display_name()
                    );
                    app.log_info(format!(
                        "Found {} browser(s) with {} sessions - attempting SSO auth",
                        sso_status.browsers_with_sessions.len(),
                        provider.display_name()
                    ));
                } else {
                    app.auth_status = format!("Authenticating {}...", provider.display_name());
                    app.log_info(format!(
                        "No existing sessions for {} - using interactive auth",
                        provider.display_name()
                    ));
                }
                terminal.draw(|f| render_state(f, app))?;

                crate::providers::auth::smart_authenticate(
                    known,
                    &runner,
                    &config,
                    provider.short_name(),
                )
                .map(|result| AuthOutcome {
                    remote_name: result.remote_name,
                    user_info: result.user_info,
                    was_silent: result.was_silent,
                })
            }
        } else {
            app.auth_status = format!("Authenticating {}...", provider.display_name());
            app.log_info(format!(
                "Using generic rclone auth for {}",
                provider.display_name()
            ));
            terminal.draw(|f| render_state(f, app))?;

            let remote_name = provider.short_name();
            let args = ["config", "create", remote_name, provider.short_name()];
            let output = runner.run(&args)?;
            if !output.success() {
                anyhow::bail!(
                    "Failed to authenticate with {}: {}",
                    provider.display_name(),
                    output.stderr_string()
                );
            }

            if !config.has_remote(remote_name)? {
                anyhow::bail!("Remote {} was not created", remote_name);
            }

            Ok(AuthOutcome {
                remote_name: remote_name.to_string(),
                user_info: None,
                was_silent: false,
            })
        };
        terminal.draw(|f| render_state(f, app))?;

        match auth_result {
            Ok(result) => {
                let auth_type = if result.was_silent {
                    "SSO"
                } else {
                    "interactive"
                };
                app.log_info(format!(
                    "Authentication successful for {} ({})",
                    provider.display_name(),
                    auth_type
                ));

                // Track authenticated provider in case
                if let Some(ref mut case) = app.case {
                    case.add_provider(crate::case::AuthenticatedProvider {
                        provider_id: provider.id.clone(),
                        provider_name: provider.display_name().to_string(),
                        remote_name: result.remote_name.clone(),
                        user_info: result.user_info.clone(),
                    });
                }

                // Persist remote name for later listing/download
                app.chosen_remote = Some(result.remote_name.clone());

                app.auth_status = "Testing connectivity...".to_string();
                terminal.draw(|f| render_state(f, app))?;

                let connectivity =
                    crate::rclone::test_connectivity(&runner, &result.remote_name)?;
                if connectivity.ok {
                    app.log_info(format!(
                        "Connectivity OK ({} ms)",
                        connectivity.duration.as_millis()
                    ));
                } else {
                    app.log_error(format!(
                        "Connectivity failed: {}",
                        connectivity.error.unwrap_or_else(|| "Unknown error".to_string())
                    ));
                }

                app.auth_status = "Listing files...".to_string();
                terminal.draw(|f| render_state(f, app))?;

                let listing_result = crate::files::listing::list_path_with_progress(
                    &runner,
                    &format!("{}:", result.remote_name),
                    |count| {
                        app.auth_status = format!("Listing files... ({} found)", count);
                        let _ = terminal.draw(|f| render_state(f, app));
                    },
                );

                match listing_result {
                    Ok(entries) => {
                        // Export file listing to CSV
                        if let Some(ref dirs) = app.directories {
                            let csv_path = dirs
                                .listings
                                .join(format!("{}_files.csv", provider.short_name()));
                            if let Err(e) =
                                crate::files::export::export_listing(&entries, &csv_path)
                            {
                                app.log_error(format!("CSV export failed: {}", e));
                            } else {
                                app.log_info(format!("Exported listing to {:?}", csv_path));
                                app.track_file(&csv_path, "Exported file listing CSV");
                            }

                            let xlsx_path = dirs
                                .listings
                                .join(format!("{}_files.xlsx", provider.short_name()));
                            if let Err(e) =
                                crate::files::export::export_listing_xlsx(&entries, &xlsx_path)
                            {
                                app.log_error(format!("Excel export failed: {}", e));
                            } else {
                                app.log_info(format!("Exported listing to {:?}", xlsx_path));
                                app.track_file(&xlsx_path, "Exported file listing Excel");
                            }
                        }

                        // Store full entries for hash verification during download
                        app.file_entries_full = entries.clone();
                        app.file_entries = entries.iter().map(|e| e.path.clone()).collect();
                        app.log_info(format!(
                            "Listed {} files from {}",
                            app.file_entries.len(),
                            provider.display_name()
                        ));
                        app.auth_status = format!("Found {} files", app.file_entries.len());
                        app.advance(); // Move to FileList
                    }
                    Err(e) => {
                        app.log_error(format!("File listing failed: {}", e));
                        app.auth_status = format!("Listing failed: {}", e);
                    }
                }
            }
            Err(e) => {
                app.log_error(format!(
                    "Authentication failed for {}: {}",
                    provider.display_name(),
                    e
                ));
                app.auth_status = format!("Auth failed: {}", e);
            }
        }
    } else {
        app.auth_status = "No provider selected".to_string();
    }

    Ok(())
}

/// Perform the download flow
fn perform_download_flow<B: ratatui::backend::Backend>(
    app: &mut App,
    terminal: &mut Terminal<B>,
) -> Result<()> {
    use crate::files::download::{DownloadPhase, DownloadQueue, DownloadRequest};

    app.unmount_remote();

    let total_files = app.files_to_download.len();
    app.download_status = format!("Downloading {} files...", total_files);
    app.download_progress = (0, total_files);
    app.download_current_bytes = None;
    app.download_done_bytes = 0;
    let total_bytes: u64 = app
        .files_to_download
        .iter()
        .filter_map(|file| app.get_file_entry(file).map(|e| e.size))
        .sum();
    app.download_total_bytes = if total_bytes > 0 {
        Some(total_bytes)
    } else {
        None
    };
    terminal.draw(|f| render_state(f, app))?;

    let binary = crate::embedded::ExtractedBinary::extract()?;
    app.cleanup_track_file(binary.path());
    if let Some(dir) = binary.temp_dir() {
        app.cleanup_track_dir(dir);
    }

    // Use case config directory if available
    let config_dir = app
        .config_dir()
        .unwrap_or_else(|| std::path::PathBuf::from("."));
    // Track env var change before config sets it
    app.track_env_var("RCLONE_CONFIG", "Set RCLONE_CONFIG for case config");
    let config = crate::rclone::RcloneConfig::for_case(&config_dir)?;
    app.cleanup_track_env_value("RCLONE_CONFIG", config.original_env());
    let runner = crate::rclone::RcloneRunner::new(binary.path()).with_config(config.path());

    if let Some(provider) = app.chosen_provider.clone() {
        let remote_name = app
            .chosen_remote
            .as_deref()
            .unwrap_or(provider.short_name());

        // Use case downloads directory if available
        let dest_dir = app
            .downloads_dir()
            .unwrap_or_else(|| std::path::PathBuf::from("./downloads"));
        std::fs::create_dir_all(&dest_dir)?;

        let total = app.files_to_download.len();
        app.log_info(format!(
            "Starting download of {} files to {:?}",
            total, dest_dir
        ));

        // Build download queue with hash verification
        let mut queue = DownloadQueue::new();
        queue.set_verify_hashes(true);

        for file in &app.files_to_download {
            let source = format!("{}:{}", remote_name, file);
            let dest = dest_dir.join(file);

            // Ensure parent directory exists
            if let Some(parent) = dest.parent() {
                std::fs::create_dir_all(parent)?;
            }

            // Get expected hash from file listing (if available)
            let (expected_hash, hash_type, expected_size) = app
                .get_file_entry(file)
                .map(|e| (e.hash.clone(), e.hash_type.clone(), Some(e.size)))
                .unwrap_or((None, None, None));

            let request = DownloadRequest::new_copyto(&source, dest.to_string_lossy())
                .with_hash(expected_hash, hash_type)
                .with_size(expected_size);
            queue.add(request);
        }

        // Execute downloads with progress callback
        let files_clone = app.files_to_download.clone();
        let mut completed_bytes: u64 = 0;
        let results = queue.download_all_with_progress(&runner, |progress| {
            match progress.phase {
                DownloadPhase::Starting | DownloadPhase::InProgress | DownloadPhase::Failed => {
                    app.download_progress = (progress.current, progress.total);
                }
                DownloadPhase::Completed => {
                    app.download_progress = (progress.current + 1, progress.total);
                }
            }

            match progress.phase {
                DownloadPhase::InProgress => {
                    if let (Some(done), Some(total)) = (progress.bytes_done, progress.bytes_total) {
                        app.download_current_bytes = Some((done, total));
                        if let Some(overall_total) = app.download_total_bytes {
                            let done_total = completed_bytes.saturating_add(done);
                            app.download_done_bytes = done_total.min(overall_total);
                        }
                    }
                }
                DownloadPhase::Completed => {
                    if let Some(total) = progress.bytes_total.or(progress.bytes_done) {
                        completed_bytes = completed_bytes.saturating_add(total);
                        if let Some(overall_total) = app.download_total_bytes {
                            app.download_done_bytes = completed_bytes.min(overall_total);
                        } else {
                            app.download_done_bytes = completed_bytes;
                        }
                    }
                    app.download_current_bytes = progress.bytes_total.map(|t| (t, t));
                }
                DownloadPhase::Starting | DownloadPhase::Failed => {
                    app.download_current_bytes = None;
                }
            }

            app.download_status = progress.status.clone();
            let _ = terminal.draw(|f| render_state(f, app));
        });

        // Process results
        let mut success_count = 0;
        let mut hash_verified_count = 0;
        let mut hash_mismatch_count = 0;

        for (i, result) in results.iter().enumerate() {
            let file = &files_clone[i];
            app.download_progress = (i + 1, total);
            app.download_status = format!("Processing {}/{}: {}", i + 1, total, file);

            if result.success {
                success_count += 1;
                let size = result.size.unwrap_or(0);

                // Log hash verification status
                match result.hash_verified {
                    Some(true) => {
                        hash_verified_count += 1;
                        app.log_info(format!(
                            "Downloaded: {} ({} bytes) - hash verified ✓",
                            file, size
                        ));
                    }
                    Some(false) => {
                        hash_mismatch_count += 1;
                        app.log_error(format!(
                            "Downloaded: {} ({} bytes) - HASH MISMATCH! Expected: {:?}, Got: {:?}",
                            file,
                            size,
                            app.get_file_entry(file).and_then(|e| e.hash.clone()),
                            result.hash
                        ));
                    }
                    None => {
                        app.log_info(format!(
                            "Downloaded: {} ({} bytes) - no hash available",
                            file, size
                        ));
                    }
                }

                // Track downloaded file
                let dest = dest_dir.join(file);
                app.track_file(&dest, format!("Downloaded file: {}", file));

                // Track downloaded file in case
                if let Some(ref mut case) = app.case {
                    case.add_download(crate::case::DownloadedFile {
                        path: file.clone(),
                        size,
                        hash: result.hash.clone(),
                        hash_type: result.hash_type.clone(),
                    });
                }
            } else {
                let err_msg = result.error.as_deref().unwrap_or("Unknown error");
                app.log_error(format!("Download failed for {}: {}", file, err_msg));
            }
        }

        // Finalize the case
        if let Some(ref mut case) = app.case {
            case.finalize();
        }

        // Summary
        app.log_info(format!(
            "Download complete: {}/{} files successful",
            success_count, total
        ));
        if hash_verified_count > 0 {
            app.log_info(format!("Hash verified: {} files", hash_verified_count));
        }
        if hash_mismatch_count > 0 {
            app.log_error(format!(
                "Hash mismatch detected: {} files (possible tampering!)",
                hash_mismatch_count
            ));
        }

        app.download_status = format!(
            "Downloaded {}/{} files ({} verified)",
            success_count, total, hash_verified_count
        );

        // Generate and write the forensic report
        if let (Some(ref case), Some(ref dirs)) = (&app.case, &app.directories) {
            let log_hash = app.logger.as_ref().map(|l| l.final_hash());

            // Capture final state and compute diff
            let state_diff = app.capture_final_state();

            // Get change tracker report as string
            let change_report = app
                .change_tracker
                .lock()
                .ok()
                .map(|tracker| tracker.generate_report());

            // Attempt cleanup and capture any unrevertable changes
            let cleanup_report = app.cleanup.as_ref().and_then(|cleanup| {
                if let Ok(mut cleanup) = cleanup.lock() {
                    let _ = cleanup.execute();
                    cleanup.cleanup_report()
                } else {
                    None
                }
            });

            let report_content = crate::case::report::generate_report(
                case,
                state_diff.as_ref(),
                change_report.as_deref(),
                cleanup_report.as_deref(),
                log_hash.as_deref(),
            );

            if let Err(e) = crate::case::report::write_report(&dirs.report, &report_content) {
                app.log_error(format!("Failed to write report: {}", e));
            } else {
                app.log_info(format!("Report written to {:?}", dirs.report));
            }
        }

        // Generate report lines for TUI display
        let dest_display = app
            .downloads_dir()
            .map(|p| p.display().to_string())
            .unwrap_or_else(|| "./downloads/".to_string());

        app.report_lines = vec!["=== rclone-triage Report ===".to_string(), String::new()];

        // Add case metadata if available
        if let Some(ref case) = app.case {
            app.report_lines
                .push(format!("Session: {}", case.session_id()));
            app.report_lines.push(format!(
                "Started: {}",
                case.start_time.format("%Y-%m-%d %H:%M:%S UTC")
            ));
            if let Some(end) = case.end_time {
                app.report_lines
                    .push(format!("Ended: {}", end.format("%Y-%m-%d %H:%M:%S UTC")));
            }
            app.report_lines.push(String::new());
        }

        app.report_lines
            .push(format!("Provider: {}", provider.display_name()));
        app.report_lines
            .push(format!("Files downloaded: {}", total));
        app.report_lines
            .push(format!("Destination: {}", dest_display));
        app.report_lines.push(String::new());
        app.report_lines.push("Downloaded files:".to_string());

        // Use case downloaded_files if available for sizes
        if let Some(ref case) = app.case {
            for file in &case.downloaded_files {
                app.report_lines
                    .push(format!("  - {} ({} bytes)", file.path, file.size));
            }
        } else {
            for file in &app.files_to_download {
                app.report_lines.push(format!("  - {}", file));
            }
        }

        app.report_lines.push(String::new());
        app.report_lines.push("Press 'q' to exit.".to_string());

        app.advance(); // Move to Complete
    }

    Ok(())
}

/// Run a basic one-frame TUI to validate rendering
#[allow(dead_code)]
pub fn run_once() -> Result<()> {
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

/// Run a basic TUI loop with simple key handling
///
/// Controls:
/// - Enter: next state
/// - Backspace: previous state
/// - q / Esc: quit
pub fn run_loop(app: &mut App) -> Result<()> {
    enable_raw_mode()?;
    let mut out = stdout();
    execute!(out, EnterAlternateScreen, EnableMouseCapture)?;

    let backend = CrosstermBackend::new(out);
    let mut terminal = Terminal::new(backend)?;

    // Ensure terminal is restored even if we exit early
    struct TuiGuard;
    impl Drop for TuiGuard {
        fn drop(&mut self) {
            let _ = disable_raw_mode();
            let mut out = std::io::stdout();
            let _ = execute!(out, DisableMouseCapture, LeaveAlternateScreen);
        }
    }
    let _guard = TuiGuard;

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
                            if app.menu_selected < app.menu_items.len() {
                                let action = app.menu_items[app.menu_selected].action;
                                app.selected_action = Some(action);
                                if action == crate::ui::MenuAction::Exit {
                                    break;
                                }
                            }
                            app.advance();
                        } else if app.state == crate::ui::AppState::CaseSetup {
                            // Initialize case directories before moving to provider select
                            let output_dir = std::env::current_dir()
                                .unwrap_or_else(|_| std::path::PathBuf::from("."));
                            if let Err(e) = app.init_case(output_dir) {
                                app.auth_status = format!("Failed to create case: {}", e);
                            } else {
                                app.advance(); // Move to ProviderSelect
                                try_refresh_providers(app);
                            }
                        } else if app.state == crate::ui::AppState::ProviderSelect {
                            app.confirm_provider();
                            if app
                                .chosen_provider
                                .as_ref()
                                .and_then(|p| p.known)
                                .is_some()
                            {
                                app.refresh_browsers();
                                app.advance(); // Move to BrowserSelect
                            } else {
                                app.chosen_browser = None;
                                app.state = crate::ui::AppState::Authenticating;
                                perform_auth_flow(app, &mut terminal)?;
                            }
                        } else if app.state == crate::ui::AppState::BrowserSelect {
                            app.confirm_browser();
                            app.advance(); // Move to Authenticating

                            if app.state == crate::ui::AppState::Authenticating {
                                perform_auth_flow(app, &mut terminal)?;
                            }
                        } else if app.state == crate::ui::AppState::FileList {
                            // Start download if files are selected
                            if !app.files_to_download.is_empty() {
                                app.advance(); // Move to Downloading
                                perform_download_flow(app, &mut terminal)?;
                            }
                        } else {
                            app.advance();
                        }
                    }
                    KeyCode::Backspace => {
                        if app.state == crate::ui::AppState::CaseSetup {
                            app.input_backspace();
                        } else {
                            app.back();
                        }
                    }
                    KeyCode::Up => {
                        if app.state == crate::ui::AppState::MainMenu {
                            app.menu_up();
                        } else if app.state == crate::ui::AppState::ProviderSelect {
                            app.provider_up();
                        } else if app.state == crate::ui::AppState::BrowserSelect {
                            app.browser_up();
                        } else if app.state == crate::ui::AppState::FileList {
                            app.file_up();
                        }
                    }
                    KeyCode::Down => {
                        if app.state == crate::ui::AppState::MainMenu {
                            app.menu_down();
                        } else if app.state == crate::ui::AppState::ProviderSelect {
                            app.provider_down();
                        } else if app.state == crate::ui::AppState::BrowserSelect {
                            app.browser_down();
                        } else if app.state == crate::ui::AppState::FileList {
                            app.file_down();
                        }
                    }
                    KeyCode::Char('r') => {
                        if app.state == crate::ui::AppState::ProviderSelect {
                            try_refresh_providers(app);
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
                                .chosen_remote
                                .clone()
                                .or_else(|| app.chosen_provider.as_ref().map(|p| p.short_name().to_string()));
                            let Some(remote_name) = remote_name else {
                                app.log_error("Mount failed: no remote selected");
                                continue;
                            };

                            let manager = match crate::rclone::MountManager::new(binary.path()) {
                                Ok(manager) => manager.with_config(config.path()),
                                Err(e) => {
                                    app.log_error(format!("Mount failed: {}", e));
                                    continue;
                                }
                            };

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
                        if app.state == crate::ui::AppState::FileList {
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
                    KeyCode::Char(ch) => app.input_char(ch),
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

fn handle_provider_help_key(app: &mut App, key: &KeyEvent) -> bool {
    if app.state != crate::ui::AppState::ProviderSelect {
        return false;
    }

    if app.show_provider_help {
        match key.code {
            KeyCode::Char('q') => false,
            KeyCode::Char('?') | KeyCode::Char('h') | KeyCode::Esc => {
                app.show_provider_help = false;
                true
            }
            _ => true,
        }
    } else {
        match key.code {
            KeyCode::Char('?') | KeyCode::Char('h') => {
                app.show_provider_help = true;
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
            crate::ui::AppState::ProviderSelect => app.provider_up(),
            crate::ui::AppState::BrowserSelect => app.browser_up(),
            crate::ui::AppState::FileList => app.file_up(),
            _ => {}
        },
        MouseEventKind::ScrollDown => match app.state {
            crate::ui::AppState::MainMenu => app.menu_down(),
            crate::ui::AppState::ProviderSelect => app.provider_down(),
            crate::ui::AppState::BrowserSelect => app.browser_down(),
            crate::ui::AppState::FileList => app.file_down(),
            _ => {}
        },
        MouseEventKind::Down(MouseButton::Left) => match app.state {
            crate::ui::AppState::MainMenu => {
                let list_area = main_menu_list_area(area);
                if let Some(index) = list_index_from_click(list_area, mouse.row) {
                    if index < app.menu_items.len() {
                        app.menu_selected = index;
                        let action = app.menu_items[index].action;
                        app.selected_action = Some(action);
                        if action == crate::ui::MenuAction::Exit {
                            app.exit_requested = true;
                        } else {
                            app.advance();
                        }
                    }
                }
            }
            crate::ui::AppState::ProviderSelect => {
                let list_area = provider_list_area(area);
                if let Some(index) = list_index_from_click(list_area, mouse.row) {
                    if index < app.providers.len() {
                        app.provider_selected = index;
                    }
                }
            }
            crate::ui::AppState::BrowserSelect => {
                if let Some(index) = list_index_from_click(area, mouse.row) {
                    if index < app.browsers.len() + 1 {
                        app.browser_selected = index;
                    }
                }
            }
            crate::ui::AppState::FileList => {
                if let Some(index) = list_index_from_click(area, mouse.row) {
                    if index < app.file_entries.len() {
                        app.file_selected = index;
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

#[cfg(test)]
mod tests {
    use super::*;
    use crossterm::event::{KeyModifiers, MouseButton, MouseEvent, MouseEventKind};
    use std::io::IsTerminal;

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
        let original_len = app.providers.len();

        let json = r#"
        [
          {"Name":"Amazon S3","Prefix":"s3"},
          {"Name":"Azure Blob","Prefix":"azureblob"},
          {"Name":"Backblaze B2","Prefix":"b2"},
          {"Name":"Google Drive","Prefix":"drive"}
        ]
        "#;

        refresh_providers_from_json(&mut app, json).unwrap();

        assert_ne!(app.providers.len(), original_len);
        assert!(app.providers.iter().any(|p| p.id == "s3"));
        assert!(app.providers.iter().any(|p| p.id == "azureblob"));
        assert!(app.providers.iter().any(|p| p.id == "b2"));
        assert!(app.providers.iter().any(|p| p.id == "drive"));
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

        assert_eq!(app.state, crate::ui::AppState::CaseSetup);
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
        assert!(app.show_provider_help);

        let up = KeyEvent::new(KeyCode::Up, KeyModifiers::NONE);
        assert!(handle_provider_help_key(&mut app, &up));
        assert!(app.show_provider_help);

        let esc = KeyEvent::new(KeyCode::Esc, KeyModifiers::NONE);
        assert!(handle_provider_help_key(&mut app, &esc));
        assert!(!app.show_provider_help);
    }

    #[test]
    fn test_provider_help_does_not_consume_quit() {
        let mut app = App::new();
        app.state = crate::ui::AppState::ProviderSelect;
        app.show_provider_help = true;

        let quit = KeyEvent::new(KeyCode::Char('q'), KeyModifiers::NONE);
        assert!(!handle_provider_help_key(&mut app, &quit));
        assert!(app.show_provider_help);
    }
}
