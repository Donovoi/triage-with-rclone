//! Basic TUI runner
//!
//! Sets up terminal backend and renders a single frame.

use anyhow::Result;
use crossterm::event::{self, Event, KeyCode};
use crossterm::execute;
use crossterm::terminal::{
    disable_raw_mode, enable_raw_mode, EnterAlternateScreen, LeaveAlternateScreen,
};
use ratatui::backend::CrosstermBackend;
use ratatui::Terminal;
use std::io::stdout;
use std::time::Duration;

use crate::ui::screens::welcome::WelcomeScreen;
use crate::ui::{render::render_state, App};

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
    let config = crate::rclone::RcloneConfig::for_case(&config_dir)?;

    // Track config file creation
    app.track_file(config.path(), "Created rclone config file");
    app.cleanup_track_env_value("RCLONE_CONFIG", config.original_env());

    let runner = crate::rclone::RcloneRunner::new(binary.path()).with_config(config.path());

    if let Some(provider) = app.chosen_provider {
        // If user selected a browser, use it; otherwise use smart auth (SSO + interactive)
        let auth_result = if let Some(ref browser) = app.chosen_browser {
            app.auth_status = format!(
                "Authenticating {} via {}...",
                provider.display_name(),
                browser.display_name()
            );
            terminal.draw(|f| render_state(f, app))?;

            crate::providers::auth::authenticate_with_browser_choice(
                provider, browser, &runner, &config,
            )
        } else {
            // Detect SSO sessions first
            let sso_status = crate::providers::auth::detect_sso_sessions(provider);
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

            crate::providers::auth::smart_authenticate(provider, &runner, &config, provider.short_name())
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
                        provider,
                        remote_name: result.remote_name.clone(),
                        user_info: result.user_info.clone(),
                    });
                }

                // Persist remote name for later listing/download
                app.chosen_remote = Some(result.remote_name.clone());

                app.auth_status = "Listing files...".to_string();
                terminal.draw(|f| render_state(f, app))?;

                match crate::files::list_path(&runner, &format!("{}:", result.remote_name)) {
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
    use crate::files::download::{DownloadQueue, DownloadRequest};

    app.download_status = format!("Downloading {} files...", app.files_to_download.len());
    app.download_progress = (0, app.files_to_download.len());
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
    let config = crate::rclone::RcloneConfig::for_case(&config_dir)?;
    app.cleanup_track_env_value("RCLONE_CONFIG", config.original_env());
    let runner = crate::rclone::RcloneRunner::new(binary.path()).with_config(config.path());

    if let Some(provider) = app.chosen_provider {
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
            let (expected_hash, hash_type) = app
                .get_file_entry(file)
                .map(|e| (e.hash.clone(), e.hash_type.clone()))
                .unwrap_or((None, None));

            let request = DownloadRequest::new_copyto(&source, dest.to_string_lossy())
                .with_hash(expected_hash, hash_type);
            queue.add(request);
        }

        // Execute downloads with progress callback
        // Since we can't borrow app mutably in the callback, we collect updates
        let files_clone = app.files_to_download.clone();
        let results = queue.download_all_with_progress(&runner, |progress| {
            // Progress callback - can't update TUI here due to borrow, but logging works
            tracing::info!("{}", progress.status);
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
    execute!(out, EnterAlternateScreen)?;

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
    execute!(out, EnterAlternateScreen)?;

    let backend = CrosstermBackend::new(out);
    let mut terminal = Terminal::new(backend)?;

    // Ensure terminal is restored even if we exit early
    struct TuiGuard;
    impl Drop for TuiGuard {
        fn drop(&mut self) {
            let _ = disable_raw_mode();
            let mut out = std::io::stdout();
            let _ = execute!(out, LeaveAlternateScreen);
        }
    }
    let _guard = TuiGuard;

    loop {
        terminal.draw(|f| {
            render_state(f, app);
        })?;

        if event::poll(Duration::from_millis(200))? {
            if let Event::Key(key) = event::read()? {
                match key.code {
                    KeyCode::Char('q') | KeyCode::Esc => break,
                    KeyCode::Enter => {
                        if app.state == crate::ui::AppState::CaseSetup {
                            // Initialize case directories before moving to provider select
                            let output_dir = std::env::current_dir()
                                .unwrap_or_else(|_| std::path::PathBuf::from("."));
                            if let Err(e) = app.init_case(output_dir) {
                                app.auth_status = format!("Failed to create case: {}", e);
                            } else {
                                app.advance(); // Move to ProviderSelect
                            }
                        } else if app.state == crate::ui::AppState::ProviderSelect {
                            app.confirm_provider();
                            app.refresh_browsers();
                            app.advance(); // Move to BrowserSelect
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
                        if app.state == crate::ui::AppState::ProviderSelect {
                            app.provider_up();
                        } else if app.state == crate::ui::AppState::BrowserSelect {
                            app.browser_up();
                        } else if app.state == crate::ui::AppState::FileList {
                            app.file_up();
                        }
                    }
                    KeyCode::Down => {
                        if app.state == crate::ui::AppState::ProviderSelect {
                            app.provider_down();
                        } else if app.state == crate::ui::AppState::BrowserSelect {
                            app.browser_down();
                        } else if app.state == crate::ui::AppState::FileList {
                            app.file_down();
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
        }
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
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
}
