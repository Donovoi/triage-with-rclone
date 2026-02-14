use anyhow::{bail, Result};
use ratatui::Terminal;
use std::time::Duration;

use crate::forensics::{
    generate_password, render_wifi_qr, start_forensic_access_point, stop_forensic_access_point,
};
use crate::providers::auth::user_identifier_from_config;
use crate::providers::config::ProviderConfig;
use crate::providers::mobile::{
    device_code_config, poll_device_code_for_token, render_qr_code, request_device_code,
};
use crate::providers::CloudProvider;
use crate::rclone::oauth::DEFAULT_OAUTH_PORT;
use crate::ui::prompt::prompt_text_in_tui;
use crate::ui::render::render_state;
use crate::ui::App;

fn update_auth_status<B: ratatui::backend::Backend>(
    app: &mut App,
    terminal: &mut Terminal<B>,
    lines: Vec<String>,
) -> Result<()> {
    app.auth_status = lines.join("\n");
    terminal.draw(|f| render_state(f, app))?;
    Ok(())
}

fn perform_mobile_auth_flow<B: ratatui::backend::Backend>(
    app: &mut App,
    terminal: &mut Terminal<B>,
    provider: CloudProvider,
    config: &crate::rclone::RcloneConfig,
    remote_name: &str,
    flow: crate::ui::MobileAuthFlow,
) -> Result<crate::providers::auth::AuthResult> {
    let provider_config = ProviderConfig::for_provider(provider);
    if !provider_config.uses_oauth() {
        bail!(
            "{} does not use OAuth. Mobile authentication is not supported.",
            provider.display_name()
        );
    }

    match flow {
        crate::ui::MobileAuthFlow::DeviceCode => {
            update_auth_status(
                app,
                terminal,
                vec![format!(
                    "Requesting device code for {}...",
                    provider.display_name()
                )],
            )?;

            let device_config = device_code_config(provider)?
                .ok_or_else(|| anyhow::anyhow!("Device code flow not supported for {}", provider))?;
            let device_info = request_device_code(&device_config)?;

            let verification = device_info
                .verification_uri_complete
                .clone()
                .unwrap_or_else(|| device_info.verification_uri.clone());

            let mut lines = vec![
                format!("Device code authentication for {}", provider.display_name()),
                format!("User code: {}", device_info.user_code),
                format!("Verify at: {}", device_info.verification_uri),
            ];

            if let Some(message) = device_info.message.as_ref() {
                lines.push(message.clone());
            }

            if let Ok(qr) = render_qr_code(&verification) {
                lines.push("Scan this QR code:".to_string());
                lines.push(qr);
            }

            lines.push("Waiting for authorization...".to_string());
            update_auth_status(app, terminal, lines)?;

            let token_json = poll_device_code_for_token(
                &device_config,
                &device_info.device_code,
                device_info.interval,
                device_info.expires_in,
            )?;

            let token_str = serde_json::to_string(&token_json)?;

            let mut options: Vec<(String, String)> = Vec::new();
            for (key, value) in provider_config.rclone_options {
                options.push(((*key).to_string(), (*value).to_string()));
            }
            if !device_config.client_id.trim().is_empty() {
                options.push(("client_id".to_string(), device_config.client_id));
            }
            if let Some(secret) = device_config.client_secret {
                if !secret.trim().is_empty() {
                    options.push(("client_secret".to_string(), secret));
                }
            }
            options.push(("token".to_string(), token_str));

            let options_ref: Vec<(&str, &str)> = options
                .iter()
                .map(|(k, v)| (k.as_str(), v.as_str()))
                .collect();

            config.set_remote(remote_name, provider.rclone_type(), &options_ref)?;
            if !config.has_remote(remote_name)? {
                bail!("Remote {} was not created", remote_name);
            }

            let user_identifier = user_identifier_from_config(provider, config, remote_name);

            Ok(crate::providers::auth::AuthResult {
                provider,
                remote_name: remote_name.to_string(),
                user_info: user_identifier,
                browser: None,
                was_silent: false,
            })
        }
        crate::ui::MobileAuthFlow::Redirect
        | crate::ui::MobileAuthFlow::RedirectWithAccessPoint => {
            let mut ap_info: Option<crate::forensics::ForensicAccessPointInfo> = None;
            if flow == crate::ui::MobileAuthFlow::RedirectWithAccessPoint {
                let password = generate_password();
                let ssid = format!("FORENSIC-{}", &password[..6]);
                update_auth_status(
                    app,
                    terminal,
                    vec![format!("Starting forensic access point: {}", ssid)],
                )?;

                match start_forensic_access_point(&ssid, &password, None) {
                    Ok(info) => {
                        ap_info = Some(info);
                    }
                    Err(e) => {
                        update_auth_status(
                            app,
                            terminal,
                            vec![
                                format!("Access point failed: {}", e),
                                "Continuing without access point.".to_string(),
                            ],
                        )?;
                    }
                }
            }

            let result = {
                let mut prelude_lines: Vec<String> = Vec::new();
                if let Some(ref info) = ap_info {
                    prelude_lines.push(format!("Access Point SSID: {}", info.ssid));
                    prelude_lines.push(format!("Access Point Password: {}", info.password));
                    prelude_lines.push(format!("Access Point IP: {}", info.ip_address));
                    if let Ok(wifi_qr) = render_wifi_qr(&info.ssid, &info.password) {
                        prelude_lines.push("WiFi QR:".to_string());
                        prelude_lines.push(wifi_qr);
                    }
                }

                crate::providers::auth::authenticate_with_mobile_redirect(
                    provider,
                    config,
                    remote_name,
                    DEFAULT_OAUTH_PORT,
                    prelude_lines,
                    |lines| update_auth_status(app, terminal, lines),
                )
            };

            if ap_info.is_some() {
                let _ = stop_forensic_access_point(true);
            }

            result
        }
    }
}

/// Perform the authentication flow (extract binary, create config, auth, list files)
pub(crate) fn perform_auth_flow<B: ratatui::backend::Backend>(
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

    if let Some(provider) = app.provider.chosen.clone() {
        struct AuthOutcome {
            remote_name: String,
            user_info: Option<String>,
            was_silent: bool,
        }

        let mut fallback_base: Option<String> = None;
        let mut fallback_remote: Option<String> = None;

        let mobile_flow = if app.selected_action == Some(crate::ui::MenuAction::MobileAuth) {
            app.mobile_auth_flow
                .take()
                .or(Some(crate::ui::MobileAuthFlow::Redirect))
        } else {
            None
        };

        // If user selected a browser, use it; otherwise use smart auth (SSO + interactive)
        let auth_result: Result<AuthOutcome> = if let Some(known) = provider.known {
            if let Some(flow) = mobile_flow {
                app.auth_status = format!(
                    "Starting mobile authentication for {}...",
                    provider.display_name()
                );
                terminal.draw(|f| render_state(f, app))?;

                let base = provider.short_name();
                let remote_name = config.next_available_remote_name(base)?;
                fallback_base = Some(base.to_string());
                fallback_remote = Some(remote_name.clone());

                perform_mobile_auth_flow(app, terminal, known, &config, &remote_name, flow).map(
                    |result| AuthOutcome {
                        remote_name: result.remote_name,
                        user_info: result.user_info,
                        was_silent: result.was_silent,
                    },
                )
            } else if let Some(ref browser) = app.browser.chosen {
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

                let base = provider.short_name();
                let remote_name = config.next_available_remote_name(base)?;
                fallback_base = Some(base.to_string());
                fallback_remote = Some(remote_name.clone());

                crate::providers::auth::smart_authenticate(known, &runner, &config, &remote_name)
                    .map(|result| AuthOutcome {
                        remote_name: result.remote_name,
                        user_info: result.user_info,
                        was_silent: result.was_silent,
                    })
            }
        } else {
            // Unknown provider: best-effort OAuth via `rclone authorize <backend>`.
            // This supports most rclone OAuth backends without needing provider-specific endpoints.
            match provider.auth_kind() {
                crate::providers::ProviderAuthKind::KeyBased
                | crate::providers::ProviderAuthKind::UserPass => {
                    bail!(
                        "Backend '{}' does not appear to use OAuth (detected: {:?}). rclone-triage cannot auto-authenticate it yet. Configure it in an rclone config and use Retrieve List / Mount / Download from CSV.",
                        provider.short_name(),
                        provider.auth_kind()
                    );
                }
                crate::providers::ProviderAuthKind::Unknown => {
                    app.log_info(format!(
                        "Backend '{}' auth type unknown; attempting OAuth via rclone authorize (best effort).",
                        provider.short_name()
                    ));
                }
                crate::providers::ProviderAuthKind::OAuth => {}
            }

            let base = provider.short_name();
            let remote_name = config.next_available_remote_name(base)?;
            fallback_base = Some(base.to_string());
            fallback_remote = Some(remote_name.clone());

            let backend = provider.short_name().to_string();

            if mobile_flow.is_some() {
                app.auth_status = format!(
                    "Mobile auth for {} (rclone authorize)...\n\n1) Open the URL on your phone\n2) After login, copy the redirected URL (it may fail to load)\n3) Paste it back when prompted",
                    provider.display_name()
                );
                terminal.draw(|f| render_state(f, app))?;

                let mut running =
                    crate::rclone::authorize::spawn_authorize(&runner, &backend, true)?;
                let auth_url = running
                    .wait_for_auth_url(Duration::from_secs(20))?
                    .ok_or_else(|| anyhow::anyhow!("rclone authorize did not produce an auth URL"))?;

                let mut lines = Vec::new();
                lines.push(format!(
                    "Mobile authorization for {} (backend: {})",
                    provider.display_name(),
                    backend
                ));
                lines.push(format!("Open on phone: {}", auth_url));
                if let Ok(qr) = render_qr_code(&auth_url) {
                    lines.push("Scan this QR code:".to_string());
                    lines.push(qr);
                }
                lines.push(String::new());
                lines.push(
                    "After login, copy/paste the final redirect URL here (or paste only the code)."
                        .to_string(),
                );
                update_auth_status(app, terminal, lines)?;

                let pasted = prompt_text_in_tui(
                    app,
                    terminal,
                    "Paste OAuth Callback",
                    "Paste redirect URL (or paste only the code value).",
                )?
                .ok_or_else(|| anyhow::anyhow!("User cancelled"))?;
                if pasted.trim().is_empty() {
                    bail!("No callback input provided");
                }
                let cb = crate::rclone::authorize::parse_authorize_callback_input(&pasted)?;

                let redirect_uri = running
                    .redirect_uri()
                    .ok_or_else(|| anyhow::anyhow!("Missing redirect_uri in authorize output"))?;
                let state = cb.state.as_deref().or(running.expected_state());

                crate::rclone::authorize::send_local_authorize_callback(
                    redirect_uri,
                    &cb.code,
                    state,
                )?;

                let finished = running.wait(Some(Duration::from_secs(300)))?;
                if finished.timed_out {
                    bail!("rclone authorize timed out waiting for completion");
                }
                let token = finished.token_json.ok_or_else(|| {
                    anyhow::anyhow!("Failed to extract token JSON from rclone output")
                })?;

                config.set_remote(&remote_name, &finished.backend, &[("token", token.as_str())])?;
                if !config.has_remote(&remote_name)? {
                    bail!("Remote {} was not created", remote_name);
                }

                Ok(AuthOutcome {
                    remote_name,
                    user_info: None,
                    was_silent: false,
                })
            } else {
                app.auth_status = format!(
                    "Authenticating {} (rclone authorize)...",
                    provider.display_name()
                );
                app.log_info(format!(
                    "Using rclone authorize for unknown backend {}",
                    backend
                ));
                terminal.draw(|f| render_state(f, app))?;

                let mut running =
                    crate::rclone::authorize::spawn_authorize(&runner, &backend, false)?;
                // Best-effort: capture and display the URL if rclone printed it.
                let _ = running.wait_for_auth_url(Duration::from_secs(10))?;

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

                let token = finished.token_json.ok_or_else(|| {
                    anyhow::anyhow!("Failed to extract token JSON from rclone output")
                })?;
                config.set_remote(&remote_name, &finished.backend, &[("token", token.as_str())])?;
                if !config.has_remote(&remote_name)? {
                    bail!("Remote {} was not created", remote_name);
                }

                Ok(AuthOutcome {
                    remote_name,
                    user_info: None,
                    was_silent: false,
                })
            }
        };
        terminal.draw(|f| render_state(f, app))?;

        match auth_result {
            Ok(result) => {
                if let (Some(base), Some(fallback)) =
                    (fallback_base.as_deref(), fallback_remote.as_deref())
                {
                    if base != fallback && result.remote_name == fallback {
                        app.log_info(format!(
                            "Remote '{}' already exists; using '{}'",
                            base, fallback
                        ));
                    }
                }

                let auth_type = if result.was_silent { "SSO" } else { "interactive" };
                app.log_info(format!(
                    "Authentication successful for {} ({})",
                    provider.display_name(),
                    auth_type
                ));

                // Track authenticated provider in case
                if let Some(ref mut case) = app.forensics.case {
                    case.add_provider(crate::case::AuthenticatedProvider {
                        provider_id: provider.id.clone(),
                        provider_name: provider.display_name().to_string(),
                        remote_name: result.remote_name.clone(),
                        user_info: result.user_info.clone(),
                    });
                }

                // Persist remote name for later listing/download
                app.remote.chosen = Some(result.remote_name.clone());

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
                        connectivity
                            .error
                            .unwrap_or_else(|| "Unknown error".to_string())
                    ));
                }

                app.auth_status = "Listing files...".to_string();
                terminal.draw(|f| render_state(f, app))?;

                let large_listing = std::env::var("RCLONE_TRIAGE_LARGE_LISTING")
                    .map(|v| v != "0")
                    .unwrap_or(false);
                let large_in_memory: usize =
                    std::env::var("RCLONE_TRIAGE_LARGE_LISTING_IN_MEMORY")
                        .ok()
                        .and_then(|v| v.parse().ok())
                        .unwrap_or(50_000);

                let include_hashes = provider
                    .known
                    .map(|known| !known.hash_types().is_empty())
                    .unwrap_or_else(|| {
                        // Best-effort: consult rclone's features table. If we can't confirm support,
                        // do not request hashes.
                        match crate::providers::features::provider_supports_hashes(&provider) {
                            Ok(Some(true)) => true,
                            Ok(Some(false)) | Ok(None) => false,
                            Err(e) => {
                                app.log_info(format!(
                                    "Skipping remote hashes (hash support lookup failed): {}",
                                    e
                                ));
                                false
                            }
                        }
                    });

                let list_options = if include_hashes {
                    crate::files::listing::ListPathOptions::with_hashes()
                } else {
                    crate::files::listing::ListPathOptions::without_hashes()
                };

                if large_listing {
                    if app.forensics.directories.is_none() {
                        app.log_info("Large listing requested, but case directories are unavailable; falling back to in-memory listing.");
                    }
                    if let Some(ref dirs) = app.forensics.directories {
                        let csv_path = dirs
                            .listings
                            .join(format!("{}_files.csv", provider.short_name()));

                        let listing_result =
                            crate::files::listing::list_path_large_to_csv_with_progress(
                                &runner,
                                &format!("{}:", result.remote_name),
                                list_options,
                                &csv_path,
                                large_in_memory,
                                |count| {
                                    app.auth_status =
                                        format!("Listing files... ({} found)", count);
                                    let _ = terminal.draw(|f| render_state(f, app));
                                },
                            );

                        match listing_result {
                            Ok(result) => {
                                app.log_info(format!("Exported listing to {:?}", csv_path));
                                app.track_file(&csv_path, "Exported file listing CSV");

                                // Store (possibly truncated) entries for UI usage.
                                app.files.entries_full = result.entries.clone();
                                app.files.entries =
                                    result.entries.iter().map(|e| e.path.clone()).collect();

                                let shown = app.files.entries.len();
                                if result.truncated {
                                    app.auth_status = format!(
                                        "Found {} files (showing first {}). CSV: {:?}",
                                        result.total_entries, shown, csv_path
                                    );
                                } else {
                                    app.auth_status =
                                        format!("Found {} files", result.total_entries);
                                }
                                app.advance(); // Move to FileList
                            }
                            Err(e) => {
                                app.log_error(format!("File listing failed: {}", e));
                                app.auth_status = format!("Listing failed: {}", e);
                            }
                        }
                        return Ok(());
                    }
                }

                let listing_result = crate::files::listing::list_path_with_progress(
                    &runner,
                    &format!("{}:", result.remote_name),
                    list_options,
                    |count| {
                        app.auth_status = format!("Listing files... ({} found)", count);
                        let _ = terminal.draw(|f| render_state(f, app));
                    },
                );

                match listing_result {
                    Ok(entries) => {
                        // Export file listing to CSV
                        if let Some(ref dirs) = app.forensics.directories {
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
                            if let Err(e) = crate::files::export::export_listing_xlsx(
                                &entries, &xlsx_path,
                            ) {
                                app.log_error(format!("Excel export failed: {}", e));
                            } else {
                                app.log_info(format!("Exported listing to {:?}", xlsx_path));
                                app.track_file(&xlsx_path, "Exported file listing Excel");
                            }
                        }

                        // Store full entries for hash verification during download
                        app.files.entries_full = entries.clone();
                        app.files.entries = entries.iter().map(|e| e.path.clone()).collect();
                        app.log_info(format!(
                            "Listed {} files from {}",
                            app.files.entries.len(),
                            provider.display_name()
                        ));
                        app.auth_status = format!("Found {} files", app.files.entries.len());
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
