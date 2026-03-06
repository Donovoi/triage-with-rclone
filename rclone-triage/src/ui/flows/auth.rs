use anyhow::{bail, Result};
use ratatui::Terminal;
use std::time::Duration;

use crate::forensics::{
    generate_password, get_forensic_access_point_status, render_wifi_qr,
    start_forensic_access_point_with_status, stop_forensic_access_point,
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
use crate::ui::{App, AuthBatchTask, MenuAction};

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

            let device_config = device_code_config(provider)?.ok_or_else(|| {
                anyhow::anyhow!("Device code flow not supported for {}", provider)
            })?;
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

                match start_forensic_access_point_with_status(&ssid, &password, None, |msg| {
                    app.auth_status = msg.to_string();
                    // Best-effort redraw; ignore errors since terminal is borrowed.
                    let _ = terminal.draw(|f| render_state(f, app));
                }) {
                    Ok(info) => {
                        // Show AP status with connected client count
                        let mut status_lines = vec![
                            format!("Access point '{}' is running.", info.ssid),
                            format!("  IP: {}", info.ip_address),
                        ];
                        if let Ok(status) = get_forensic_access_point_status() {
                            status_lines
                                .push(format!("  Connected clients: {}", status.connected_clients));
                        }
                        status_lines.push(
                            "Connect your mobile device to the WiFi network above.".to_string(),
                        );
                        update_auth_status(app, terminal, status_lines)?;

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
                    if let Ok(status) = get_forensic_access_point_status() {
                        prelude_lines
                            .push(format!("Connected clients: {}", status.connected_clients));
                    }
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

#[derive(Debug, Clone)]
struct AuthOutcome {
    remote_name: String,
    user_info: Option<String>,
    was_silent: bool,
}

fn build_auth_tasks(app: &App) -> Result<Vec<AuthBatchTask>> {
    let providers = if !app.provider.chosen_multiple.is_empty() {
        app.provider.chosen_multiple.clone()
    } else {
        app.provider.chosen.clone().into_iter().collect()
    };

    if providers.is_empty() {
        bail!("No provider selected");
    }

    let selected_browsers = if !app.browser.chosen_multiple.is_empty() {
        app.browser.chosen_multiple.clone()
    } else if app.browser.chosen.is_some() || app.browser.checked.iter().any(|checked| *checked) {
        vec![app.browser.chosen.clone()]
    } else {
        Vec::new()
    };

    let mut tasks = Vec::new();
    for provider in providers {
        let requires_browser = matches!(app.selected_action, Some(MenuAction::Authenticate))
            && provider.known.is_some()
            && matches!(
                provider.auth_kind(),
                crate::providers::ProviderAuthKind::OAuth
            );

        if requires_browser {
            if selected_browsers.is_empty() {
                bail!("Select at least one browser (Space toggles selection).");
            }

            for browser in &selected_browsers {
                tasks.push(AuthBatchTask {
                    provider: provider.clone(),
                    browser: browser.clone(),
                });
            }
        } else {
            tasks.push(AuthBatchTask {
                provider,
                browser: None,
            });
        }
    }

    Ok(tasks)
}

fn format_batch_progress(app: &App, task: &AuthBatchTask) -> String {
    if app.auth_batch.total > 1 {
        format!(
            "[{}/{}] {}",
            app.auth_batch.completed + 1,
            app.auth_batch.total,
            task.description()
        )
    } else {
        task.description()
    }
}

fn record_authenticated_remote(
    app: &mut App,
    provider: &crate::providers::ProviderEntry,
    result: &AuthOutcome,
) {
    let is_new_remote = !app
        .authenticated_remotes
        .iter()
        .any(|(remote, _)| remote == &result.remote_name);

    if is_new_remote {
        app.authenticated_remotes.push((
            result.remote_name.clone(),
            provider.display_name().to_string(),
        ));

        if let Some(ref mut case) = app.forensics.case {
            case.add_provider(crate::case::AuthenticatedProvider {
                provider_id: provider.id.clone(),
                provider_name: provider.display_name().to_string(),
                remote_name: result.remote_name.clone(),
                user_info: result.user_info.clone(),
            });
        }
    }

    app.remote.chosen = Some(result.remote_name.clone());
}

fn perform_single_auth_task<B: ratatui::backend::Backend>(
    app: &mut App,
    terminal: &mut Terminal<B>,
    runner: &crate::rclone::RcloneRunner,
    config: &crate::rclone::RcloneConfig,
    task: &AuthBatchTask,
) -> Result<AuthOutcome> {
    let provider = task.provider.clone();
    let batch_label = format_batch_progress(app, task);

    let mut fallback_base: Option<String> = None;
    let mut fallback_remote: Option<String> = None;

    let mobile_flow = if app.selected_action == Some(MenuAction::MobileAuth) {
        Some(
            app.mobile_auth_flow
                .unwrap_or(crate::ui::MobileAuthFlow::Redirect),
        )
    } else {
        None
    };

    let auth_result: Result<AuthOutcome> = if let Some(known) = provider.known {
        if let Some(flow) = mobile_flow {
            app.auth_status = format!(
                "{}\n\nStarting mobile authentication for {}...",
                batch_label,
                provider.display_name()
            );
            terminal.draw(|f| render_state(f, app))?;

            let base = provider.short_name();
            let remote_name = config.next_available_remote_name(base)?;
            fallback_base = Some(base.to_string());
            fallback_remote = Some(remote_name.clone());

            perform_mobile_auth_flow(app, terminal, known, config, &remote_name, flow).map(
                |result| AuthOutcome {
                    remote_name: result.remote_name,
                    user_info: result.user_info,
                    was_silent: result.was_silent,
                },
            )
        } else if matches!(app.selected_action, Some(MenuAction::Authenticate)) {
            if let Some(ref browser) = task.browser {
                app.auth_status = format!(
                    "{}\n\nAuthenticating {} via {}...",
                    batch_label,
                    provider.display_name(),
                    browser.display_name()
                );
                terminal.draw(|f| render_state(f, app))?;

                crate::providers::auth::authenticate_with_browser_choice(
                    known, browser, runner, config,
                )
                .map(|result| AuthOutcome {
                    remote_name: result.remote_name,
                    user_info: result.user_info,
                    was_silent: result.was_silent,
                })
            } else {
                app.auth_status = format!(
                    "{}\n\nAuthenticating {} via System Default...",
                    batch_label,
                    provider.display_name()
                );
                terminal.draw(|f| render_state(f, app))?;

                let base = provider.short_name();
                let remote_name = config.next_available_remote_name(base)?;
                fallback_base = Some(base.to_string());
                fallback_remote = Some(remote_name.clone());

                crate::providers::auth::authenticate_with_system_browser(
                    known,
                    runner,
                    config,
                    &remote_name,
                )
                .map(|result| AuthOutcome {
                    remote_name: result.remote_name,
                    user_info: result.user_info,
                    was_silent: result.was_silent,
                })
            }
        } else {
            let sso_status = crate::providers::auth::detect_sso_sessions(known);
            if sso_status.has_sessions {
                app.auth_status = format!(
                    "{}\n\nFound existing {} sessions - attempting SSO...",
                    batch_label,
                    provider.display_name()
                );
                app.log_info(format!(
                    "Found {} browser(s) with {} sessions - attempting SSO auth",
                    sso_status.browsers_with_sessions.len(),
                    provider.display_name()
                ));
            } else {
                app.auth_status = format!(
                    "{}\n\nAuthenticating {}...",
                    batch_label,
                    provider.display_name()
                );
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

            crate::providers::auth::smart_authenticate(known, runner, config, &remote_name).map(
                |result| AuthOutcome {
                    remote_name: result.remote_name,
                    user_info: result.user_info,
                    was_silent: result.was_silent,
                },
            )
        }
    } else {
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
                "{}\n\nMobile auth for {} (rclone authorize)...\n\n1) Open the URL on your phone\n2) After login, copy the redirected URL (it may fail to load)\n3) Paste it back when prompted",
                batch_label,
                provider.display_name()
            );
            terminal.draw(|f| render_state(f, app))?;

            let mut running = crate::rclone::authorize::spawn_authorize(runner, &backend, true)?;
            let auth_url = running
                .wait_for_auth_url(Duration::from_secs(20))?
                .ok_or_else(|| anyhow::anyhow!("rclone authorize did not produce an auth URL"))?;

            let mut lines = Vec::new();
            lines.push(batch_label.clone());
            lines.push(String::new());
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

            crate::rclone::authorize::send_local_authorize_callback(redirect_uri, &cb.code, state)?;

            let finished = running.wait(Some(Duration::from_secs(300)))?;
            if finished.timed_out {
                bail!("rclone authorize timed out waiting for completion");
            }
            let token = finished.token_json.ok_or_else(|| {
                anyhow::anyhow!("Failed to extract token JSON from rclone output")
            })?;

            config.set_remote(
                &remote_name,
                &finished.backend,
                &[("token", token.as_str())],
            )?;
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
                "{}\n\nAuthenticating {} (rclone authorize)...",
                batch_label,
                provider.display_name()
            );
            app.log_info(format!(
                "Using rclone authorize for unknown backend {}",
                backend
            ));
            terminal.draw(|f| render_state(f, app))?;

            let mut running = crate::rclone::authorize::spawn_authorize(runner, &backend, false)?;
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
            config.set_remote(
                &remote_name,
                &finished.backend,
                &[("token", token.as_str())],
            )?;
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

    let outcome = auth_result?;
    if let (Some(base), Some(fallback)) = (fallback_base.as_deref(), fallback_remote.as_deref()) {
        if base != fallback && outcome.remote_name == fallback {
            app.log_info(format!(
                "Remote '{}' already exists; using '{}'",
                base, fallback
            ));
        }
    }

    Ok(outcome)
}

/// Perform the authentication flow (extract binary, create config, auth, list files)
pub(crate) fn perform_auth_flow<B: ratatui::backend::Backend>(
    app: &mut App,
    terminal: &mut Terminal<B>,
) -> Result<()> {
    if app.auth_batch.total == 0
        && app.auth_batch.pending.is_empty()
        && app.auth_batch.current.is_none()
    {
        match build_auth_tasks(app) {
            Ok(tasks) => app.start_auth_batch(tasks),
            Err(e) => {
                app.auth_status = e.to_string();
                return Ok(());
            }
        }
    }

    if app.auth_batch.pending.is_empty() && app.auth_batch.current.is_none() {
        app.auth_status = "No pending authentication tasks.".to_string();
        return Ok(());
    }

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

    let mut last_success: Option<(crate::providers::ProviderEntry, AuthOutcome)> = None;

    while let Some(task) = app.next_auth_task() {
        let task_label = format_batch_progress(app, &task);

        match perform_single_auth_task(app, terminal, &runner, &config, &task) {
            Ok(result) => {
                let auth_type = if result.was_silent {
                    "SSO"
                } else {
                    "interactive"
                };
                app.log_info(format!(
                    "Authentication successful for {} ({})",
                    task.provider.display_name(),
                    auth_type
                ));

                record_authenticated_remote(app, &task.provider, &result);
                last_success = Some((task.provider.clone(), result.clone()));

                app.auth_status = if app.auth_batch.total > 1 {
                    format!("{}\n\nTesting connectivity...", task_label)
                } else {
                    "Testing connectivity...".to_string()
                };
                terminal.draw(|f| render_state(f, app))?;

                let max_retries: u32 = 3;
                let mut connectivity =
                    crate::rclone::test_connectivity(&runner, &result.remote_name)?;
                let mut attempt: u32 = 1;
                while !connectivity.ok && attempt <= max_retries {
                    let delay = crate::rclone::retry_delay(attempt - 1);
                    let msg = format!(
                        "Connectivity check failed (attempt {}/{}), retrying in {}s...",
                        attempt,
                        max_retries + 1,
                        delay.as_secs()
                    );
                    app.log_info(&msg);
                    app.auth_status = if app.auth_batch.total > 1 {
                        format!("{}\n\n{}", task_label, msg)
                    } else {
                        msg
                    };
                    terminal.draw(|f| render_state(f, app))?;
                    std::thread::sleep(delay);
                    connectivity = crate::rclone::test_connectivity(&runner, &result.remote_name)?;
                    attempt += 1;
                }

                if connectivity.ok {
                    let extra = if attempt > 1 {
                        format!(" (succeeded on attempt {})", attempt)
                    } else {
                        String::new()
                    };
                    app.log_info(format!(
                        "Connectivity OK ({} ms){}",
                        connectivity.duration.as_millis(),
                        extra
                    ));
                } else {
                    let err_msg = connectivity
                        .error
                        .unwrap_or_else(|| "Unknown error".to_string());
                    let failure = format!(
                        "Authentication succeeded, but connectivity check failed after {} attempts: {}",
                        attempt, err_msg
                    );
                    app.log_error(failure.clone());
                    app.fail_current_auth_task(failure.clone());
                    app.auth_status = if app.auth_batch.total > 1 {
                        format!(
                            "{}\n\nBatch stopped after {} of {} successful task(s).\nRemaining queued authentications: {}\n\n{}",
                            task_label,
                            app.auth_batch.completed,
                            app.auth_batch.total,
                            app.auth_batch.pending.len(),
                            failure
                        )
                    } else {
                        format!(
                            "{}\n\nYou can retry listing from the file list screen.",
                            failure
                        )
                    };
                    return Ok(());
                }

                app.finish_current_auth_task();

                if app.auth_batch.completed < app.auth_batch.total {
                    app.auth_status = format!(
                        "Completed {}/{}: {}\n\nPreparing next authentication...",
                        app.auth_batch.completed,
                        app.auth_batch.total,
                        task.description()
                    );
                    terminal.draw(|f| render_state(f, app))?;
                }
            }
            Err(e) => {
                let error_text = format!(
                    "Authentication failed for {}: {}",
                    task.provider.display_name(),
                    e
                );
                app.log_error(error_text.clone());
                app.fail_current_auth_task(error_text.clone());
                app.auth_status = if app.auth_batch.total > 1 {
                    format!(
                        "{}\n\nBatch stopped after {} of {} successful task(s).\nRemaining queued authentications: {}\n\n{}",
                        task_label,
                        app.auth_batch.completed,
                        app.auth_batch.total,
                        app.auth_batch.pending.len(),
                        error_text
                    )
                } else {
                    format!("Auth failed: {}", e)
                };
                return Ok(());
            }
        }
    }

    if let Some((provider, result)) = last_success {
        let ready_names: Vec<String> = app
            .authenticated_remotes
            .iter()
            .map(|(remote, _)| remote.clone())
            .collect();

        app.auth_status = if app.authenticated_remotes.len() > 1 || app.auth_batch.total > 1 {
            format!(
                "Authenticated {} remote(s) across {} authentication step(s).\nReady remotes: {}\n\nChoose how to access the remote files.",
                app.authenticated_remotes.len(),
                app.auth_batch.total,
                ready_names.join(", ")
            )
        } else {
            let provider_name = provider.display_name().to_string();
            let user_line = result
                .user_info
                .as_ref()
                .map(|user| format!("  User: {}\n", user))
                .unwrap_or_default();
            format!(
                "Authenticated {} successfully ({}){}\n\nChoose how to access the remote files.",
                provider_name,
                if result.was_silent {
                    "SSO"
                } else {
                    "interactive"
                },
                if user_line.is_empty() {
                    String::new()
                } else {
                    format!("\n{}", user_line)
                },
            )
        };

        app.post_auth_selected = 0;
        app.post_auth_action = None;
        app.advance();
    } else {
        app.auth_status = "No provider selected".to_string();
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::providers::browser::{Browser, BrowserType};
    use crate::providers::{CloudProvider, ProviderEntry};

    #[test]
    fn test_build_auth_tasks_cross_product_in_visible_order() {
        let mut app = App::new();
        app.selected_action = Some(MenuAction::Authenticate);
        app.provider.chosen_multiple = vec![
            ProviderEntry::from_known(CloudProvider::GoogleDrive),
            ProviderEntry::from_known(CloudProvider::OneDrive),
        ];

        let mut chrome = Browser::new(BrowserType::Chrome);
        chrome.is_installed = true;
        let mut edge = Browser::new(BrowserType::Edge);
        edge.is_installed = true;

        app.browser.chosen_multiple = vec![Some(chrome.clone()), Some(edge.clone())];

        let tasks = build_auth_tasks(&app).unwrap();
        assert_eq!(tasks.len(), 4);
        assert_eq!(tasks[0].provider.id, "drive");
        assert_eq!(tasks[1].provider.id, "drive");
        assert_eq!(tasks[2].provider.id, "onedrive");
        assert_eq!(tasks[3].provider.id, "onedrive");
        assert_eq!(
            tasks[0]
                .browser
                .as_ref()
                .map(|browser| browser.browser_type),
            Some(BrowserType::Chrome)
        );
        assert_eq!(
            tasks[1]
                .browser
                .as_ref()
                .map(|browser| browser.browser_type),
            Some(BrowserType::Edge)
        );
    }

    #[test]
    fn test_build_auth_tasks_requires_browser_for_interactive_oauth() {
        let mut app = App::new();
        app.selected_action = Some(MenuAction::Authenticate);
        app.provider.chosen_multiple = vec![ProviderEntry::from_known(CloudProvider::GoogleDrive)];

        let err = build_auth_tasks(&app).unwrap_err();
        assert!(err.to_string().contains("Select at least one browser"));
    }

    #[test]
    fn test_build_auth_tasks_smart_auth_ignores_browser_cross_product() {
        let mut app = App::new();
        app.selected_action = Some(MenuAction::SmartAuth);
        app.provider.chosen_multiple = vec![
            ProviderEntry::from_known(CloudProvider::GoogleDrive),
            ProviderEntry::from_known(CloudProvider::OneDrive),
        ];

        let mut chrome = Browser::new(BrowserType::Chrome);
        chrome.is_installed = true;
        let mut edge = Browser::new(BrowserType::Edge);
        edge.is_installed = true;
        app.browser.chosen_multiple = vec![Some(chrome), Some(edge)];

        let tasks = build_auth_tasks(&app).unwrap();
        assert_eq!(tasks.len(), 2);
        assert!(tasks.iter().all(|task| task.browser.is_none()));
    }
}
