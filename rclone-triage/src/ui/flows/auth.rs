use anyhow::{bail, Result};
use ratatui::Terminal;
use std::time::Duration;

use crate::forensics::{
    generate_password, get_forensic_access_point_status, render_wifi_qr,
    start_forensic_access_point_with_status, stop_forensic_access_point,
};
use crate::providers::auth::user_identifier_from_config;
use crate::providers::browser::BrowserAuthSession;
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

            crate::providers::auth::complete_provider_remote_setup(provider, config, remote_name)?;

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

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum BrowserFailureKind {
    ViaRcloneAuthorize,
    LocalhostCallback,
    LocalhostListenerUnavailable,
    MissingAuthorizeUrl,
    Other,
}

fn classify_browser_failure(error: &anyhow::Error) -> Option<BrowserFailureKind> {
    let mut saw_browser_timeout = false;
    let mut saw_localhost_callback_timeout = false;
    let mut saw_localhost_listener_unavailable = false;
    let mut saw_missing_authorize_url = false;
    let mut saw_direct_retry_failure = false;

    for cause in error.chain() {
        let message = cause.to_string().to_lowercase();

        if message.contains("did not produce an auth url") {
            saw_missing_authorize_url = true;
        }

        if message.contains(
            "direct browser oauth retry failed after rclone authorize did not yield an auth url",
        ) || message.contains(
            "direct system-browser oauth retry failed after rclone authorize did not yield an auth url",
        ) {
            saw_direct_retry_failure = true;
        }

        if message.contains("authentication timed out waiting for") {
            saw_browser_timeout = true;
            if message.contains("via rclone authorize") {
                return Some(BrowserFailureKind::ViaRcloneAuthorize);
            }
        }

        if message.contains("oauth timeout: no response received within") {
            saw_localhost_callback_timeout = true;
        }

        if message.contains("failed to start oauth server on")
            || message.contains("address already in use")
        {
            saw_localhost_listener_unavailable = true;
        }
    }

    if saw_direct_retry_failure || saw_localhost_listener_unavailable {
        Some(BrowserFailureKind::LocalhostListenerUnavailable)
    } else if saw_missing_authorize_url {
        Some(BrowserFailureKind::MissingAuthorizeUrl)
    } else if saw_localhost_callback_timeout {
        Some(BrowserFailureKind::LocalhostCallback)
    } else if saw_browser_timeout {
        Some(BrowserFailureKind::Other)
    } else {
        None
    }
}

fn auth_error_mentions_timeout(error: &anyhow::Error) -> bool {
    classify_browser_failure(error).is_some()
}

fn should_auto_fallback_to_onedrive_device_code(
    provider: CloudProvider,
    error: &anyhow::Error,
) -> bool {
    provider == CloudProvider::OneDrive && auth_error_mentions_timeout(error)
}

fn browser_device_code_fallback_remote_name(task: &AuthBatchTask) -> Option<String> {
    let browser = task.browser.as_ref()?;
    Some(BrowserAuthSession::new(browser.clone(), task.provider.short_name()).remote_name(None))
}

fn browser_profile_label(browser: &crate::providers::browser::Browser) -> Option<String> {
    browser
        .profile_path
        .as_ref()?
        .file_name()
        .and_then(|name| name.to_str())
        .filter(|name| !name.trim().is_empty())
        .map(|name| name.to_string())
}

fn browser_name_for_auth_status(app: &App, browser: &crate::providers::browser::Browser) -> String {
    if matches!(app.selected_action, Some(MenuAction::AutoDetectAccounts)) {
        if let Some(profile) = browser_profile_label(browser) {
            return format!("{} [{}]", browser.display_name(), profile);
        }
    }

    browser.display_name().to_string()
}

fn uses_targeted_browser_auth(action: Option<MenuAction>) -> bool {
    matches!(
        action,
        Some(MenuAction::Authenticate) | Some(MenuAction::AutoDetectAccounts)
    )
}

fn build_onedrive_device_code_fallback_message(
    provider_name: &str,
    error: &anyhow::Error,
) -> String {
    match classify_browser_failure(error) {
        Some(BrowserFailureKind::ViaRcloneAuthorize) => format!(
            "{} browser authentication timed out via rclone authorize; switching to device code.",
            provider_name
        ),
        Some(BrowserFailureKind::LocalhostCallback) => format!(
            "{} browser authentication timed out waiting for the localhost callback; switching to device code.",
            provider_name
        ),
        Some(BrowserFailureKind::LocalhostListenerUnavailable) => format!(
            "{} browser authentication could not start the localhost callback listener; switching to device code.",
            provider_name
        ),
        Some(BrowserFailureKind::MissingAuthorizeUrl) => format!(
            "{} browser authentication could not get an rclone authorize URL; switching to device code.",
            provider_name
        ),
        _ => format!(
            "{} browser authentication stalled; switching to device code.",
            provider_name
        ),
    }
}

fn maybe_fallback_to_onedrive_device_code<B: ratatui::backend::Backend>(
    app: &mut App,
    terminal: &mut Terminal<B>,
    config: &crate::rclone::RcloneConfig,
    task: &AuthBatchTask,
    batch_label: &str,
    remote_name: &str,
    auth_result: Result<AuthOutcome>,
) -> Result<AuthOutcome> {
    let known = task.provider.known.ok_or_else(|| {
        anyhow::anyhow!("Automatic OneDrive device-code fallback requires a known provider")
    })?;

    match auth_result {
        Ok(outcome) => Ok(outcome),
        Err(auth_error) if should_auto_fallback_to_onedrive_device_code(known, &auth_error) => {
            let provider_name = task.provider.display_name();
            let fallback_message =
                build_onedrive_device_code_fallback_message(provider_name, &auth_error);

            tracing::warn!(
                provider = %provider_name,
                remote = %remote_name,
                error = %auth_error,
                "Browser authentication stalled; starting automatic device-code fallback"
            );
            app.log_info(fallback_message.clone());
            app.auth_status = format!("{}\n\n{}", batch_label, fallback_message);
            terminal.draw(|f| render_state(f, app))?;

            perform_mobile_auth_flow(
                app,
                terminal,
                known,
                config,
                remote_name,
                crate::ui::MobileAuthFlow::DeviceCode,
            )
            .map(|result| AuthOutcome {
                remote_name: result.remote_name,
                user_info: result.user_info,
                was_silent: result.was_silent,
            })
            .map_err(|fallback_error| {
                anyhow::anyhow!(
                    "Browser authentication stalled for {}: {}. Automatic device-code fallback failed: {}",
                    provider_name,
                    auth_error,
                    fallback_error
                )
            })
        }
        Err(auth_error) => Err(auth_error),
    }
}

fn build_auth_tasks(app: &App) -> Result<Vec<AuthBatchTask>> {
    if matches!(app.selected_action, Some(MenuAction::AutoDetectAccounts)) {
        return crate::ui::flows::auto_detect::build_auth_tasks_from_detected_accounts(app);
    }

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

fn build_batch_stopped_status(
    task_label: &str,
    completed: usize,
    total: usize,
    remaining: usize,
    failure: &str,
    follow_up: Option<&str>,
) -> String {
    let mut status = if total > 1 {
        format!(
            "{}\n\nBatch stopped after {} of {} successful task(s).\nRemaining queued authentications: {}\n\n{}",
            task_label, completed, total, remaining, failure
        )
    } else {
        failure.to_string()
    };

    if let Some(note) = follow_up.filter(|note| !note.trim().is_empty()) {
        status.push_str("\n\n");
        status.push_str(note);
    }

    status
}

fn partial_success_retry_guidance(provider: &crate::providers::ProviderEntry) -> String {
    if provider.known == Some(CloudProvider::OneDrive) {
        "Continuing with the ready remotes. Return to Provider Select to retry Microsoft OneDrive. If Microsoft sign-in keeps completing but the remote still fails, try the Device Code flow.".to_string()
    } else {
        format!(
            "Continuing with the ready remotes. Return to Provider Select to retry {}.",
            provider.display_name()
        )
    }
}

fn no_success_retry_guidance(provider: &crate::providers::ProviderEntry) -> String {
    if provider.known == Some(CloudProvider::OneDrive) {
        "No validated remotes are ready yet. Return to Provider Select and retry Microsoft OneDrive. If Microsoft sign-in keeps completing but the remote still fails, try the Device Code flow or use a known-good rclone config.".to_string()
    } else {
        format!(
            "No validated remotes are ready yet. Return to Provider Select and retry {}.",
            provider.display_name()
        )
    }
}

fn build_auth_completion_status(
    authenticated_remotes: &[(String, String)],
    total_steps: usize,
    provider: &crate::providers::ProviderEntry,
    result: &AuthOutcome,
    last_error: Option<&str>,
) -> String {
    let failure_note = last_error
        .filter(|error| !error.trim().is_empty())
        .map(|error| {
            format!(
                "\n\nOne or more authentication steps failed:\n{}\n\nContinue with the ready remotes, then return to Provider Select to retry the failed provider.",
                error
            )
        })
        .unwrap_or_default();

    if authenticated_remotes.len() > 1 || total_steps > 1 {
        let ready_names: Vec<String> = authenticated_remotes
            .iter()
            .map(|(remote, _)| remote.clone())
            .collect();

        format!(
            "Authenticated {} remote(s) across {} authentication step(s).\nReady remotes: {}{}\n\nChoose how to access the remote files.",
            authenticated_remotes.len(),
            total_steps,
            ready_names.join(", "),
            failure_note,
        )
    } else {
        let provider_name = provider.display_name().to_string();
        let user_line = format!(
            "  {}\n",
            authenticated_account_status_line(&provider_name, result.user_info.as_deref())
        );
        format!(
            "Authenticated {} successfully ({})\n{}{}\nChoose how to access the remote files.",
            provider_name,
            if result.was_silent {
                "SSO"
            } else {
                "interactive"
            },
            user_line,
            failure_note,
        )
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
enum BrowserAccountContext {
    KnownUser(String),
    ReusableSessionUnknownUser,
    NoReusableSession,
    InspectionUnavailable,
    UnresolvedSystemDefault,
}

fn browser_account_context_from_session(
    session: &crate::providers::session::BrowserSession,
) -> BrowserAccountContext {
    if !session.is_valid {
        return BrowserAccountContext::NoReusableSession;
    }

    match session
        .user_hint
        .as_deref()
        .map(str::trim)
        .filter(|hint| !hint.is_empty())
    {
        Some(hint) => BrowserAccountContext::KnownUser(hint.to_string()),
        None => BrowserAccountContext::ReusableSessionUnknownUser,
    }
}

fn inspect_browser_account_context(
    provider: CloudProvider,
    browser: Option<&crate::providers::browser::Browser>,
) -> BrowserAccountContext {
    let Some(browser) = browser else {
        return BrowserAccountContext::UnresolvedSystemDefault;
    };

    let extractor = match crate::providers::session::SessionExtractor::new() {
        Ok(extractor) => extractor,
        Err(_) => return BrowserAccountContext::InspectionUnavailable,
    };

    match extractor.extract_session(browser, provider) {
        Ok(session) => browser_account_context_from_session(&session),
        Err(_) => BrowserAccountContext::InspectionUnavailable,
    }
}

fn build_browser_account_context_message(
    provider_name: &str,
    browser_name: &str,
    context: &BrowserAccountContext,
) -> String {
    match context {
        BrowserAccountContext::KnownUser(user) => format!(
            "Detected reusable {} session for {}; that account is likely to be used unless {} prompts otherwise.",
            browser_name, user, provider_name
        ),
        BrowserAccountContext::ReusableSessionUnknownUser => format!(
            "Detected reusable {} session, but the account could not yet be identified.",
            browser_name
        ),
        BrowserAccountContext::NoReusableSession => format!(
            "No reusable {} session was detected; the browser/provider may ask which account to use.",
            browser_name
        ),
        BrowserAccountContext::InspectionUnavailable => format!(
            "The current {} session could not be inspected.",
            browser_name
        ),
        BrowserAccountContext::UnresolvedSystemDefault => {
            "Using the system default browser. The OS/browser will decide which signed-in account is presented.".to_string()
        }
    }
}

fn build_browser_auth_status(
    task_label: &str,
    provider_name: &str,
    browser_name: &str,
    context: &BrowserAccountContext,
) -> String {
    [
        task_label.to_string(),
        String::new(),
        format!("Authenticating {} via {}...", provider_name, browser_name),
        build_browser_account_context_message(provider_name, browser_name, context),
    ]
    .join("\n")
}

fn format_sso_session_summary(status: &crate::providers::auth::SsoStatus) -> Option<String> {
    if !status.has_sessions {
        return None;
    }

    let has_user_hints = status.browsers_with_sessions.iter().any(|(_, session)| {
        session
            .user_hint
            .as_deref()
            .map(str::trim)
            .is_some_and(|hint| !hint.is_empty())
    });

    let session_descriptions: Vec<String> = status
        .browsers_with_sessions
        .iter()
        .map(|(browser, session)| {
            match session
                .user_hint
                .as_deref()
                .map(str::trim)
                .filter(|hint| !hint.is_empty())
            {
                Some(hint) => format!("{} ({})", browser.display_name(), hint),
                None if has_user_hints => {
                    format!("{} (account not identified)", browser.display_name())
                }
                None => browser.display_name().to_string(),
            }
        })
        .collect();

    if session_descriptions.is_empty() {
        None
    } else if has_user_hints {
        Some(format!(
            "Session hints: {}",
            session_descriptions.join(", ")
        ))
    } else {
        Some(format!(
            "Reusable sessions detected in: {}",
            session_descriptions.join(", ")
        ))
    }
}

fn build_sso_auth_status(
    task_label: &str,
    provider_name: &str,
    status: &crate::providers::auth::SsoStatus,
) -> String {
    let mut lines = vec![task_label.to_string(), String::new()];

    if status.has_sessions {
        lines.push(format!(
            "Found existing {} sessions - attempting SSO...",
            provider_name
        ));
        if let Some(summary) = format_sso_session_summary(status) {
            lines.push(summary);
        }
    } else {
        lines.push(format!(
            "No reusable {} browser sessions were detected; interactive auth may ask which account to use.",
            provider_name
        ));
    }

    lines.join("\n")
}

fn authenticated_account_status_line(provider_name: &str, user_info: Option<&str>) -> String {
    match user_info.map(str::trim).filter(|user| !user.is_empty()) {
        Some(user) => format!("Authenticated account: {}", user),
        None => format!(
            "Authenticated account: not reported yet ({} did not report an account identifier yet).",
            provider_name
        ),
    }
}

fn build_connectivity_status(
    task_label: Option<&str>,
    detail: &str,
    provider_name: &str,
    user_info: Option<&str>,
) -> String {
    let mut lines = vec![detail.to_string()];
    if let Some(label) = task_label.map(str::trim).filter(|label| !label.is_empty()) {
        lines.push(label.to_string());
    }
    lines.push(authenticated_account_status_line(provider_name, user_info));
    lines.join("\n")
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
        } else if uses_targeted_browser_auth(app.selected_action) {
            if let Some(ref browser) = task.browser {
                let browser_name = browser_name_for_auth_status(app, browser);
                let account_context = inspect_browser_account_context(known, Some(browser));
                app.auth_status = build_browser_auth_status(
                    &batch_label,
                    provider.display_name(),
                    &browser_name,
                    &account_context,
                );
                terminal.draw(|f| render_state(f, app))?;

                let remote_name = browser_device_code_fallback_remote_name(task)
                    .ok_or_else(|| anyhow::anyhow!("Missing browser for browser auth task"))?;

                maybe_fallback_to_onedrive_device_code(
                    app,
                    terminal,
                    config,
                    task,
                    &batch_label,
                    &remote_name,
                    crate::providers::auth::authenticate_with_browser_choice(
                        known, browser, runner, config,
                    )
                    .map(|result| AuthOutcome {
                        remote_name: result.remote_name,
                        user_info: result.user_info,
                        was_silent: result.was_silent,
                    }),
                )
            } else {
                let account_context = inspect_browser_account_context(known, None);
                app.auth_status = build_browser_auth_status(
                    &batch_label,
                    provider.display_name(),
                    "System Default",
                    &account_context,
                );
                terminal.draw(|f| render_state(f, app))?;

                let base = provider.short_name();
                let remote_name = config.next_available_remote_name(base)?;
                fallback_base = Some(base.to_string());
                fallback_remote = Some(remote_name.clone());

                maybe_fallback_to_onedrive_device_code(
                    app,
                    terminal,
                    config,
                    task,
                    &batch_label,
                    &remote_name,
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
                    }),
                )
            }
        } else {
            let sso_status = crate::providers::auth::detect_sso_sessions(known);
            app.auth_status =
                build_sso_auth_status(&batch_label, provider.display_name(), &sso_status);
            if sso_status.has_sessions {
                app.log_info(format!(
                    "Found {} browser(s) with {} sessions - attempting SSO auth",
                    sso_status.browsers_with_sessions.len(),
                    provider.display_name()
                ));
            } else {
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

            maybe_fallback_to_onedrive_device_code(
                app,
                terminal,
                config,
                task,
                &batch_label,
                &remote_name,
                crate::providers::auth::smart_authenticate(known, runner, config, &remote_name)
                    .map(|result| AuthOutcome {
                        remote_name: result.remote_name,
                        user_info: result.user_info,
                        was_silent: result.was_silent,
                    }),
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

                let connectivity_label = if app.auth_batch.total > 1 {
                    Some(task_label.as_str())
                } else {
                    None
                };
                app.auth_status = build_connectivity_status(
                    connectivity_label,
                    "Testing connectivity...",
                    task.provider.display_name(),
                    result.user_info.as_deref(),
                );
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
                    app.auth_status = build_connectivity_status(
                        connectivity_label,
                        &msg,
                        task.provider.display_name(),
                        result.user_info.as_deref(),
                    );
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

                    record_authenticated_remote(app, &task.provider, &result);
                    last_success = Some((task.provider.clone(), result.clone()));
                    app.finish_current_auth_task();
                } else {
                    let err_msg = connectivity
                        .error
                        .unwrap_or_else(|| "Unknown error".to_string());
                    let failure = format!(
                        "Authentication succeeded, but connectivity check failed after {} attempts: {}",
                        attempt, err_msg
                    );
                    app.log_error(failure.clone());
                    if let Err(cleanup_error) = config.remove_remote(&result.remote_name) {
                        app.log_error(format!(
                            "Failed to clean up remote '{}' after connectivity failure: {}",
                            result.remote_name, cleanup_error
                        ));
                    }
                    app.fail_current_auth_task(failure.clone());
                    app.auth_batch.current = None;

                    if last_success.is_some() {
                        let remaining_tasks = app.auth_batch.pending.len();
                        app.auth_batch.pending.clear();
                        app.auth_status = build_batch_stopped_status(
                            &task_label,
                            app.auth_batch.completed,
                            app.auth_batch.total,
                            remaining_tasks,
                            &failure,
                            Some(&partial_success_retry_guidance(&task.provider)),
                        );
                        break;
                    }

                    let guidance = no_success_retry_guidance(&task.provider);
                    let status = build_batch_stopped_status(
                        &task_label,
                        app.auth_batch.completed,
                        app.auth_batch.total,
                        app.auth_batch.pending.len(),
                        &failure,
                        Some(&guidance),
                    );
                    app.auth_status = status.clone();
                    app.provider.status = status;
                    app.clear_auth_batch();
                    app.state = crate::ui::AppState::ProviderSelect;
                    return Ok(());
                }

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
                app.auth_batch.current = None;

                if last_success.is_some() {
                    let remaining_tasks = app.auth_batch.pending.len();
                    app.auth_batch.pending.clear();
                    app.auth_status = build_batch_stopped_status(
                        &task_label,
                        app.auth_batch.completed,
                        app.auth_batch.total,
                        remaining_tasks,
                        &error_text,
                        Some(&partial_success_retry_guidance(&task.provider)),
                    );
                    break;
                }

                app.auth_status = if app.auth_batch.total > 1 {
                    build_batch_stopped_status(
                        &task_label,
                        app.auth_batch.completed,
                        app.auth_batch.total,
                        app.auth_batch.pending.len(),
                        &error_text,
                        None,
                    )
                } else {
                    format!("Auth failed: {}", e)
                };
                return Ok(());
            }
        }
    }

    if let Some((provider, result)) = last_success {
        let total_steps = app.auth_batch.total;
        let last_error = app.auth_batch.last_error.clone();
        app.auth_status = build_auth_completion_status(
            &app.authenticated_remotes,
            total_steps,
            &provider,
            &result,
            last_error.as_deref(),
        );

        app.post_auth_selected = 0;
        app.post_auth_action = None;
        app.clear_auth_batch();
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
    use crate::providers::session::BrowserSession;
    use crate::providers::{CloudProvider, ProviderEntry};
    use anyhow::Context;

    #[test]
    fn test_should_auto_fallback_to_onedrive_device_code_for_oauth_timeout() {
        let error = anyhow::anyhow!("OAuth timeout: no response received within 300 seconds");

        assert!(should_auto_fallback_to_onedrive_device_code(
            CloudProvider::OneDrive,
            &error,
        ));
    }

    #[test]
    fn test_should_auto_fallback_to_onedrive_device_code_for_nested_browser_timeout() {
        let error = Err::<(), _>(anyhow::anyhow!(
            "Authentication timed out waiting for Microsoft OneDrive login via rclone authorize"
        ))
        .context("Fallback OAuth failed for Microsoft OneDrive")
        .unwrap_err();

        assert!(should_auto_fallback_to_onedrive_device_code(
            CloudProvider::OneDrive,
            &error,
        ));
    }

    #[test]
    fn test_should_auto_fallback_to_onedrive_device_code_for_missing_authorize_url() {
        let error =
            anyhow::anyhow!("rclone authorize did not produce an auth URL for Microsoft OneDrive");

        assert!(should_auto_fallback_to_onedrive_device_code(
            CloudProvider::OneDrive,
            &error,
        ));
    }

    #[test]
    fn test_should_auto_fallback_to_onedrive_device_code_for_direct_retry_failure() {
        let error = Err::<(), _>(anyhow::anyhow!(
            "Failed to start OAuth server on 127.0.0.1:53682: address already in use"
        ))
        .context(
            "Direct browser OAuth retry failed after rclone authorize did not yield an auth URL",
        )
        .unwrap_err();

        assert!(should_auto_fallback_to_onedrive_device_code(
            CloudProvider::OneDrive,
            &error,
        ));
    }

    #[test]
    fn test_should_not_auto_fallback_for_non_timeout_errors() {
        let error = anyhow::anyhow!("OAuth error: access_denied - user declined consent");

        assert!(!should_auto_fallback_to_onedrive_device_code(
            CloudProvider::OneDrive,
            &error,
        ));
    }

    #[test]
    fn test_should_not_auto_fallback_for_other_providers() {
        let error = anyhow::anyhow!("OAuth timeout: no response received within 300 seconds");

        assert!(!should_auto_fallback_to_onedrive_device_code(
            CloudProvider::GoogleDrive,
            &error,
        ));
    }

    #[test]
    fn test_browser_device_code_fallback_remote_name_matches_browser_prefix() {
        let mut browser = Browser::new(BrowserType::Edge);
        browser.is_installed = true;

        let task = AuthBatchTask {
            provider: ProviderEntry::from_known(CloudProvider::OneDrive),
            browser: Some(browser),
        };

        assert_eq!(
            browser_device_code_fallback_remote_name(&task).as_deref(),
            Some("edge-onedrive")
        );
    }

    #[test]
    fn test_build_onedrive_device_code_fallback_message_for_rclone_authorize_timeout() {
        let error = anyhow::anyhow!(
            "Authentication timed out waiting for Microsoft OneDrive login via rclone authorize"
        );

        let message = build_onedrive_device_code_fallback_message("Microsoft OneDrive", &error);

        assert!(message.contains("via rclone authorize"));
        assert!(!message.contains("localhost callback"));
    }

    #[test]
    fn test_build_onedrive_device_code_fallback_message_for_localhost_timeout() {
        let error = Err::<(), _>(anyhow::anyhow!(
            "OAuth timeout: no response received within 300 seconds"
        ))
        .context("OAuth authentication failed for Microsoft OneDrive")
        .unwrap_err();

        let message = build_onedrive_device_code_fallback_message("Microsoft OneDrive", &error);

        assert!(message.contains("localhost callback"));
        assert!(!message.contains("via rclone authorize"));
    }

    #[test]
    fn test_build_onedrive_device_code_fallback_message_for_missing_authorize_url() {
        let error =
            anyhow::anyhow!("rclone authorize did not produce an auth URL for Microsoft OneDrive");

        let message = build_onedrive_device_code_fallback_message("Microsoft OneDrive", &error);

        assert!(message.contains("could not get an rclone authorize URL"));
        assert!(!message.contains("localhost callback"));
    }

    #[test]
    fn test_build_onedrive_device_code_fallback_message_for_localhost_listener_unavailable() {
        let error = Err::<(), _>(anyhow::anyhow!(
            "Failed to start OAuth server on 127.0.0.1:53682: address already in use"
        ))
        .context(
            "Direct browser OAuth retry failed after rclone authorize did not yield an auth URL",
        )
        .unwrap_err();

        let message = build_onedrive_device_code_fallback_message("Microsoft OneDrive", &error);

        assert!(message.contains("could not start the localhost callback listener"));
        assert!(!message.contains("could not get an rclone authorize URL"));
    }

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

    #[test]
    fn test_browser_name_for_auth_status_includes_profile_for_auto_detect_flow() {
        let mut app = App::new();
        app.selected_action = Some(MenuAction::AutoDetectAccounts);

        let mut browser = Browser::new(BrowserType::Chrome);
        browser.profile_path = Some(std::path::PathBuf::from("/profiles/Profile 7"));

        assert_eq!(
            browser_name_for_auth_status(&app, &browser),
            "Google Chrome [Profile 7]"
        );
    }

    #[test]
    fn test_uses_targeted_browser_auth_includes_auto_detect_accounts() {
        assert!(uses_targeted_browser_auth(Some(MenuAction::Authenticate)));
        assert!(uses_targeted_browser_auth(Some(
            MenuAction::AutoDetectAccounts
        )));
        assert!(!uses_targeted_browser_auth(Some(MenuAction::SmartAuth)));
    }

    #[test]
    fn test_build_batch_stopped_status_appends_follow_up_note() {
        let status = build_batch_stopped_status(
            "[2/2] Microsoft OneDrive via Chrome",
            1,
            2,
            0,
            "Authentication succeeded, but connectivity check failed after 4 attempts",
            Some("Continuing with the ready remotes."),
        );

        assert!(status.contains("Batch stopped after 1 of 2 successful task(s)."));
        assert!(status.contains("Continuing with the ready remotes."));
    }

    #[test]
    fn test_no_success_retry_guidance_for_onedrive_mentions_device_code() {
        let provider = ProviderEntry::from_known(CloudProvider::OneDrive);
        let guidance = no_success_retry_guidance(&provider);

        assert!(guidance.contains("Microsoft OneDrive"));
        assert!(guidance.contains("Device Code"));
    }

    #[test]
    fn test_build_auth_completion_status_includes_partial_failure_note() {
        let provider = ProviderEntry::from_known(CloudProvider::GoogleDrive);
        let outcome = AuthOutcome {
            remote_name: "drive-user@example.com".to_string(),
            user_info: Some("user@example.com".to_string()),
            was_silent: false,
        };

        let status = build_auth_completion_status(
            &[(
                "drive-user@example.com".to_string(),
                "Google Drive".to_string(),
            )],
            2,
            &provider,
            &outcome,
            Some("Authentication failed for Microsoft OneDrive"),
        );

        assert!(status.contains("Ready remotes: drive-user@example.com"));
        assert!(status.contains("One or more authentication steps failed"));
        assert!(status.contains("retry the failed provider"));
    }

    #[test]
    fn test_browser_account_context_message_for_detected_known_user_session() {
        let session = BrowserSession {
            browser_type: BrowserType::Edge,
            provider: CloudProvider::OneDrive,
            cookies: Vec::new(),
            user_hint: Some("analyst@example.com".to_string()),
            is_valid: true,
            local_state_key: None,
        };

        let message = build_browser_account_context_message(
            "Microsoft OneDrive",
            "Microsoft Edge",
            &browser_account_context_from_session(&session),
        );

        assert!(message.contains("analyst@example.com"));
        assert!(message.contains("likely to be used"));
    }

    #[test]
    fn test_browser_account_context_message_when_no_reusable_session_detected() {
        let session = BrowserSession {
            browser_type: BrowserType::Chrome,
            provider: CloudProvider::GoogleDrive,
            cookies: Vec::new(),
            user_hint: None,
            is_valid: false,
            local_state_key: None,
        };

        let message = build_browser_account_context_message(
            "Google Drive",
            "Google Chrome",
            &browser_account_context_from_session(&session),
        );

        assert!(message.contains("No reusable Google Chrome session was detected"));
        assert!(message.contains("may ask which account to use"));
    }

    #[test]
    fn test_build_connectivity_status_includes_authenticated_account_when_present() {
        let status = build_connectivity_status(
            Some("[1/1] Google Drive via Chrome"),
            "Testing connectivity...",
            "Google Drive",
            Some("user@example.com"),
        );

        assert!(status.starts_with("Testing connectivity..."));
        assert!(status.contains("[1/1] Google Drive via Chrome"));
        assert!(status.contains("Authenticated account: user@example.com"));
    }

    #[test]
    fn test_build_connectivity_status_explains_missing_account_when_absent() {
        let status =
            build_connectivity_status(None, "Testing connectivity...", "Microsoft OneDrive", None);

        assert!(status.contains("Testing connectivity..."));
        assert!(status.contains("Authenticated account: not reported yet"));
        assert!(status.contains("did not report an account identifier yet"));
    }
}
