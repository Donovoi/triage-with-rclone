//! Provider authentication
//!
//! Handles OAuth authentication flow for each provider.
//! Supports multi-browser authentication for forensic scenarios.
//! Includes SSO/Silent authentication by detecting existing browser sessions.

use super::browser::{Browser, BrowserAuthSession, BrowserDetector};
use super::credentials::{custom_oauth_credentials_for, OAuthCredentials};
use super::mobile::{
    device_code_config, exchange_code_for_token, poll_device_code_for_token, render_qr_code,
    request_device_code,
};
use super::session::{browsers_with_sessions, BrowserSession};
use super::{config::ProviderConfig, CloudProvider};
use crate::rclone::{OAuthFlow, RcloneConfig, RcloneRunner};
use crate::utils::network::get_local_ip_address;
use anyhow::{bail, Context, Result};
use serde::Deserialize;
use std::time::Duration;

const INTERACTIVE_AUTH_TIMEOUT: Duration = Duration::from_secs(300);

/// Result of authentication
#[derive(Debug, Clone)]
pub struct AuthResult {
    /// The provider that was authenticated
    pub provider: CloudProvider,
    /// Remote name in rclone config
    pub remote_name: String,
    /// User email/ID if available
    pub user_info: Option<String>,
    /// Browser used for authentication (if applicable)
    pub browser: Option<Browser>,
    /// Whether this was a silent/SSO authentication
    pub was_silent: bool,
}

/// Information about available SSO sessions for a provider
#[derive(Debug, Clone)]
pub struct SsoStatus {
    /// Provider being checked
    pub provider: CloudProvider,
    /// Browsers with valid sessions
    pub browsers_with_sessions: Vec<(Browser, BrowserSession)>,
    /// Whether any SSO session is available
    pub has_sessions: bool,
    /// Best browser to use (most recent/complete session)
    pub recommended_browser: Option<Browser>,
}

fn resolve_custom_oauth(provider: CloudProvider) -> Option<OAuthCredentials> {
    match custom_oauth_credentials_for(provider) {
        Ok(Some(creds)) => {
            tracing::info!("Using custom OAuth credentials for {}", provider);
            Some(creds)
        }
        Ok(None) => None,
        Err(e) => {
            tracing::warn!("Failed to load custom OAuth credentials: {}", e);
            None
        }
    }
}

fn non_empty_owned(value: &str) -> Option<String> {
    if value.trim().is_empty() {
        None
    } else {
        Some(value.to_string())
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum BrowserAuthStrategy {
    DirectCodeExchange,
    ViaRcloneAuthorize,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct ResolvedBrowserAuthSettings {
    client_id: String,
    client_secret: Option<String>,
    strategy: BrowserAuthStrategy,
}

fn select_browser_auth_strategy(
    provider: CloudProvider,
    has_effective_client_secret: bool,
    has_custom_oauth_config: bool,
) -> BrowserAuthStrategy {
    if provider == CloudProvider::GooglePhotos && !has_custom_oauth_config {
        return BrowserAuthStrategy::ViaRcloneAuthorize;
    }

    if has_effective_client_secret || has_custom_oauth_config {
        BrowserAuthStrategy::DirectCodeExchange
    } else {
        BrowserAuthStrategy::ViaRcloneAuthorize
    }
}

fn should_retry_onedrive_direct_browser_auth(error: &anyhow::Error) -> bool {
    error.chain().any(|cause| {
        cause
            .to_string()
            .to_lowercase()
            .contains("did not produce an auth url")
    })
}

fn resolve_effective_client_secret(
    provider_config: &ProviderConfig,
    custom: Option<&OAuthCredentials>,
) -> Option<String> {
    match custom {
        Some(custom) => custom
            .client_secret
            .clone()
            .filter(|secret| !secret.trim().is_empty())
            .or_else(|| {
                if custom.client_id.trim() == provider_config.oauth.client_id {
                    non_empty_owned(provider_config.oauth.client_secret)
                } else {
                    None
                }
            }),
        None => non_empty_owned(provider_config.oauth.client_secret),
    }
}

fn resolve_browser_auth_settings_with_custom(
    provider_config: &ProviderConfig,
    custom: Option<OAuthCredentials>,
) -> ResolvedBrowserAuthSettings {
    let has_custom_oauth_config = custom.is_some();
    let client_id = custom
        .as_ref()
        .map(|creds| creds.client_id.clone())
        .unwrap_or_else(|| provider_config.oauth.client_id.to_string());
    let client_secret = resolve_effective_client_secret(provider_config, custom.as_ref());
    let strategy = select_browser_auth_strategy(
        provider_config.provider,
        client_secret.is_some(),
        has_custom_oauth_config,
    );

    ResolvedBrowserAuthSettings {
        client_id,
        client_secret,
        strategy,
    }
}

fn resolve_browser_auth_settings(
    provider: CloudProvider,
    provider_config: &ProviderConfig,
) -> ResolvedBrowserAuthSettings {
    resolve_browser_auth_settings_with_custom(provider_config, resolve_custom_oauth(provider))
}

fn build_rclone_auth_args(
    provider: CloudProvider,
    remote_name: &str,
    non_interactive: bool,
) -> Vec<String> {
    let mut args = vec![
        "config".to_string(),
        "create".to_string(),
        remote_name.to_string(),
        provider.rclone_type().to_string(),
    ];

    if let Some(creds) = resolve_custom_oauth(provider) {
        if !creds.client_id.trim().is_empty() {
            args.push("client_id".to_string());
            args.push(creds.client_id);
        }
        if let Some(secret) = creds.client_secret {
            if !secret.trim().is_empty() {
                args.push("client_secret".to_string());
                args.push(secret);
            }
        }
    }

    if non_interactive {
        args.push("--non-interactive".to_string());
    }

    args
}

fn run_rclone_with_browser_env(
    browser: &Browser,
    rclone: &RcloneRunner,
    args: &[&str],
) -> Result<crate::rclone::process::RcloneOutput> {
    if let Some(ref path) = browser.executable_path {
        let path_str = path.to_string_lossy().to_string();
        let envs = [
            ("BROWSER".to_string(), path_str.clone()),
            ("RCLONE_BROWSER".to_string(), path_str),
        ];
        let envs_ref: Vec<(&str, &str)> =
            envs.iter().map(|(k, v)| (k.as_str(), v.as_str())).collect();
        return rclone.run_with_env(args, &envs_ref);
    }

    rclone.run(args)
}

pub fn user_identifier_from_config(
    provider: CloudProvider,
    config: &RcloneConfig,
    remote_name: &str,
) -> Option<String> {
    if !provider.supports_token_user_info() {
        return None;
    }
    config
        .get_user_info(remote_name)
        .ok()
        .flatten()
        .and_then(|u| u.best_identifier())
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct OneDriveDriveSelection {
    drive_id: String,
    drive_type: String,
}

#[derive(Debug, Deserialize)]
struct OneDriveDriveResponse {
    id: String,
    #[serde(rename = "driveType")]
    drive_type: String,
}

fn parse_onedrive_drive_selection_response(body: &str) -> Result<OneDriveDriveSelection> {
    let response: OneDriveDriveResponse =
        serde_json::from_str(body).context("Failed to parse OneDrive drive discovery response")?;

    if response.id.trim().is_empty() {
        bail!("OneDrive drive discovery response did not include a drive id");
    }
    if response.drive_type.trim().is_empty() {
        bail!("OneDrive drive discovery response did not include a drive type");
    }

    Ok(OneDriveDriveSelection {
        drive_id: response.id,
        drive_type: response.drive_type,
    })
}

fn resolve_onedrive_drive_selection(access_token: &str) -> Result<OneDriveDriveSelection> {
    let agent = ureq::AgentBuilder::new()
        .timeout_connect(Duration::from_secs(5))
        .timeout_read(Duration::from_secs(15))
        .timeout_write(Duration::from_secs(15))
        .build();

    let response = match agent
        .get("https://graph.microsoft.com/v1.0/me/drive")
        .set("Authorization", &format!("Bearer {}", access_token))
        .set("Accept", "application/json")
        .call()
    {
        Ok(response) => response,
        Err(ureq::Error::Status(code, response)) => {
            let body = response.into_string().unwrap_or_default();
            bail!("OneDrive drive discovery failed (HTTP {}): {}", code, body);
        }
        Err(error) => return Err(error.into()),
    };

    let body = response
        .into_string()
        .context("Failed to read OneDrive drive discovery response")?;
    parse_onedrive_drive_selection_response(&body)
}

fn persist_remote_option_updates(
    config: &RcloneConfig,
    remote_name: &str,
    updates: Vec<(String, String)>,
) -> Result<()> {
    let parsed = config.parse()?;
    let remote = parsed
        .get_remote(remote_name)
        .ok_or_else(|| anyhow::anyhow!("Remote {} not found", remote_name))?;

    let mut options: Vec<(String, String)> = remote.options.clone().into_iter().collect();
    if let Some(ref token) = remote.token {
        let token_json = serde_json::to_string(token)?;
        options.push(("token".to_string(), token_json));
    }

    for (key, value) in updates {
        if let Some(existing) = options
            .iter_mut()
            .find(|(existing_key, _)| *existing_key == key)
        {
            existing.1 = value;
        } else {
            options.push((key, value));
        }
    }

    let options_ref: Vec<(&str, &str)> = options
        .iter()
        .map(|(key, value)| (key.as_str(), value.as_str()))
        .collect();

    config.set_remote(remote_name, &remote.remote_type, &options_ref)
}

fn complete_onedrive_remote_setup_with_resolver<F>(
    config: &RcloneConfig,
    remote_name: &str,
    resolve_drive: F,
) -> Result<()>
where
    F: FnOnce(&str) -> Result<OneDriveDriveSelection>,
{
    let parsed = config.parse()?;
    let remote = parsed
        .get_remote(remote_name)
        .ok_or_else(|| anyhow::anyhow!("Remote {} not found", remote_name))?;

    if remote.remote_type != CloudProvider::OneDrive.rclone_type() {
        return Ok(());
    }

    let has_drive_id = remote
        .options
        .get("drive_id")
        .map(|value| !value.trim().is_empty())
        .unwrap_or(false);
    let has_drive_type = remote
        .options
        .get("drive_type")
        .map(|value| !value.trim().is_empty())
        .unwrap_or(false);
    if has_drive_id && has_drive_type {
        return Ok(());
    }

    let access_token = remote
        .token
        .as_ref()
        .and_then(|token| token.access_token.as_deref())
        .filter(|token| !token.trim().is_empty())
        .ok_or_else(|| {
            anyhow::anyhow!("OneDrive remote {} is missing an access token", remote_name)
        })?;

    let selection = resolve_drive(access_token).with_context(|| {
        format!(
            "Failed to resolve OneDrive drive details for {}",
            remote_name
        )
    })?;

    persist_remote_option_updates(
        config,
        remote_name,
        vec![
            ("drive_id".to_string(), selection.drive_id),
            ("drive_type".to_string(), selection.drive_type),
        ],
    )?;

    tracing::info!(remote = %remote_name, "Completed OneDrive remote setup");
    Ok(())
}

fn complete_onedrive_remote_setup(config: &RcloneConfig, remote_name: &str) -> Result<()> {
    complete_onedrive_remote_setup_with_resolver(
        config,
        remote_name,
        resolve_onedrive_drive_selection,
    )
}

pub(crate) fn complete_provider_remote_setup(
    provider: CloudProvider,
    config: &RcloneConfig,
    remote_name: &str,
) -> Result<()> {
    if provider == CloudProvider::OneDrive {
        complete_onedrive_remote_setup(config, remote_name)?;
    }

    Ok(())
}

fn authenticate_with_authorize_fallback(
    provider: CloudProvider,
    rclone: &RcloneRunner,
    config: &RcloneConfig,
    remote_name: &str,
) -> Result<AuthResult> {
    authenticate_with_system_browser(provider, rclone, config, remote_name)
        .with_context(|| format!("Fallback OAuth failed for {}", provider.display_name()))
}

/// Authenticate using rclone's built-in OAuth flow
pub fn authenticate_with_rclone(
    provider: CloudProvider,
    rclone: &RcloneRunner,
    config: &RcloneConfig,
    remote_name: &str,
) -> Result<AuthResult> {
    // Use rclone config create with a timeout. Without --non-interactive, rclone may
    // hang on post-OAuth interactive prompts when stdin is /dev/null.
    let args = build_rclone_auth_args(provider, remote_name, false);
    let args_ref: Vec<&str> = args.iter().map(String::as_str).collect();
    let output = rclone.run_with_timeout(&args_ref, Some(INTERACTIVE_AUTH_TIMEOUT))?;

    // If rclone hung (e.g., waiting for interactive prompts with stdin piped to null),
    // fall through to the authorize fallback.
    if output.timed_out {
        tracing::warn!(
            "rclone config create timed out for {}; trying fallback",
            provider
        );
        return authenticate_with_authorize_fallback(provider, rclone, config, remote_name);
    }

    if !output.success() {
        let primary_error = output.stderr_string();
        match authenticate_with_authorize_fallback(provider, rclone, config, remote_name) {
            Ok(result) => {
                tracing::warn!(
                    "Interactive rclone auth failed for {}; fallback authorize succeeded",
                    provider
                );
                return Ok(result);
            }
            Err(fallback_error) => {
                bail!(
                    "Failed to authenticate with {}: {} (fallback failed: {})",
                    provider,
                    primary_error,
                    fallback_error
                );
            }
        }
    }

    // Verify the remote was created
    if !config.has_remote(remote_name)? {
        bail!("Remote {} was not created", remote_name);
    }

    complete_provider_remote_setup(provider, config, remote_name)?;

    // Try to get user info from config
    let user_identifier = user_identifier_from_config(provider, config, remote_name);

    // Also try rclone about for additional info
    let about_info = get_user_info(rclone, remote_name).ok();
    let final_user_info = user_identifier.or(about_info);

    if final_user_info.is_none() {
        tracing::info!(
            provider = %provider.display_name(),
            remote = %remote_name,
            "Could not extract user identity (opaque token). Authentication succeeded but user is unknown."
        );
    }

    Ok(AuthResult {
        provider,
        remote_name: remote_name.to_string(),
        user_info: final_user_info,
        browser: None,
        was_silent: false,
    })
}

/// Authenticate using a mobile device (QR code + local callback)
pub fn authenticate_with_mobile(
    provider: CloudProvider,
    config: &RcloneConfig,
    remote_name: &str,
    port: u16,
) -> Result<AuthResult> {
    authenticate_with_mobile_redirect(provider, config, remote_name, port, Vec::new(), |lines| {
        for line in lines {
            println!("{}", line);
        }
        Ok(())
    })
}

/// Authenticate using a mobile device (QR code + LAN callback), with caller-controlled status output.
pub fn authenticate_with_mobile_redirect<F>(
    provider: CloudProvider,
    config: &RcloneConfig,
    remote_name: &str,
    port: u16,
    prelude_lines: Vec<String>,
    mut status: F,
) -> Result<AuthResult>
where
    F: FnMut(Vec<String>) -> Result<()>,
{
    let provider_config = ProviderConfig::for_provider(provider);

    if !provider_config.uses_oauth() {
        bail!(
            "{} does not use OAuth. Manual configuration required.",
            provider
        );
    }

    let custom = resolve_custom_oauth(provider);
    let client_id = custom
        .as_ref()
        .map(|c| c.client_id.as_str())
        .unwrap_or(provider_config.oauth.client_id);
    let client_secret = custom
        .as_ref()
        .and_then(|c| c.client_secret.as_deref())
        .filter(|s| !s.trim().is_empty())
        .or_else(|| {
            let secret = provider_config.oauth.client_secret;
            if secret.trim().is_empty() {
                None
            } else {
                Some(secret)
            }
        });

    let local_ip = get_local_ip_address()?
        .ok_or_else(|| anyhow::anyhow!("Unable to determine local IP address"))?;

    let oauth = OAuthFlow::new()
        .with_port(port)
        .with_timeout(Duration::from_secs(300))
        .with_bind_host(&local_ip)
        .with_redirect_host(local_ip.clone());

    let redirect_uri = oauth.redirect_uri();
    let state = OAuthFlow::generate_state();
    let auth_url =
        provider_config.build_auth_url_with_client_id(client_id, &redirect_uri, Some(&state));

    let mut lines = prelude_lines;
    lines.push(format!(
        "Mobile redirect authentication for {}",
        provider.display_name()
    ));
    lines.push("Phone must be on the same network as this PC.".to_string());
    lines.push(format!("Open on phone: {}", auth_url));
    lines.push(format!("Callback: {}", redirect_uri));
    if let Ok(qr) = render_qr_code(&auth_url) {
        lines.push("Scan this QR code:".to_string());
        lines.push(qr);
    }
    lines.push("Waiting for authorization callback...".to_string());
    status(lines)?;

    let result = oauth
        .wait_for_redirect_with_state(Some(&state))
        .with_context(|| format!("OAuth authentication failed for {}", provider))?;

    status(vec![
        "Authorization received. Exchanging token...".to_string()
    ])?;

    let token_json = exchange_code_for_token(
        provider_config.oauth.token_url,
        &result.code,
        &redirect_uri,
        client_id,
        client_secret,
    )?;
    let token_str = serde_json::to_string(&token_json)?;

    let mut options: Vec<(String, String)> = Vec::new();
    for (key, value) in provider_config.rclone_options {
        options.push(((*key).to_string(), (*value).to_string()));
    }
    if !client_id.trim().is_empty() {
        options.push(("client_id".to_string(), client_id.to_string()));
    }
    if let Some(secret) = client_secret {
        options.push(("client_secret".to_string(), secret.to_string()));
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

    complete_provider_remote_setup(provider, config, remote_name)?;

    let user_identifier = user_identifier_from_config(provider, config, remote_name);

    status(vec![format!("Remote '{}' configured.", remote_name)])?;

    Ok(AuthResult {
        provider,
        remote_name: remote_name.to_string(),
        user_info: user_identifier,
        browser: None,
        was_silent: false,
    })
}

/// Authenticate using device code flow (for providers that support it).
pub fn authenticate_with_device_code(
    provider: CloudProvider,
    config: &RcloneConfig,
    remote_name: &str,
) -> Result<AuthResult> {
    let provider_config = ProviderConfig::for_provider(provider);
    if !provider_config.uses_oauth() {
        bail!(
            "{} does not use OAuth. Manual configuration required.",
            provider
        );
    }

    let device_config = device_code_config(provider)?
        .ok_or_else(|| anyhow::anyhow!("Device code flow not supported for {}", provider))?;

    let device_info = request_device_code(&device_config)?;
    let verification = device_info
        .verification_uri_complete
        .clone()
        .unwrap_or_else(|| device_info.verification_uri.clone());

    println!("Device code authentication for {}", provider.display_name());
    println!("User code: {}", device_info.user_code);
    println!("Verify at: {}", device_info.verification_uri);
    if let Ok(qr) = render_qr_code(&verification) {
        println!("\nScan this QR code:\n{}", qr);
    }
    if let Some(message) = device_info.message.as_ref() {
        println!("{}", message);
    }
    println!("Waiting for authorization...");

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
        options.push(("client_secret".to_string(), secret));
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

    complete_provider_remote_setup(provider, config, remote_name)?;

    let user_identifier = user_identifier_from_config(provider, config, remote_name);

    Ok(AuthResult {
        provider,
        remote_name: remote_name.to_string(),
        user_info: user_identifier,
        browser: None,
        was_silent: false,
    })
}

/// Authenticate using a specific browser
///
/// This is useful for forensic scenarios where:
/// - Different browsers may have different logged-in sessions
/// - You want to capture multiple accounts from different browsers
pub fn authenticate_with_browser(
    provider: CloudProvider,
    browser: &Browser,
    rclone: &RcloneRunner,
    config: &RcloneConfig,
) -> Result<AuthResult> {
    if !browser.is_installed {
        bail!("Browser {} is not installed", browser.display_name());
    }

    let session = BrowserAuthSession::new(browser.clone(), provider.short_name());
    let temp_remote_name = session.remote_name(None);
    let provider_config = ProviderConfig::for_provider(provider);

    if !provider_config.uses_oauth() {
        bail!(
            "{} does not use OAuth. Manual configuration required.",
            provider.display_name()
        );
    }

    let auth_settings = resolve_browser_auth_settings(provider, &provider_config);

    let (token_str, used_rclone_authorize) = match auth_settings.strategy {
        BrowserAuthStrategy::DirectCodeExchange => (
            authenticate_with_browser_direct(
                provider,
                Some(browser),
                &provider_config,
                &auth_settings.client_id,
                auth_settings.client_secret.as_deref(),
            )?,
            false,
        ),
        BrowserAuthStrategy::ViaRcloneAuthorize => {
            match authenticate_with_browser_via_rclone(provider, Some(browser), rclone) {
                Ok(token) => (token, true),
                Err(error)
                    if provider == CloudProvider::OneDrive
                        && should_retry_onedrive_direct_browser_auth(&error) =>
                {
                    tracing::warn!(
                        provider = %provider.display_name(),
                        browser = %browser.display_name(),
                        error = %error,
                        "rclone authorize did not yield an auth URL for OneDrive; retrying with direct browser OAuth"
                    );

                    (
                        authenticate_with_browser_direct(
                            provider,
                            Some(browser),
                            &provider_config,
                            &auth_settings.client_id,
                            auth_settings.client_secret.as_deref(),
                        )
                        .context(
                            "Direct browser OAuth retry failed after rclone authorize did not yield an auth URL",
                        )?,
                        false,
                    )
                }
                Err(error) => return Err(error),
            }
        }
    };

    // Build config options
    let mut options: Vec<(String, String)> = Vec::new();
    for (key, value) in provider_config.rclone_options {
        options.push(((*key).to_string(), (*value).to_string()));
    }
    if !used_rclone_authorize {
        if !auth_settings.client_id.trim().is_empty() {
            options.push(("client_id".to_string(), auth_settings.client_id.clone()));
        }
        if let Some(secret) = auth_settings.client_secret.as_deref() {
            if !secret.trim().is_empty() {
                options.push(("client_secret".to_string(), secret.to_string()));
            }
        }
    }
    options.push(("token".to_string(), token_str));

    let options_ref: Vec<(&str, &str)> = options
        .iter()
        .map(|(k, v)| (k.as_str(), v.as_str()))
        .collect();

    config.set_remote(&temp_remote_name, provider.rclone_type(), &options_ref)?;

    if !config.has_remote(&temp_remote_name)? {
        bail!("Remote {} was not created", temp_remote_name);
    }

    complete_provider_remote_setup(provider, config, &temp_remote_name)?;

    let user_identifier = user_identifier_from_config(provider, config, &temp_remote_name);

    let final_remote_name = if let Some(ref username) = user_identifier {
        let new_name = session.remote_name(Some(username));
        if new_name != temp_remote_name {
            rename_remote(config, &temp_remote_name, &new_name)?;
            new_name
        } else {
            temp_remote_name
        }
    } else {
        temp_remote_name
    };

    Ok(AuthResult {
        provider,
        remote_name: final_remote_name,
        user_info: user_identifier,
        browser: Some(browser.clone()),
        was_silent: false,
    })
}

/// Authenticate interactively using the system default browser.
pub fn authenticate_with_system_browser(
    provider: CloudProvider,
    rclone: &RcloneRunner,
    config: &RcloneConfig,
    remote_name: &str,
) -> Result<AuthResult> {
    let provider_config = ProviderConfig::for_provider(provider);

    if !provider_config.uses_oauth() {
        bail!(
            "{} does not use OAuth. Manual configuration required.",
            provider.display_name()
        );
    }

    let auth_settings = resolve_browser_auth_settings(provider, &provider_config);

    let (token_str, used_rclone_authorize) = match auth_settings.strategy {
        BrowserAuthStrategy::DirectCodeExchange => (
            authenticate_with_browser_direct(
                provider,
                None,
                &provider_config,
                &auth_settings.client_id,
                auth_settings.client_secret.as_deref(),
            )?,
            false,
        ),
        BrowserAuthStrategy::ViaRcloneAuthorize => {
            match authenticate_with_browser_via_rclone(provider, None, rclone) {
                Ok(token) => (token, true),
                Err(error)
                    if provider == CloudProvider::OneDrive
                        && should_retry_onedrive_direct_browser_auth(&error) =>
                {
                    tracing::warn!(
                        provider = %provider.display_name(),
                        error = %error,
                        "rclone authorize did not yield an auth URL for OneDrive; retrying with direct system-browser OAuth"
                    );

                    (
                        authenticate_with_browser_direct(
                            provider,
                            None,
                            &provider_config,
                            &auth_settings.client_id,
                            auth_settings.client_secret.as_deref(),
                        )
                        .context(
                            "Direct system-browser OAuth retry failed after rclone authorize did not yield an auth URL",
                        )?,
                        false,
                    )
                }
                Err(error) => return Err(error),
            }
        }
    };

    let mut options: Vec<(String, String)> = Vec::new();
    for (key, value) in provider_config.rclone_options {
        options.push(((*key).to_string(), (*value).to_string()));
    }
    if !used_rclone_authorize {
        if !auth_settings.client_id.trim().is_empty() {
            options.push(("client_id".to_string(), auth_settings.client_id.clone()));
        }
        if let Some(secret) = auth_settings.client_secret.as_deref() {
            if !secret.trim().is_empty() {
                options.push(("client_secret".to_string(), secret.to_string()));
            }
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

    complete_provider_remote_setup(provider, config, remote_name)?;

    let user_identifier = user_identifier_from_config(provider, config, remote_name);

    Ok(AuthResult {
        provider,
        remote_name: remote_name.to_string(),
        user_info: user_identifier,
        browser: None,
        was_silent: false,
    })
}

/// Browser auth via `rclone authorize` — used when we don't have the provider's client_secret.
/// rclone knows its own built-in secrets and handles the token exchange internally.
fn authenticate_with_browser_via_rclone(
    provider: CloudProvider,
    browser: Option<&Browser>,
    rclone: &RcloneRunner,
) -> Result<String> {
    use crate::rclone::authorize::spawn_authorize;

    let mut running = spawn_authorize(rclone, provider.rclone_type(), true)?;

    let auth_url = match running.wait_for_auth_url(Duration::from_secs(20))? {
        Some(url) => url,
        None => {
            let finished = running.wait(Some(Duration::from_secs(1)))?;
            let mut details = Vec::new();

            if finished.timed_out {
                details.push("still running after waiting for the auth URL".to_string());
            } else if finished.status != 0 {
                details.push(format!("exit status {}", finished.status));
            }

            let stderr = finished.stderr.join("\n").trim().to_string();
            if !stderr.is_empty() {
                details.push(format!("stderr: {}", stderr));
            }

            let stdout = finished.stdout.join("\n").trim().to_string();
            if !stdout.is_empty() {
                details.push(format!("stdout: {}", stdout));
            }

            if details.is_empty() {
                bail!(
                    "rclone authorize did not produce an auth URL for {}",
                    provider.display_name()
                );
            }

            bail!(
                "rclone authorize did not produce an auth URL for {} ({})",
                provider.display_name(),
                details.join("; ")
            );
        }
    };

    open_browser_to_url(browser, &auth_url)?;

    let finished = running.wait(Some(INTERACTIVE_AUTH_TIMEOUT))?;

    if finished.timed_out {
        let recovery_hint = if provider == CloudProvider::OneDrive {
            " Try the Device Code flow from 'Authenticate from Mobile Device (QR Code)' if Microsoft sign-in keeps spinning."
        } else {
            ""
        };
        bail!(
            "Authentication timed out waiting for {} login via rclone authorize.{}",
            provider.display_name(),
            recovery_hint
        );
    }

    finished.token_json.ok_or_else(|| {
        let stderr = finished.stderr.join("\n");
        anyhow::anyhow!(
            "Failed to extract token from rclone authorize for {}. stderr: {}",
            provider.display_name(),
            stderr
        )
    })
}

/// Browser auth with Rust-side token exchange — used when we have the client_secret.
fn authenticate_with_browser_direct(
    provider: CloudProvider,
    browser: Option<&Browser>,
    provider_config: &ProviderConfig,
    client_id: &str,
    client_secret: Option<&str>,
) -> Result<String> {
    let oauth = OAuthFlow::new().with_timeout(INTERACTIVE_AUTH_TIMEOUT);
    let redirect_uri = oauth.redirect_uri();
    let state = OAuthFlow::generate_state();
    let auth_url =
        provider_config.build_auth_url_with_client_id(client_id, &redirect_uri, Some(&state));

    open_browser_to_url(browser, &auth_url)?;

    let result = oauth
        .wait_for_redirect_with_state(Some(&state))
        .with_context(|| {
            format!(
                "OAuth authentication failed for {}",
                provider.display_name()
            )
        })?;

    let token_json = exchange_code_for_token(
        provider_config.oauth.token_url,
        &result.code,
        &redirect_uri,
        client_id,
        client_secret,
    )?;
    serde_json::to_string(&token_json).context("Failed to serialize token")
}

fn open_browser_to_url(browser: Option<&Browser>, url: &str) -> Result<()> {
    if let Some(browser) = browser {
        if browser.executable_path.is_some() {
            browser
                .open_url(url)
                .with_context(|| format!("Failed to open {}", browser.display_name()))?;
        } else {
            open::that(url).with_context(|| "Failed to open system default browser")?;
        }
    } else {
        open::that(url).with_context(|| "Failed to open system default browser")?;
    }
    Ok(())
}

/// Get available browsers for authentication
pub fn get_available_browsers() -> Vec<Browser> {
    BrowserDetector::detect_all()
}

/// Get the default browser
pub fn get_default_browser() -> Option<Browser> {
    BrowserDetector::get_default_browser()
}

/// Rename a remote in the config
fn rename_remote(config: &RcloneConfig, old_name: &str, new_name: &str) -> Result<()> {
    let parsed = config.parse()?;
    let remote = parsed
        .get_remote(old_name)
        .ok_or_else(|| anyhow::anyhow!("Remote {} not found", old_name))?;

    // Build options list
    let mut options: Vec<(String, String)> = remote.options.clone().into_iter().collect();

    // Add token if present
    if let Some(ref token) = remote.token {
        let token_json = serde_json::to_string(token)?;
        options.push(("token".to_string(), token_json));
    }

    // Convert to the format set_remote expects
    let options_ref: Vec<(&str, &str)> = options
        .iter()
        .map(|(k, v)| (k.as_str(), v.as_str()))
        .collect();

    // Create new remote
    config.set_remote(new_name, &remote.remote_type, &options_ref)?;

    // Remove old remote
    config.remove_remote(old_name)?;

    Ok(())
}

/// Get user information from an authenticated remote
fn get_user_info(rclone: &RcloneRunner, remote_name: &str) -> Result<String> {
    let output = rclone.run(&["about", &format!("{}:", remote_name), "--json"])?;

    if output.success() {
        // Parse JSON to extract user info
        let json: serde_json::Value = serde_json::from_str(&output.stdout_string())?;
        if let Some(used) = json.get("used") {
            return Ok(format!("Storage used: {} bytes", used));
        }
    }

    bail!("Could not get user info")
}

// ============= SSO/Silent Authentication =============

/// Detect available SSO sessions for a provider
///
/// Scans installed browsers to find those with valid authentication
/// sessions for the specified provider. This enables "silent" authentication
/// where the user doesn't need to re-enter credentials.
pub fn detect_sso_sessions(provider: CloudProvider) -> SsoStatus {
    let sessions = browsers_with_sessions(provider);
    let has_sessions = !sessions.is_empty();

    // Recommend the first browser with a valid session
    // Priority: default browser > others
    let recommended = if has_sessions {
        // Try to find the default browser among those with sessions
        let default_browser = BrowserDetector::get_default_browser();
        if let Some(ref default) = default_browser {
            sessions
                .iter()
                .find(|(b, _)| b.browser_type == default.browser_type)
                .map(|(b, _)| b.clone())
        } else {
            sessions.first().map(|(b, _)| b.clone())
        }
        .or_else(|| sessions.first().map(|(b, _)| b.clone()))
    } else {
        None
    };

    SsoStatus {
        provider,
        browsers_with_sessions: sessions,
        has_sessions,
        recommended_browser: recommended,
    }
}

/// Authenticate using a browser with an existing session (SSO)
///
/// The browser should have an active session detected via `detect_sso_sessions`.
/// Authentication will typically complete without user interaction.
pub fn authenticate_with_sso(
    provider: CloudProvider,
    browser: &Browser,
    session: &BrowserSession,
    rclone: &RcloneRunner,
    config: &RcloneConfig,
) -> Result<AuthResult> {
    if !session.is_valid {
        bail!("Browser session is not valid for {}", provider);
    }

    // Generate remote name using session user hint if available
    let remote_name = if let Some(ref user) = session.user_hint {
        format!(
            "{}-{}-{}",
            browser.short_name(),
            provider.short_name(),
            user.replace('@', "_at_").replace('.', "_")
        )
    } else {
        format!("{}-{}", browser.short_name(), provider.short_name())
    };

    tracing::info!(
        "Attempting SSO authentication for {} via {} (user hint: {:?})",
        provider,
        browser.display_name(),
        session.user_hint
    );

    // Use rclone config create - the browser already has the session,
    // so OAuth should complete quickly/silently
    let args = build_rclone_auth_args(provider, &remote_name, false);
    let args_ref: Vec<&str> = args.iter().map(String::as_str).collect();
    let output = run_rclone_with_browser_env(browser, rclone, &args_ref)?;

    if !output.success() {
        bail!(
            "SSO authentication failed for {} with {}: {}",
            provider,
            browser.display_name(),
            output.stderr_string()
        );
    }

    // Verify remote was created
    if !config.has_remote(&remote_name)? {
        bail!("Remote {} was not created", remote_name);
    }

    complete_provider_remote_setup(provider, config, &remote_name)?;

    // Get user info from config token if supported, otherwise fall back to hint.
    let user_identifier = user_identifier_from_config(provider, config, &remote_name)
        .or_else(|| session.user_hint.clone());

    Ok(AuthResult {
        provider,
        remote_name,
        user_info: user_identifier,
        browser: Some(browser.clone()),
        was_silent: true, // This is SSO/silent auth
    })
}

/// Smart authentication that tries SSO first, falls back to interactive
///
/// This is the recommended authentication method for forensic scenarios:
/// 1. Check for existing browser sessions
/// 2. If found, try silent authentication
/// 3. If no sessions or SSO fails, fall back to normal interactive auth
pub fn smart_authenticate(
    provider: CloudProvider,
    rclone: &RcloneRunner,
    config: &RcloneConfig,
    remote_name: &str,
) -> Result<AuthResult> {
    // Step 1: Detect SSO sessions
    let sso_status = detect_sso_sessions(provider);

    if sso_status.has_sessions {
        tracing::info!(
            "Found {} browser(s) with {} sessions",
            sso_status.browsers_with_sessions.len(),
            provider
        );

        // Step 2: Try SSO with browsers that have sessions
        for (browser, session) in &sso_status.browsers_with_sessions {
            match authenticate_with_sso(provider, browser, session, rclone, config) {
                Ok(result) => {
                    tracing::info!(
                        "SSO authentication succeeded for {} via {}",
                        provider,
                        browser.display_name()
                    );
                    return Ok(result);
                }
                Err(e) => {
                    tracing::warn!(
                        "SSO authentication failed for {} via {}: {}",
                        provider,
                        browser.display_name(),
                        e
                    );
                    // Continue to try other browsers
                }
            }
        }

        tracing::info!("All SSO attempts failed, falling back to interactive auth");
    } else {
        tracing::info!(
            "No existing {} sessions found, using interactive auth",
            provider
        );
    }

    // Step 3: Fall back to normal authentication
    authenticate_with_rclone(provider, rclone, config, remote_name)
}

/// Authenticate using a user-selected browser
///
/// Uses the explicit browser/profile launch path so the chosen browser profile
/// is actually honored during OAuth.
pub fn authenticate_with_browser_choice(
    provider: CloudProvider,
    browser: &Browser,
    rclone: &RcloneRunner,
    config: &RcloneConfig,
) -> Result<AuthResult> {
    authenticate_with_browser(provider, browser, rclone, config)
}

/// Get SSO status summary for display in TUI
pub fn get_sso_summary(provider: CloudProvider) -> String {
    let status = detect_sso_sessions(provider);

    if status.has_sessions {
        let browsers: Vec<_> = status
            .browsers_with_sessions
            .iter()
            .map(|(b, s)| {
                if let Some(ref hint) = s.user_hint {
                    format!("{} ({})", b.display_name(), hint)
                } else {
                    b.display_name().to_string()
                }
            })
            .collect();
        format!("Active sessions in: {}", browsers.join(", "))
    } else {
        "No active sessions found".to_string()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_auth_result() {
        let result = AuthResult {
            provider: CloudProvider::GoogleDrive,
            remote_name: "test".to_string(),
            user_info: Some("test@example.com".to_string()),
            browser: None,
            was_silent: false,
        };
        assert_eq!(result.provider, CloudProvider::GoogleDrive);
        assert_eq!(result.remote_name, "test");
        assert!(!result.was_silent);
    }

    #[test]
    fn test_browser_auth_session_naming() {
        let browser = Browser::new(super::super::browser::BrowserType::Chrome);
        let session = BrowserAuthSession::new(browser, "gdrive");

        assert_eq!(session.remote_name(None), "chrome-gdrive");
        assert_eq!(
            session.remote_name(Some("user@example.com")),
            "chrome-gdrive-user@example.com"
        );
    }

    #[test]
    fn test_get_available_browsers() {
        // Should not panic
        let browsers = get_available_browsers();
        // Can't assert specific browsers, but can check it returns a vec
        assert!(browsers.iter().all(|b| b.is_installed));
    }

    #[test]
    fn test_sso_status() {
        let status = SsoStatus {
            provider: CloudProvider::GoogleDrive,
            browsers_with_sessions: vec![],
            has_sessions: false,
            recommended_browser: None,
        };
        assert_eq!(status.provider, CloudProvider::GoogleDrive);
        assert!(!status.has_sessions);
    }

    #[test]
    fn test_select_browser_auth_strategy_without_secret_or_custom_uses_rclone_authorize() {
        assert_eq!(
            select_browser_auth_strategy(CloudProvider::GoogleDrive, false, false),
            BrowserAuthStrategy::ViaRcloneAuthorize
        );
    }

    #[test]
    fn test_select_browser_auth_strategy_with_secret_uses_direct() {
        assert_eq!(
            select_browser_auth_strategy(CloudProvider::GoogleDrive, true, false),
            BrowserAuthStrategy::DirectCodeExchange
        );
    }

    #[test]
    fn test_select_browser_auth_strategy_for_google_photos_prefers_rclone_authorize() {
        assert_eq!(
            select_browser_auth_strategy(CloudProvider::GooglePhotos, true, false),
            BrowserAuthStrategy::ViaRcloneAuthorize
        );
    }

    #[test]
    fn test_should_retry_onedrive_direct_browser_auth_for_missing_auth_url() {
        let error = anyhow::anyhow!(
            "rclone authorize did not produce an auth URL for Microsoft OneDrive"
        );

        assert!(should_retry_onedrive_direct_browser_auth(&error));
    }

    #[test]
    fn test_should_not_retry_onedrive_direct_browser_auth_for_other_errors() {
        let error = anyhow::anyhow!("OAuth error: access_denied");

        assert!(!should_retry_onedrive_direct_browser_auth(&error));
    }

    #[test]
    fn test_resolve_browser_auth_settings_for_onedrive_default_config_uses_rclone_authorize() {
        let provider_config = ProviderConfig::for_provider(CloudProvider::OneDrive);
        let settings = resolve_browser_auth_settings_with_custom(&provider_config, None);

        assert_eq!(settings.strategy, BrowserAuthStrategy::ViaRcloneAuthorize);
        assert_eq!(settings.client_id, provider_config.oauth.client_id);
        assert_eq!(settings.client_secret, None);
    }

    #[test]
    fn test_resolve_browser_auth_settings_for_google_drive_default_config_uses_direct() {
        let provider_config = ProviderConfig::for_provider(CloudProvider::GoogleDrive);
        let settings = resolve_browser_auth_settings_with_custom(&provider_config, None);

        assert_eq!(settings.strategy, BrowserAuthStrategy::DirectCodeExchange);
        assert_eq!(settings.client_id, provider_config.oauth.client_id);
        assert_eq!(
            settings.client_secret.as_deref(),
            Some(provider_config.oauth.client_secret)
        );
    }

    #[test]
    fn test_resolve_browser_auth_settings_for_google_photos_default_config_uses_rclone_authorize() {
        let provider_config = ProviderConfig::for_provider(CloudProvider::GooglePhotos);
        let settings = resolve_browser_auth_settings_with_custom(&provider_config, None);

        assert_eq!(settings.strategy, BrowserAuthStrategy::ViaRcloneAuthorize);
    }

    #[test]
    fn test_resolve_browser_auth_settings_with_custom_public_client_uses_direct() {
        let provider_config = ProviderConfig::for_provider(CloudProvider::OneDrive);
        let settings = resolve_browser_auth_settings_with_custom(
            &provider_config,
            Some(OAuthCredentials {
                client_id: "custom-client-id".to_string(),
                client_secret: None,
            }),
        );

        assert_eq!(settings.strategy, BrowserAuthStrategy::DirectCodeExchange);
        assert_eq!(settings.client_id, "custom-client-id");
        assert_eq!(settings.client_secret, None);
    }

    #[test]
    fn test_parse_onedrive_drive_selection_response() {
        let selection =
            parse_onedrive_drive_selection_response(r#"{"id":"drive-123","driveType":"business"}"#)
                .unwrap();

        assert_eq!(selection.drive_id, "drive-123");
        assert_eq!(selection.drive_type, "business");
    }

    #[test]
    fn test_complete_onedrive_remote_setup_persists_drive_details() {
        use tempfile::tempdir;

        let dir = tempdir().unwrap();
        let config = RcloneConfig::new(dir.path().join("rclone.conf")).unwrap();
        config
            .set_remote(
                "onedrive-test",
                CloudProvider::OneDrive.rclone_type(),
                &[(
                    "token",
                    r#"{"access_token":"token-123","refresh_token":"refresh-456","token_type":"Bearer"}"#,
                )],
            )
            .unwrap();

        complete_onedrive_remote_setup_with_resolver(&config, "onedrive-test", |_token| {
            Ok(OneDriveDriveSelection {
                drive_id: "drive-123".to_string(),
                drive_type: "business".to_string(),
            })
        })
        .unwrap();

        let parsed = config.parse().unwrap();
        let remote = parsed.get_remote("onedrive-test").unwrap();
        assert_eq!(
            remote.options.get("drive_id").map(String::as_str),
            Some("drive-123")
        );
        assert_eq!(
            remote.options.get("drive_type").map(String::as_str),
            Some("business")
        );
    }

    #[test]
    fn test_complete_onedrive_remote_setup_skips_resolver_when_drive_already_present() {
        use tempfile::tempdir;

        let dir = tempdir().unwrap();
        let config = RcloneConfig::new(dir.path().join("rclone.conf")).unwrap();
        config
            .set_remote(
                "onedrive-test",
                CloudProvider::OneDrive.rclone_type(),
                &[
                    (
                        "token",
                        r#"{"access_token":"token-123","token_type":"Bearer"}"#,
                    ),
                    ("drive_id", "drive-123"),
                    ("drive_type", "personal"),
                ],
            )
            .unwrap();

        complete_onedrive_remote_setup_with_resolver(&config, "onedrive-test", |_token| {
            panic!("resolver should not be called when drive details already exist")
        })
        .unwrap();
    }
}
