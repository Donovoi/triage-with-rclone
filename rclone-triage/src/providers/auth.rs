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
use super::session::{browsers_with_sessions, BrowserSession, SessionExtractor};
use super::{config::ProviderConfig, CloudProvider};
use crate::rclone::{authorize_fallback, OAuthFlow, RcloneConfig, RcloneRunner};
use crate::utils::network::get_local_ip_address;
use anyhow::{bail, Context, Result};
use std::time::Duration;

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

fn parse_redirect_host_port(redirect_uri: &str) -> Option<(String, u16)> {
    let trimmed = redirect_uri.trim();
    let stripped = trimmed
        .strip_prefix("http://")
        .or_else(|| trimmed.strip_prefix("https://"))?;
    let host_port = stripped.split('/').next().unwrap_or(stripped);
    if let Some((host, port_str)) = host_port.split_once(':') {
        if let Ok(port) = port_str.parse::<u16>() {
            return Some((host.to_string(), port));
        }
    }
    Some((
        host_port.to_string(),
        crate::rclone::oauth::DEFAULT_OAUTH_PORT,
    ))
}

fn resolve_fallback_credentials(
    provider: CloudProvider,
    provider_config: &ProviderConfig,
    client_id_from_url: Option<&str>,
) -> (String, Option<String>) {
    let custom = resolve_custom_oauth(provider);
    let client_id = client_id_from_url
        .filter(|s| !s.trim().is_empty())
        .map(|s| s.to_string())
        .or_else(|| custom.as_ref().map(|c| c.client_id.clone()))
        .unwrap_or_else(|| provider_config.oauth.client_id.to_string());

    let mut client_secret = custom
        .and_then(|c| {
            if c.client_id.trim() == client_id {
                c.client_secret
            } else {
                None
            }
        })
        .filter(|s| !s.trim().is_empty());

    if client_secret.is_none() {
        let secret = provider_config.oauth.client_secret;
        if !secret.trim().is_empty() {
            client_secret = Some(secret.to_string());
        }
    }

    (client_id, client_secret)
}

fn authenticate_with_authorize_fallback(
    provider: CloudProvider,
    rclone: &RcloneRunner,
    config: &RcloneConfig,
    remote_name: &str,
) -> Result<AuthResult> {
    let provider_config = ProviderConfig::for_provider(provider);
    if !provider_config.uses_oauth() {
        bail!(
            "{} does not use OAuth. Fallback authorization is not supported.",
            provider.display_name()
        );
    }

    let fallback = authorize_fallback(rclone, provider.rclone_type(), Duration::from_secs(15))?;
    let auth_url = fallback
        .auth_url
        .ok_or_else(|| anyhow::anyhow!("Fallback did not capture an auth URL"))?;

    let auth_url = ensure_oauth_url_has_state(&auth_url);

    let redirect_uri = crate::rclone::oauth::extract_param(&auth_url, "redirect_uri")
        .unwrap_or_else(|| OAuthFlow::new().redirect_uri());
    let mut oauth = OAuthFlow::new();
    if let Some((host, port)) = parse_redirect_host_port(&redirect_uri) {
        oauth = oauth
            .with_port(port)
            .with_bind_host(host.clone())
            .with_redirect_host(host);
    }

    let result = oauth
        .run(&auth_url)
        .with_context(|| format!("Fallback OAuth failed for {}", provider.display_name()))?;

    let client_id_from_url = crate::rclone::oauth::extract_param(&auth_url, "client_id");
    let (client_id, client_secret) =
        resolve_fallback_credentials(provider, &provider_config, client_id_from_url.as_deref());

    let token_json = exchange_code_for_token(
        provider_config.oauth.token_url,
        &result.code,
        &redirect_uri,
        &client_id,
        client_secret.as_deref(),
    )?;
    let token_str = serde_json::to_string(&token_json)?;

    let mut options: Vec<(String, String)> = Vec::new();
    for (key, value) in provider_config.rclone_options {
        options.push(((*key).to_string(), (*value).to_string()));
    }
    if !client_id.trim().is_empty() {
        options.push(("client_id".to_string(), client_id));
    }
    if let Some(secret) = client_secret {
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

    Ok(AuthResult {
        provider,
        remote_name: remote_name.to_string(),
        user_info: user_identifier,
        browser: None,
        was_silent: false,
    })
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
    let output = rclone.run_with_timeout(&args_ref, Some(Duration::from_secs(120)))?;

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

fn ensure_oauth_url_has_state(auth_url: &str) -> String {
    if crate::rclone::oauth::extract_param(auth_url, "state").is_some() {
        return auth_url.to_string();
    }

    let state = OAuthFlow::generate_state();
    let (before_fragment, fragment) = auth_url.split_once('#').unwrap_or((auth_url, ""));
    let sep = if before_fragment.contains('?') {
        "&"
    } else {
        "?"
    };
    let mut out = format!("{}{}state={}", before_fragment, sep, state);
    if !fragment.is_empty() {
        out.push('#');
        out.push_str(fragment);
    }
    out
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
    _rclone: &RcloneRunner,
    config: &RcloneConfig,
) -> Result<AuthResult> {
    if !browser.is_installed {
        bail!("Browser {} is not installed", browser.display_name());
    }

    let session = BrowserAuthSession::new(browser.clone(), provider.short_name());

    // Generate remote name based on browser and provider
    // We'll get the actual username after authentication
    let temp_remote_name = session.remote_name(None);

    // Use the app's own OAuth flow instead of rclone config create.
    // rclone config create hangs when stdin is /dev/null because it waits
    // for interactive prompts after the OAuth callback.
    let provider_config = ProviderConfig::for_provider(provider);

    if !provider_config.uses_oauth() {
        bail!(
            "{} does not use OAuth. Manual configuration required.",
            provider.display_name()
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
            let s = provider_config.oauth.client_secret;
            if s.trim().is_empty() {
                None
            } else {
                Some(s)
            }
        });

    let oauth = OAuthFlow::new();
    let redirect_uri = oauth.redirect_uri();
    let state = OAuthFlow::generate_state();
    let auth_url =
        provider_config.build_auth_url_with_client_id(client_id, &redirect_uri, Some(&state));

    // Open the auth URL in the selected browser
    if let Some(ref path) = browser.executable_path {
        std::process::Command::new(path)
            .arg(&auth_url)
            .stdin(std::process::Stdio::null())
            .stdout(std::process::Stdio::null())
            .stderr(std::process::Stdio::null())
            .spawn()
            .with_context(|| format!("Failed to open browser: {}", path.display()))?;
    } else {
        open::that(&auth_url).with_context(|| "Failed to open system default browser")?;
    }

    // Wait for the OAuth callback
    let result = oauth
        .wait_for_redirect_with_state(Some(&state))
        .with_context(|| {
            format!(
                "OAuth authentication failed for {}",
                provider.display_name()
            )
        })?;

    // Exchange code for token
    let token_json = exchange_code_for_token(
        provider_config.oauth.token_url,
        &result.code,
        &redirect_uri,
        client_id,
        client_secret,
    )?;
    let token_str = serde_json::to_string(&token_json)?;

    // Build config options
    let mut options: Vec<(String, String)> = Vec::new();
    for (key, value) in provider_config.rclone_options {
        options.push(((*key).to_string(), (*value).to_string()));
    }
    if !client_id.trim().is_empty() {
        options.push(("client_id".to_string(), client_id.to_string()));
    }
    if let Some(secret) = client_secret {
        if !secret.trim().is_empty() {
            options.push(("client_secret".to_string(), secret.to_string()));
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

    // Try to extract user info from the token
    let user_identifier = user_identifier_from_config(provider, config, &temp_remote_name);

    // If we got a user identifier, rename the remote to include it
    let final_remote_name = if let Some(ref username) = user_identifier {
        let new_name = session.remote_name(Some(username));

        // Rename the remote if different
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
/// Tries SSO with that browser if a valid session exists,
/// otherwise falls back to interactive auth in that browser.
pub fn authenticate_with_browser_choice(
    provider: CloudProvider,
    browser: &Browser,
    rclone: &RcloneRunner,
    config: &RcloneConfig,
) -> Result<AuthResult> {
    if let Ok(extractor) = SessionExtractor::new() {
        if let Ok(session) = extractor.extract_session(browser, provider) {
            if session.is_valid {
                if let Ok(result) =
                    authenticate_with_sso(provider, browser, &session, rclone, config)
                {
                    return Ok(result);
                }
            }
        }
    }

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
    fn test_parse_redirect_host_port() {
        let (host, port) = parse_redirect_host_port("http://127.0.0.1:53682/").unwrap();
        assert_eq!(host, "127.0.0.1");
        assert_eq!(port, 53682);

        let (host, port) = parse_redirect_host_port("https://localhost:8888/callback").unwrap();
        assert_eq!(host, "localhost");
        assert_eq!(port, 8888);
    }
}
