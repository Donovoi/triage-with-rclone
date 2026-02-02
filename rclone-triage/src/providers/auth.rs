//! Provider authentication
//!
//! Handles OAuth authentication flow for each provider.
//! Supports multi-browser authentication for forensic scenarios.
//! Includes SSO/Silent authentication by detecting existing browser sessions.

use super::browser::{Browser, BrowserAuthSession, BrowserDetector};
use super::session::{browsers_with_sessions, BrowserSession};
use super::{config::ProviderConfig, CloudProvider};
use crate::rclone::{OAuthFlow, RcloneConfig, RcloneRunner};
use anyhow::{bail, Context, Result};

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

/// Authenticate to a cloud provider
pub fn authenticate(
    provider: CloudProvider,
    rclone: &RcloneRunner,
    config: &RcloneConfig,
    remote_name: &str,
) -> Result<AuthResult> {
    let provider_config = ProviderConfig::for_provider(provider);

    if !provider_config.uses_oauth() {
        // iCloud uses username/password
        bail!(
            "{} does not use OAuth. Manual configuration required.",
            provider
        );
    }

    // Run OAuth flow
    let oauth = OAuthFlow::new();
    let redirect_uri = oauth.redirect_uri();
    let auth_url = provider_config.build_auth_url(&redirect_uri, None);

    println!("Opening browser for {} authentication...", provider);
    let _result = oauth
        .run(&auth_url)
        .with_context(|| format!("OAuth authentication failed for {}", provider))?;

    // Use rclone to complete the config with the auth code
    // rclone config create <name> <type> config_token=<token>
    let output = rclone.run(&[
        "config",
        "create",
        remote_name,
        provider.rclone_type(),
        "--non-interactive",
    ])?;

    if !output.success() {
        bail!("Failed to create rclone remote: {}", output.stderr_string());
    }

    // Verify the remote was created
    if !config.has_remote(remote_name)? {
        bail!("Remote {} was not created in config", remote_name);
    }

    Ok(AuthResult {
        provider,
        remote_name: remote_name.to_string(),
        user_info: None,
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
    // Use rclone config create with interactive OAuth
    let output = rclone.run(&["config", "create", remote_name, provider.rclone_type()])?;

    if !output.success() {
        bail!(
            "Failed to authenticate with {}: {}",
            provider,
            output.stderr_string()
        );
    }

    // Verify the remote was created
    if !config.has_remote(remote_name)? {
        bail!("Remote {} was not created", remote_name);
    }

    // Try to get user info from config
    let user_info = config.get_user_info(remote_name).ok().flatten();
    let user_identifier = user_info.and_then(|u| u.best_identifier());

    // Also try rclone about for additional info
    let about_info = get_user_info(rclone, remote_name).ok();
    let final_user_info = user_identifier.or(about_info);

    Ok(AuthResult {
        provider,
        remote_name: remote_name.to_string(),
        user_info: final_user_info,
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

    // Generate remote name based on browser and provider
    // We'll get the actual username after authentication
    let temp_remote_name = session.remote_name(None);

    // Authenticate using rclone's flow
    // The default browser will be used by rclone - we track which browser was intended
    let output = rclone.run(&[
        "config",
        "create",
        &temp_remote_name,
        provider.rclone_type(),
    ])?;

    if !output.success() {
        bail!(
            "Failed to authenticate {} with {}: {}",
            provider,
            browser.display_name(),
            output.stderr_string()
        );
    }

    // Verify the remote was created
    if !config.has_remote(&temp_remote_name)? {
        bail!("Remote {} was not created", temp_remote_name);
    }

    // Try to extract user info from the token
    let user_info = config.get_user_info(&temp_remote_name).ok().flatten();
    let user_identifier = user_info.and_then(|u| u.best_identifier());

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

/// Authenticate to all installed browsers for a provider
///
/// Returns a list of successfully authenticated remotes.
/// Useful for capturing all possible accounts across browsers.
pub fn authenticate_all_browsers(
    provider: CloudProvider,
    rclone: &RcloneRunner,
    config: &RcloneConfig,
) -> Vec<AuthResult> {
    let browsers = BrowserDetector::detect_all();
    let mut results = Vec::new();

    for browser in browsers {
        match authenticate_with_browser(provider, &browser, rclone, config) {
            Ok(result) => {
                tracing::info!(
                    "Authenticated {} with browser {}",
                    provider,
                    browser.display_name()
                );
                results.push(result);
            }
            Err(e) => {
                tracing::warn!(
                    "Failed to authenticate {} with browser {}: {}",
                    provider,
                    browser.display_name(),
                    e
                );
            }
        }
    }

    results
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

/// Check if a remote is already authenticated
pub fn is_authenticated(config: &RcloneConfig, remote_name: &str) -> Result<bool> {
    config.has_remote(remote_name)
}

/// List all authenticated remotes for a provider
pub fn list_authenticated_remotes(
    config: &RcloneConfig,
    provider: CloudProvider,
) -> Result<Vec<String>> {
    let parsed = config.parse()?;
    let remotes = parsed.remotes_by_type(provider.rclone_type());
    Ok(remotes.iter().map(|r| r.name.clone()).collect())
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
    let output = rclone.run(&["config", "create", &remote_name, provider.rclone_type()])?;

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

    // Get user info from config token
    let user_info = config.get_user_info(&remote_name).ok().flatten();
    let user_identifier = user_info
        .and_then(|u| u.best_identifier())
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
}
