//! Credential creation without account discovery, connectivity probes or listings.

use super::*;
use crate::providers::mobile::{
    device_code_config_with_credentials, poll_device_code_for_token_with_cancel, DeviceCodeConfig,
};
use std::sync::atomic::{AtomicBool, Ordering};

/// Explicit interactive flow used by the CLI's metadata-free authentication path.
#[derive(Clone, Copy, Debug)]
pub enum AuthOnlyFlow {
    SystemBrowser,
    ManualBrowser,
    DeviceCode,
}

/// Authenticate and persist a remote without discovering accounts or reading files.
/// OneDrive drive_id/drive_type and an optional folder root are configured separately.
pub fn authenticate_only(
    provider: CloudProvider,
    flow: AuthOnlyFlow,
    config: &RcloneConfig,
    remote_name: &str,
    cancel: &AtomicBool,
) -> Result<AuthResult> {
    // Load once and propagate errors: malformed custom credentials must never
    // silently select a different OAuth registration.
    let custom = custom_oauth_credentials_for(provider)?;
    authenticate_only_with(
        provider,
        config,
        remote_name,
        custom.as_ref(),
        cancel,
        |settings, provider_config| {
            match flow {
                AuthOnlyFlow::DeviceCode => {
                    let device = device_code_config_with_credentials(provider, custom.clone())?
                        .ok_or_else(|| {
                            anyhow::anyhow!("Device code flow is unavailable for {}", provider)
                        })?;
                    authorize_device_only(&device, cancel)
                }
                AuthOnlyFlow::SystemBrowser | AuthOnlyFlow::ManualBrowser => {
                    // This path deliberately owns its listener instead of invoking
                    // rclone authorize or trying browser/profile SSO discovery.
                    let oauth = OAuthFlow::new().with_timeout(INTERACTIVE_AUTH_TIMEOUT);
                    let redirect_uri = oauth.redirect_uri();
                    let state = OAuthFlow::generate_state();
                    let pkce = Pkce::new();
                    let auth_url =
                        pkce.authorize_url(&provider_config.build_auth_url_with_client_id(
                            &settings.client_id,
                            &redirect_uri,
                            Some(&state),
                        ));
                    let response = oauth.run_with_opener_cancellable(&auth_url, cancel, |url| {
                        if matches!(flow, AuthOnlyFlow::ManualBrowser) {
                            // Bind precedes this output. The URL includes one-time
                            // state; callers must keep captured stdout private.
                            println!("Open authorization URL: {}", url);
                            println!("Waiting for authorization callback...");
                            Ok(())
                        } else {
                            open_browser_to_url(None, url)
                        }
                    })?;
                    check_cancel(cancel)?;
                    let token = exchange_code_for_token_with_pkce(
                        provider_config.oauth.token_url,
                        &response.code,
                        &redirect_uri,
                        &settings.client_id,
                        settings.client_secret.as_deref(),
                        Some(pkce.verifier()),
                    )?;
                    serde_json::to_string(&token).context("Failed to serialize token")
                }
            }
        },
    )
}

fn authorize_device_only(device: &DeviceCodeConfig, cancel: &AtomicBool) -> Result<String> {
    check_cancel(cancel)?;
    let challenge = request_device_code(device)?;
    check_cancel(cancel)?;
    println!("User code: {}", challenge.user_code);
    println!("Verify at: {}", challenge.verification_uri);
    println!("Waiting for authorization...");
    let token = poll_device_code_for_token_with_cancel(
        device,
        &challenge.device_code,
        challenge.interval,
        challenge.expires_in,
        Some(cancel),
    )?;
    serde_json::to_string(&token).context("Failed to serialize token")
}

fn authenticate_only_with<F>(
    provider: CloudProvider,
    config: &RcloneConfig,
    remote_name: &str,
    custom: Option<&OAuthCredentials>,
    cancel: &AtomicBool,
    authorize: F,
) -> Result<AuthResult>
where
    F: FnOnce(&ResolvedBrowserAuthSettings, &ProviderConfig) -> Result<String>,
{
    check_cancel(cancel)?;
    if !matches!(
        provider,
        CloudProvider::GoogleDrive | CloudProvider::OneDrive
    ) {
        bail!("--auth-only currently supports Google Drive and OneDrive");
    }
    ensure_new_auth_credentials_with_custom(provider, custom)?;
    let provider_config = ProviderConfig::for_provider(provider);
    if provider == CloudProvider::OneDrive
        && !custom.is_some_and(|credentials| {
            !credentials.client_id.trim().is_empty()
                && !credentials
                    .client_id
                    .trim()
                    .eq_ignore_ascii_case(provider_config.oauth.client_id)
        })
    {
        bail!("Auth-only OneDrive requires your own OAuth client registration in RCLONE_TRIAGE_OAUTH_CONFIG; the bundled registration needs rclone-managed authorization");
    }
    let settings = resolve_browser_auth_settings_with_custom(&provider_config, custom.cloned());
    let token = authorize(&settings, &provider_config)?;
    check_cancel(cancel)?;
    let mut options: Vec<(&str, &str)> = provider_config.rclone_options.to_vec();
    options.push(("client_id", settings.client_id.as_str()));
    if let Some(secret) = settings.client_secret.as_deref() {
        options.push(("client_secret", secret));
    }
    options.push(("token", token.as_str()));
    config.set_remote(remote_name, provider.rclone_type(), &options)?;
    // No complete_provider_remote_setup, user-info, rclone runner or listing here.
    Ok(AuthResult {
        provider,
        remote_name: remote_name.to_string(),
        user_info: None,
        browser: None,
        was_silent: false,
    })
}

fn check_cancel(cancel: &AtomicBool) -> Result<()> {
    if cancel.load(Ordering::Relaxed) {
        bail!("Authorization cancelled");
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn auth_only_requires_own_onedrive_client_before_authorization() {
        let dir = tempfile::tempdir().unwrap();
        let config = RcloneConfig::new(dir.path().join("rclone.conf")).unwrap();
        let bundled = OAuthCredentials {
            client_id: ProviderConfig::for_provider(CloudProvider::OneDrive)
                .oauth
                .client_id
                .into(),
            client_secret: None,
        };
        let uppercase_bundled = OAuthCredentials {
            client_id: bundled.client_id.to_ascii_uppercase(),
            client_secret: None,
        };
        for custom in [None, Some(&bundled), Some(&uppercase_bundled)] {
            let result = authenticate_only_with(
                CloudProvider::OneDrive,
                &config,
                "onedrive-test",
                custom,
                &AtomicBool::new(false),
                |_, _| panic!("must not start unsupported authorization"),
            );
            assert!(result.unwrap_err().to_string().contains("own OAuth client"));
        }
        assert!(config.list_remotes().unwrap().is_empty());
    }

    #[test]
    fn auth_only_cancelled_late_token_is_not_persisted() {
        let dir = tempfile::tempdir().unwrap();
        let config = RcloneConfig::new(dir.path().join("rclone.conf")).unwrap();
        let custom = OAuthCredentials {
            client_id: "synthetic-own-client".into(),
            client_secret: None,
        };
        let cancel = AtomicBool::new(false);
        let result = authenticate_only_with(
            CloudProvider::OneDrive,
            &config,
            "onedrive-test",
            Some(&custom),
            &cancel,
            |_, _| {
                cancel.store(true, Ordering::Relaxed);
                Ok(r#"{"access_token":"synthetic-late-token"}"#.into())
            },
        );
        assert!(result.unwrap_err().to_string().contains("cancelled"));
        assert!(config.list_remotes().unwrap().is_empty());
    }

    #[test]
    fn auth_only_persists_credentials_without_account_discovery() {
        let dir = tempfile::tempdir().unwrap();
        let config = RcloneConfig::new(dir.path().join("rclone.conf")).unwrap();
        let custom = OAuthCredentials {
            client_id: "test-public-client".into(),
            client_secret: None,
        };
        let result = authenticate_only_with(
            CloudProvider::OneDrive,
            &config,
            "onedrive-test",
            Some(&custom),
            &AtomicBool::new(false),
            |settings, provider| {
                assert_eq!(settings.client_id, "test-public-client");
                assert_eq!(settings.client_secret, None);
                assert!(provider.oauth.scopes.contains(&"Files.Read"));
                Ok(
                    r#"{"access_token":"synthetic-access","refresh_token":"synthetic-refresh"}"#
                        .into(),
                )
            },
        )
        .unwrap();
        assert_eq!(result.user_info, None);
        let saved = std::fs::read_to_string(config.path()).unwrap();
        assert!(saved.contains("[onedrive-test]"));
        assert!(saved.contains("synthetic-refresh"));
        assert!(saved.contains("client_id = test-public-client"));
        assert!(!saved.contains("client_secret"));
        assert!(!saved.contains("drive_id"));
        assert!(!saved.contains("drive_type"));
    }

    #[test]
    fn auth_only_refuses_google_registration_before_authorization() {
        let dir = tempfile::tempdir().unwrap();
        let config = RcloneConfig::new(dir.path().join("rclone.conf")).unwrap();
        let result = authenticate_only_with(
            CloudProvider::GoogleDrive,
            &config,
            "drive-test",
            None,
            &AtomicBool::new(false),
            |_, _| panic!("must not request authorization"),
        );
        assert!(result.is_err());
        assert!(config.list_remotes().unwrap().is_empty());
    }

    #[test]
    fn auth_only_failed_exchange_does_not_persist_a_remote() {
        let dir = tempfile::tempdir().unwrap();
        let config = RcloneConfig::new(dir.path().join("rclone.conf")).unwrap();
        let custom = OAuthCredentials {
            client_id: "synthetic-own-client".into(),
            client_secret: None,
        };
        let result = authenticate_only_with(
            CloudProvider::OneDrive,
            &config,
            "onedrive-test",
            Some(&custom),
            &AtomicBool::new(false),
            |_, _| bail!("synthetic exchange failure"),
        );
        assert!(result.is_err());
        assert!(config.list_remotes().unwrap().is_empty());
    }

    #[test]
    fn auth_only_device_exchange_persists_token_after_only_oauth_requests() {
        let server = tiny_http::Server::http("127.0.0.1:0").unwrap();
        let address = server.server_addr().to_string();
        let fixture = std::thread::spawn(move || {
            let mut paths = Vec::new();
            for response in [
                r#"{"device_code":"synthetic-device","user_code":"SYNTHETIC","verification_uri":"https://example.invalid/verify","expires_in":30,"interval":1}"#,
                r#"{"access_token":"synthetic-access","refresh_token":"synthetic-refresh","token_type":"Bearer","expires_in":3600}"#,
            ] {
                let mut request = server
                    .recv_timeout(Duration::from_secs(5))
                    .unwrap()
                    .expect("OAuth request");
                assert_eq!(request.method(), &tiny_http::Method::Post);
                paths.push(request.url().to_string());
                let mut body = String::new();
                request.as_reader().read_to_string(&mut body).unwrap();
                assert!(body.contains("client_id=test-public-client"));
                assert!(!body.contains("client_secret"));
                request
                    .respond(tiny_http::Response::from_string(response))
                    .unwrap();
            }
            paths
        });
        let dir = tempfile::tempdir().unwrap();
        let config = RcloneConfig::new(dir.path().join("rclone.conf")).unwrap();
        let custom = OAuthCredentials {
            client_id: "test-public-client".into(),
            client_secret: None,
        };
        let result = authenticate_only_with(
            CloudProvider::OneDrive,
            &config,
            "onedrive-test",
            Some(&custom),
            &AtomicBool::new(false),
            |settings, provider| {
                authorize_device_only(
                    &DeviceCodeConfig {
                        device_code_url: format!("http://{address}/devicecode"),
                        token_url: format!("http://{address}/token"),
                        client_id: settings.client_id.clone(),
                        client_secret: settings.client_secret.clone(),
                        scope: provider.oauth.scopes.join(" "),
                    },
                    &AtomicBool::new(false),
                )
            },
        )
        .unwrap();
        assert_eq!(fixture.join().unwrap(), ["/devicecode", "/token"]);
        assert!(config.has_remote(&result.remote_name).unwrap());
        assert_eq!(
            config
                .get_remote_option(&result.remote_name, "drive_id")
                .unwrap(),
            None
        );
        let token = config
            .get_remote_option(&result.remote_name, "token")
            .unwrap()
            .unwrap();
        let token: serde_json::Value = serde_json::from_str(&token).unwrap();
        assert_eq!(token["refresh_token"], "synthetic-refresh");
        assert_eq!(result.user_info, None);
    }
}
