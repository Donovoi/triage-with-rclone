//! Synthetic protocol coverage. No browser, provider endpoint or host credentials.
use super::*;
use base64::Engine;
use sha2::{Digest, Sha256};
use std::collections::HashMap;
use std::sync::{atomic::AtomicBool, Arc, Mutex};

pub(super) fn fields(encoded: &str) -> HashMap<String, String> {
    encoded
        .split('&')
        .filter_map(|part| part.split_once('='))
        .map(|(key, value)| {
            (
                crate::rclone::oauth::urldecoded(key),
                crate::rclone::oauth::urldecoded(value),
            )
        })
        .collect()
}

/// Uses the production listener, state validation, PKCE and HTTP client. Only
/// the provider token endpoint and browser opener are replaced by local fixtures.
pub(super) fn exchange_through_loopback(
    provider: &ProviderConfig,
    client_id: &str,
    client_secret: Option<&str>,
    response_body: &str,
    response_status: u16,
) -> Result<String> {
    exchange_through_loopback_with_policy(
        provider,
        client_id,
        client_secret,
        response_body,
        response_status,
        CodeGrantPolicy::Existing,
    )
}

pub(super) fn exchange_through_loopback_with_policy(
    provider: &ProviderConfig,
    client_id: &str,
    client_secret: Option<&str>,
    response_body: &str,
    response_status: u16,
    policy: CodeGrantPolicy,
) -> Result<String> {
    let token_server = tiny_http::Server::http("127.0.0.1:0").unwrap();
    let token_url = format!("http://{}/token", token_server.server_addr());
    let mut provider = provider.clone();
    // ProviderConfig stores compile-time URLs; this tiny fixture is test-only.
    provider.oauth.token_url = Box::leak(token_url.into_boxed_str());
    let callback_socket = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let port = callback_socket.local_addr().unwrap().port();
    drop(callback_socket);
    let oauth = OAuthFlow::new()
        .with_port(port)
        .with_timeout(Duration::from_secs(5));
    let auth_fields = Arc::new(Mutex::new(HashMap::<String, String>::new()));
    let request_fields = auth_fields.clone();
    let expected_client = client_id.to_owned();
    let expected_secret = client_secret.map(str::to_owned);
    let body = response_body.to_owned();
    let token_worker = std::thread::spawn(move || {
        let mut request = token_server
            .recv_timeout(Duration::from_secs(5))
            .unwrap()
            .expect("token request");
        assert_eq!(request.method(), &tiny_http::Method::Post);
        assert_eq!(request.url(), "/token");
        let mut body_in = String::new();
        request.as_reader().read_to_string(&mut body_in).unwrap();
        let form = fields(&body_in);
        assert_eq!(form["grant_type"], "authorization_code");
        assert_eq!(form["code"], "测试+code&");
        assert_eq!(form["client_id"], expected_client);
        assert_eq!(form.get("client_secret"), expected_secret.as_ref());
        let authorization = request_fields.lock().unwrap();
        assert_eq!(form["redirect_uri"], authorization["redirect_uri"]);
        assert_eq!(authorization["code_challenge_method"], "S256");
        let challenge = base64::engine::general_purpose::URL_SAFE_NO_PAD
            .encode(Sha256::digest(form["code_verifier"].as_bytes()));
        assert_eq!(challenge, authorization["code_challenge"]);
        request
            .respond(tiny_http::Response::from_string(body).with_status_code(response_status))
            .unwrap();
        assert!(token_server
            .recv_timeout(Duration::from_millis(30))
            .unwrap()
            .is_none());
    });
    let callback_worker = Arc::new(Mutex::new(None));
    let worker_slot = callback_worker.clone();
    let result = authorize_browser_with_grant_policy(
        &provider,
        client_id,
        client_secret,
        &oauth,
        &AtomicBool::new(false),
        policy,
        |url| {
            let query = fields(url.split_once('?').unwrap().1);
            assert_eq!(query["client_id"], client_id);
            if !provider.oauth.scopes.is_empty() {
                assert_eq!(query["scope"], provider.oauth.scopes.join(" "));
            }
            if policy == CodeGrantPolicy::DropboxReadOnlyOffline {
                assert!(url.starts_with("https://www.dropbox.com/oauth2/authorize?"));
                assert_eq!(query["response_type"], "code");
                assert_eq!(query["scope"], "files.metadata.read files.content.read");
                assert_eq!(query["token_access_type"], "offline");
                assert!(!query.contains_key("include_granted_scopes"));
                assert!(!query.contains_key("client_secret"));
                assert!(!query.contains_key("code_verifier"));
                assert_eq!(query.len(), 8);
            }
            let callback = query["redirect_uri"].replace("localhost", "127.0.0.1");
            let state = query["state"].clone();
            *auth_fields.lock().unwrap() = query;
            *worker_slot.lock().unwrap() = Some(std::thread::spawn(move || {
                let agent = ureq::AgentBuilder::new()
                    .timeout(Duration::from_secs(5))
                    .build();
                if policy == CodeGrantPolicy::DropboxReadOnlyOffline {
                    assert!(matches!(
                        agent.get(&format!("{callback}?code=wrong")).call(),
                        Err(ureq::Error::Status(400, _))
                    ));
                }
                let wrong = agent
                    .get(&format!("{callback}?code=wrong&state=wrong-state"))
                    .call();
                match wrong {
                    Err(ureq::Error::Status(400, response)) => {
                        assert!(!response.into_string().unwrap().contains(&state));
                    }
                    _ => panic!("wrong state must be rejected"),
                }
                let valid = format!("{callback}?code=%E6%B5%8B%E8%AF%95%2Bcode%26&state={state}");
                assert_eq!(agent.get(&valid).call().unwrap().status(), 200);
            }));
            Ok(())
        },
    );
    callback_worker
        .lock()
        .unwrap()
        .take()
        .unwrap()
        .join()
        .unwrap();
    token_worker.join().unwrap();
    result
}

#[test]
fn every_advertised_oauth_backend_completes_the_local_callback_exchange_protocol() {
    assert_eq!(
        CloudProvider::all()
            .iter()
            .filter(|provider| ProviderConfig::for_provider(**provider).uses_oauth())
            .count(),
        9
    );
    for provider in CloudProvider::all() {
        let provider = ProviderConfig::for_provider(*provider);
        if !provider.uses_oauth() {
            continue;
        }
        for secret in [None, Some("synthetic-secret+&=")] {
            let result = exchange_through_loopback(&provider, "synthetic-client+&=", secret,
                r#"{"access_token":"synthetic-access","refresh_token":"synthetic-refresh","expires_in":3600}"#, 200).unwrap();
            let token: serde_json::Value = serde_json::from_str(&result).unwrap();
            assert_eq!(token["access_token"], "synthetic-access");
            assert_eq!(token["refresh_token"], "synthetic-refresh");
            assert!(token["expiry"].as_str().is_some());
        }
    }
}

#[test]
fn every_oauth_child_command_keeps_custom_credentials_out_of_arguments() {
    for provider in CloudProvider::all() {
        let custom = OAuthCredentials {
            client_id: "synthetic-own-client".into(),
            client_secret: Some("synthetic-own-secret".into()),
        };
        let result = build_rclone_auth_command_with_custom(
            *provider,
            "synthetic-remote",
            true,
            Some(custom.clone()),
        );
        if !ProviderConfig::for_provider(*provider).uses_oauth() {
            assert!(
                result.is_err(),
                "{provider} must use provider-specific configuration"
            );
            continue;
        }
        let command = result.unwrap();
        assert_eq!(
            &command.args[..4],
            [
                "config",
                "create",
                "synthetic-remote",
                provider.rclone_type()
            ]
        );
        assert!(command
            .args
            .iter()
            .all(|arg| !arg.contains("synthetic-own-") && arg != "client_secret"));
        let prefix = format!("RCLONE_{}", provider.rclone_type().to_ascii_uppercase());
        assert!(command
            .env
            .contains(&(format!("{prefix}_CLIENT_ID"), custom.client_id.clone())));
        assert!(command.env.contains(&(
            format!("{prefix}_CLIENT_SECRET"),
            custom.client_secret.clone().unwrap()
        )));
        let dir = tempfile::tempdir().unwrap();
        let config = RcloneConfig::new(dir.path().join("rclone.conf")).unwrap();
        config
            .set_remote(
                "synthetic-remote",
                provider.rclone_type(),
                &[
                    ("token", r#"{"access_token":"synthetic-issued-token","refresh_token":"synthetic-refresh","token_type":"Bearer","expiry":"2030-01-01T00:00:00Z"}"#),
                    ("root_folder_id", "synthetic-root"),
                ],
            )
            .unwrap();
        persist_auth_client(&config, "synthetic-remote", command.credentials.as_ref()).unwrap();
        assert_eq!(
            config
                .get_remote_option("synthetic-remote", "client_id")
                .unwrap(),
            Some(custom.client_id)
        );
        assert_eq!(
            config
                .get_remote_option("synthetic-remote", "client_secret")
                .unwrap(),
            custom.client_secret
        );
        let token: serde_json::Value = serde_json::from_str(
            &config
                .get_remote_option("synthetic-remote", "token")
                .unwrap()
                .unwrap(),
        )
        .unwrap();
        assert_eq!(token["access_token"], "synthetic-issued-token");
        assert_eq!(token["refresh_token"], "synthetic-refresh");
        assert_eq!(token["expiry"], "2030-01-01T00:00:00Z");
        assert_eq!(
            config
                .get_remote_option("synthetic-remote", "root_folder_id")
                .unwrap()
                .as_deref(),
            Some("synthetic-root")
        );
    }
    let public = build_rclone_auth_command_with_custom(
        CloudProvider::OneDrive,
        "test",
        false,
        Some(OAuthCredentials {
            client_id: "public".into(),
            client_secret: None,
        }),
    )
    .unwrap();
    assert!(public
        .env
        .contains(&("RCLONE_ONEDRIVE_CLIENT_SECRET".into(), String::new())));
}
