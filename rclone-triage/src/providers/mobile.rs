//! Mobile authentication helpers (QR code + token exchange)

use anyhow::{bail, Context, Result};
use chrono::{Duration, Utc};
use qrcode::QrCode;
use serde::Deserialize;
use serde_json::{json, Map, Value};
use std::io::Read;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::{Duration as StdDuration, Instant};

use super::{
    config::ProviderConfig,
    credentials::{custom_oauth_credentials_for, OAuthCredentials},
    CloudProvider,
};

fn oauth_agent() -> ureq::Agent {
    ureq::AgentBuilder::new()
        .timeout_connect(StdDuration::from_secs(10))
        .timeout_read(StdDuration::from_secs(20))
        .timeout_write(StdDuration::from_secs(20))
        .timeout(StdDuration::from_secs(30))
        .redirects(0)
        .build()
}

const MAX_OAUTH_RESPONSE_BYTES: u64 = 64 * 1024;

pub(super) fn read_oauth_response<T: serde::de::DeserializeOwned>(
    response: ureq::Response,
) -> Result<T> {
    let mut bytes = Vec::new();
    response
        .into_reader()
        .take(MAX_OAUTH_RESPONSE_BYTES + 1)
        .read_to_end(&mut bytes)
        .map_err(|_| anyhow::anyhow!("Failed to read OAuth response"))?;
    if bytes.len() as u64 > MAX_OAUTH_RESPONSE_BYTES {
        bail!("OAuth response exceeds size limit");
    }
    // Provider JSON/type errors may contain tokens or client secrets. Never
    // expose the body or serde's value-bearing diagnostic through an error chain.
    serde_json::from_slice(&bytes).map_err(|_| anyhow::anyhow!("Invalid OAuth response JSON"))
}

#[derive(Debug, Deserialize)]
struct TokenResponse {
    access_token: String,
    #[serde(default)]
    refresh_token: Option<String>,
    #[serde(default)]
    token_type: Option<String>,
    #[serde(default)]
    expires_in: Option<u64>,
    #[serde(default)]
    id_token: Option<String>,
}

/// Applied only to the explicit auth-only code exchange, never to refresh or
/// ordinary provider authorization. Existing callers retain their old parser.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) enum CodeGrantPolicy {
    Existing,
    DropboxReadOnlyOffline,
}

#[derive(Deserialize)]
struct DropboxCodeGrant {
    access_token: String,
    refresh_token: String,
    token_type: String,
    expires_in: u64,
    scope: String,
}

// Retain forward-compatible unknown fields without allowing duplicate decoded
// top-level keys to be hidden by serde_json::Value's last-value behavior.
struct DropboxGrantObject(Map<String, Value>);

impl<'de> Deserialize<'de> for DropboxGrantObject {
    fn deserialize<D: serde::Deserializer<'de>>(
        deserializer: D,
    ) -> std::result::Result<Self, D::Error> {
        struct GrantVisitor;
        impl<'de> serde::de::Visitor<'de> for GrantVisitor {
            type Value = DropboxGrantObject;

            fn expecting(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
                formatter.write_str("an OAuth grant object")
            }

            fn visit_map<M: serde::de::MapAccess<'de>>(
                self,
                mut access: M,
            ) -> std::result::Result<Self::Value, M::Error> {
                let mut fields = Map::new();
                while let Some(key) = access.next_key::<String>()? {
                    if fields.contains_key(&key) {
                        return Err(serde::de::Error::custom("Duplicate OAuth grant field"));
                    }
                    fields.insert(key, access.next_value::<Value>()?);
                }
                Ok(DropboxGrantObject(fields))
            }
        }
        deserializer.deserialize_map(GrantVisitor)
    }
}

fn dropbox_grant_to_token(grant: DropboxGrantObject) -> Result<TokenResponse> {
    if ["error", "error_description", "error_uri"]
        .iter()
        .any(|field| grant.0.contains_key(*field))
    {
        bail!("Invalid Dropbox authorization grant");
    }
    let grant: DropboxCodeGrant = serde_json::from_value(Value::Object(grant.0))
        .map_err(|_| anyhow::anyhow!("Invalid Dropbox authorization grant"))?;
    let scopes: Vec<_> = grant.scope.split(' ').collect();
    if scopes.len() != 2
        || !scopes.contains(&"files.metadata.read")
        || !scopes.contains(&"files.content.read")
    {
        bail!("Dropbox authorization did not grant exactly the required read scopes");
    }
    if grant.access_token.trim().is_empty()
        || grant.refresh_token.trim().is_empty()
        || !grant.token_type.eq_ignore_ascii_case("bearer")
    {
        bail!("Dropbox authorization did not return an offline bearer grant");
    }
    // Match the pinned runtime's representable wire lifetime, not an assumed
    // vendor TTL: golang/oauth2 v0.36.0 internal/token.go expirationTime is i32.
    // https://github.com/golang/oauth2/blob/v0.36.0/internal/token.go#L79-L98
    if !(1..=i32::MAX as u64).contains(&grant.expires_in) {
        bail!("Invalid Dropbox authorization expiry");
    }
    Ok(TokenResponse {
        access_token: grant.access_token,
        refresh_token: Some(grant.refresh_token),
        token_type: Some(grant.token_type),
        expires_in: Some(grant.expires_in),
        id_token: None,
    })
}

#[derive(Debug, Deserialize)]
struct DeviceCodeResponse {
    device_code: String,
    user_code: String,
    #[serde(default)]
    verification_uri: Option<String>,
    #[serde(default)]
    verification_url: Option<String>,
    #[serde(default)]
    verification_uri_complete: Option<String>,
    expires_in: u64,
    #[serde(default)]
    interval: Option<u64>,
    #[serde(default)]
    message: Option<String>,
}

#[derive(Debug)]
pub struct DeviceCodeInfo {
    pub device_code: String,
    pub user_code: String,
    pub verification_uri: String,
    pub verification_uri_complete: Option<String>,
    pub expires_in: u64,
    pub interval: u64,
    pub message: Option<String>,
}

#[derive(Debug)]
pub struct DeviceCodeConfig {
    pub device_code_url: String,
    pub token_url: String,
    pub scope: String,
    pub client_id: String,
    pub client_secret: Option<String>,
}

/// Render a QR code for the provided data as a unicode string.
pub fn render_qr_code(data: &str) -> Result<String> {
    let code = QrCode::new(data.as_bytes()).context("Failed to build QR code")?;
    Ok(code
        .render::<qrcode::render::unicode::Dense1x2>()
        .quiet_zone(true)
        .build())
}

/// Build the token request body for an OAuth authorization code exchange.
pub fn build_token_request_body(
    code: &str,
    redirect_uri: &str,
    client_id: &str,
    client_secret: Option<&str>,
) -> String {
    let mut body = vec![
        ("grant_type", "authorization_code".to_string()),
        ("code", code.to_string()),
        ("redirect_uri", redirect_uri.to_string()),
        ("client_id", client_id.to_string()),
    ];

    if let Some(secret) = client_secret {
        if !secret.trim().is_empty() {
            body.push(("client_secret", secret.to_string()));
        }
    }

    body.into_iter()
        .map(|(k, v)| format!("{}={}", urlencoded(k), urlencoded(&v)))
        .collect::<Vec<_>>()
        .join("&")
}

/// Exchange an OAuth authorization code for a token JSON compatible with rclone.
pub fn exchange_code_for_token(
    token_url: &str,
    code: &str,
    redirect_uri: &str,
    client_id: &str,
    client_secret: Option<&str>,
) -> Result<Value> {
    exchange_code_for_token_with_pkce(
        token_url,
        code,
        redirect_uri,
        client_id,
        client_secret,
        None,
    )
}

fn token_body_with_pkce(
    code: &str,
    redirect_uri: &str,
    client_id: &str,
    client_secret: Option<&str>,
    verifier: Option<&str>,
) -> String {
    let mut body = build_token_request_body(code, redirect_uri, client_id, client_secret);
    if let Some(verifier) = verifier {
        body.push_str(&format!("&code_verifier={}", urlencoded(verifier)));
    }
    body
}

pub fn exchange_code_for_token_with_pkce(
    token_url: &str,
    code: &str,
    redirect_uri: &str,
    client_id: &str,
    client_secret: Option<&str>,
    verifier: Option<&str>,
) -> Result<Value> {
    exchange_code_for_token_with_policy(
        token_url,
        code,
        redirect_uri,
        client_id,
        client_secret,
        verifier,
        CodeGrantPolicy::Existing,
    )
}

pub(super) fn exchange_code_for_token_with_policy(
    token_url: &str,
    code: &str,
    redirect_uri: &str,
    client_id: &str,
    client_secret: Option<&str>,
    verifier: Option<&str>,
    policy: CodeGrantPolicy,
) -> Result<Value> {
    let body = token_body_with_pkce(code, redirect_uri, client_id, client_secret, verifier);

    let response = oauth_agent()
        .post(token_url)
        .set("Content-Type", "application/x-www-form-urlencoded")
        .send_string(&body);

    let response = match response {
        Ok(ok) => ok,
        Err(ureq::Error::Status(code, _)) => {
            bail!("Token exchange failed (HTTP {})", code);
        }
        Err(_) => bail!("Token exchange transport failed"),
    };
    if !(200..300).contains(&response.status()) {
        bail!("Token exchange failed (HTTP {})", response.status());
    }
    let token = match policy {
        CodeGrantPolicy::Existing => read_oauth_response(response)?,
        CodeGrantPolicy::DropboxReadOnlyOffline => {
            dropbox_grant_to_token(read_oauth_response(response)?)?
        }
    };
    token_response_to_rclone_json(token)
}

/// Return device code config for providers that support it.
pub fn device_code_config(provider: CloudProvider) -> Result<Option<DeviceCodeConfig>> {
    if provider != CloudProvider::OneDrive {
        return Ok(None);
    }
    device_code_config_with_credentials(provider, custom_oauth_credentials_for(provider)?)
}

pub(super) fn device_code_config_with_credentials(
    provider: CloudProvider,
    custom: Option<OAuthCredentials>,
) -> Result<Option<DeviceCodeConfig>> {
    // Google's limited-input flow excludes Drive read-only and Photos scopes.
    // A Desktop OAuth registration also cannot be reused as a TV registration.
    // Keep those providers on browser authorization instead of offering a flow
    // that cannot issue the permissions required by this application.
    if provider != CloudProvider::OneDrive {
        return Ok(None);
    }
    super::auth::ensure_new_auth_credentials_with_custom(provider, custom.as_ref())?;
    let provider_config = ProviderConfig::for_provider(provider);
    if !provider_config.uses_oauth() {
        return Ok(None);
    }

    let (client_id, client_secret) = device_code_credentials(&provider_config, custom.as_ref());

    let scope = if !provider_config.oauth.scopes.is_empty() {
        provider_config.oauth.scopes.join(" ")
    } else {
        "offline_access".to_string()
    };

    let device_code_url = match provider {
        CloudProvider::OneDrive => {
            "https://login.microsoftonline.com/common/oauth2/v2.0/devicecode".to_string()
        }
        _ => return Ok(None),
    };

    Ok(Some(DeviceCodeConfig {
        device_code_url,
        token_url: provider_config.oauth.token_url.to_string(),
        scope,
        client_id,
        client_secret,
    }))
}

fn device_code_credentials(
    provider_config: &ProviderConfig,
    custom: Option<&OAuthCredentials>,
) -> (String, Option<String>) {
    let client_id = custom
        .map(|credentials| credentials.client_id.as_str())
        .unwrap_or(provider_config.oauth.client_id)
        .to_owned();
    let client_secret = custom
        .and_then(|credentials| credentials.client_secret.as_deref())
        .filter(|secret| !secret.trim().is_empty())
        .or_else(|| {
            // A secret belongs to one client registration. Public custom
            // clients must never borrow the unrelated bundled client's secret.
            let uses_bundled_client = client_id.trim() == provider_config.oauth.client_id;
            (uses_bundled_client && !provider_config.oauth.client_secret.trim().is_empty())
                .then_some(provider_config.oauth.client_secret)
        })
        .map(str::to_owned);
    (client_id, client_secret)
}

/// Request a device code from the OAuth device authorization endpoint.
pub fn request_device_code(config: &DeviceCodeConfig) -> Result<DeviceCodeInfo> {
    let body = format!(
        "client_id={}&scope={}",
        urlencoded(&config.client_id),
        urlencoded(&config.scope)
    );

    let response = oauth_agent()
        .post(&config.device_code_url)
        .set("Content-Type", "application/x-www-form-urlencoded")
        .send_string(&body);

    let response = match response {
        Ok(ok) => ok,
        Err(ureq::Error::Status(code, _)) => {
            bail!("Device code request failed (HTTP {})", code);
        }
        Err(_) => bail!("Device code request transport failed"),
    };
    if !(200..300).contains(&response.status()) {
        bail!("Device code request failed (HTTP {})", response.status());
    }
    let payload: DeviceCodeResponse = read_oauth_response(response)?;

    let verification_uri = payload
        .verification_uri
        .or(payload.verification_url)
        .ok_or_else(|| anyhow::anyhow!("Missing verification URL in device code response"))?;

    Ok(DeviceCodeInfo {
        device_code: payload.device_code,
        user_code: payload.user_code,
        verification_uri,
        verification_uri_complete: payload.verification_uri_complete,
        expires_in: payload.expires_in,
        interval: payload.interval.unwrap_or(5),
        message: payload.message,
    })
}

/// Poll the token endpoint for device code flow.
pub fn poll_device_code_for_token(
    config: &DeviceCodeConfig,
    device_code: &str,
    interval_secs: u64,
    expires_in: u64,
) -> Result<Value> {
    poll_device_code_for_token_with_cancel(config, device_code, interval_secs, expires_in, None)
}

pub(super) fn poll_device_code_for_token_with_cancel(
    config: &DeviceCodeConfig,
    device_code: &str,
    interval_secs: u64,
    expires_in: u64,
    cancel: Option<&AtomicBool>,
) -> Result<Value> {
    let start = Instant::now();
    let mut interval = interval_secs.max(1);

    loop {
        ensure_not_cancelled(cancel)?;
        if start.elapsed() >= StdDuration::from_secs(expires_in) {
            bail!("Device code expired before authorization completed");
        }

        let mut body = format!(
            "grant_type=urn:ietf:params:oauth:grant-type:device_code&client_id={}&device_code={}",
            urlencoded(&config.client_id),
            urlencoded(device_code)
        );
        if let Some(secret) = config.client_secret.as_ref() {
            if !secret.trim().is_empty() {
                body.push_str(&format!("&client_secret={}", urlencoded(secret)));
            }
        }

        let response = oauth_agent()
            .post(&config.token_url)
            .timeout(
                StdDuration::from_secs(expires_in)
                    .saturating_sub(start.elapsed())
                    .min(StdDuration::from_secs(30)),
            )
            .set("Content-Type", "application/x-www-form-urlencoded")
            .send_string(&body);

        ensure_not_cancelled(cancel)?;

        match response {
            Ok(ok) => {
                if !(200..300).contains(&ok.status()) {
                    bail!("Token polling failed (HTTP {})", ok.status());
                }
                return token_response_to_rclone_json(read_oauth_response(ok)?);
            }
            Err(ureq::Error::Status(code, resp)) => {
                if let Ok(error_json) = read_oauth_response::<serde_json::Value>(resp) {
                    if let Some(err) = error_json.get("error").and_then(|v| v.as_str()) {
                        match err {
                            "authorization_pending" => {
                                wait_for_next_poll(
                                    StdDuration::from_secs(interval).min(
                                        StdDuration::from_secs(expires_in)
                                            .saturating_sub(start.elapsed()),
                                    ),
                                    cancel,
                                )?;
                                continue;
                            }
                            "slow_down" => {
                                interval = interval.saturating_add(5);
                                wait_for_next_poll(
                                    StdDuration::from_secs(interval).min(
                                        StdDuration::from_secs(expires_in)
                                            .saturating_sub(start.elapsed()),
                                    ),
                                    cancel,
                                )?;
                                continue;
                            }
                            "access_denied" => bail!("User denied access"),
                            "expired_token" => bail!("Device code expired"),
                            _ => {
                                bail!("Token polling failed (HTTP {})", code);
                            }
                        }
                    }
                }
                bail!("Token polling failed (HTTP {})", code);
            }
            Err(_) => bail!("Token polling transport failed"),
        }
    }
}

fn ensure_not_cancelled(cancel: Option<&AtomicBool>) -> Result<()> {
    if cancel.is_some_and(|flag| flag.load(Ordering::Relaxed)) {
        bail!("Authorization cancelled");
    }
    Ok(())
}

fn wait_for_next_poll(duration: StdDuration, cancel: Option<&AtomicBool>) -> Result<()> {
    if cancel.is_none() {
        std::thread::sleep(duration);
        return Ok(());
    }
    let start = Instant::now();
    loop {
        ensure_not_cancelled(cancel)?;
        let remaining = duration.saturating_sub(start.elapsed());
        if remaining.is_zero() {
            return Ok(());
        }
        std::thread::sleep(remaining.min(StdDuration::from_millis(100)));
    }
}

fn token_response_to_rclone_json(token: TokenResponse) -> Result<Value> {
    if token.access_token.trim().is_empty() {
        bail!("OAuth response has no access token");
    }
    let mut map = Map::new();
    map.insert("access_token".to_string(), json!(token.access_token));

    if let Some(refresh) = token.refresh_token {
        map.insert("refresh_token".to_string(), json!(refresh));
    }
    if let Some(token_type) = token.token_type {
        map.insert("token_type".to_string(), json!(token_type));
    }
    if let Some(id_token) = token.id_token {
        map.insert("id_token".to_string(), json!(id_token));
    }
    if let Some(expires_in) = token.expires_in {
        let seconds = i64::try_from(expires_in).context("Invalid OAuth expiry")?;
        let lifetime = Duration::try_seconds(seconds).context("Invalid OAuth expiry")?;
        let expiry = Utc::now()
            .checked_add_signed(lifetime)
            .context("Invalid OAuth expiry")?;
        map.insert("expiry".to_string(), json!(expiry.to_rfc3339()));
    }
    Ok(Value::Object(map))
}

fn urlencoded(s: &str) -> String {
    let mut result = String::with_capacity(s.len() * 3);
    for c in s.chars() {
        match c {
            'a'..='z' | 'A'..='Z' | '0'..='9' | '-' | '_' | '.' | '~' => result.push(c),
            ' ' => result.push_str("%20"),
            _ => {
                for b in c.to_string().as_bytes() {
                    result.push_str(&format!("%{:02X}", b));
                }
            }
        }
    }
    result
}

#[cfg(test)]
mod tests {
    use super::*;

    fn dropbox_response(body: &str) -> Result<Value> {
        let response = ureq::Response::new(200, "OK", body).unwrap();
        token_response_to_rclone_json(dropbox_grant_to_token(read_oauth_response(response)?)?)
    }

    #[test]
    fn dropbox_grant_requires_exact_read_scopes_and_offline_fields() {
        let good = json!({
            "access_token": "synthetic-access",
            "refresh_token": "synthetic-refresh",
            "token_type": "bearer",
            "expires_in": 14400,
            "scope": "files.content.read files.metadata.read",
            "account_id": "SYNTHETIC_PRIVATE_ACCOUNT",
            "uid": "SYNTHETIC_PRIVATE_UID",
            "future": {"ignored": true}
        });
        let before = Utc::now();
        let token = dropbox_response(&good.to_string()).unwrap();
        assert_eq!(token["access_token"], "synthetic-access");
        assert_eq!(token["refresh_token"], "synthetic-refresh");
        assert_eq!(token["token_type"], "bearer");
        assert_eq!(token.as_object().unwrap().len(), 4);
        assert!(!token.to_string().contains("PRIVATE"));
        let expiry =
            chrono::DateTime::parse_from_rfc3339(token["expiry"].as_str().unwrap()).unwrap();
        assert!(expiry >= before + Duration::seconds(14400));
        assert!(expiry <= Utc::now() + Duration::seconds(14400));
        for (field, value) in [
            ("scope", json!("files.metadata.read")),
            ("scope", json!("files.metadata.read files.metadata.read")),
            (
                "scope",
                json!("files.metadata.read files.content.read account_info.read"),
            ),
            ("scope", json!("files.metadata.read files.content.write")),
            ("scope", json!("files.metadata.read\tfiles.content.read")),
            ("scope", json!("files.metadata.read  files.content.read")),
            (
                "scope",
                json!(["files.metadata.read", "files.content.read"]),
            ),
            ("access_token", json!(" \t")),
            ("refresh_token", json!("")),
            ("refresh_token", Value::Null),
            ("token_type", json!("mac")),
            ("token_type", json!(" bearer")),
            ("expires_in", json!(0)),
            ("expires_in", json!(-1)),
            ("expires_in", json!(1.5)),
            ("expires_in", json!("14400")),
            ("expires_in", json!(i32::MAX as u64 + 1)),
            ("expires_in", json!(u64::MAX)),
            ("error", json!("SYNTHETIC_PRIVATE_ERROR")),
        ] {
            let mut candidate = good.clone();
            candidate[field] = value;
            let error = dropbox_response(&candidate.to_string()).unwrap_err();
            assert!(!format!("{error:#}").contains("PRIVATE"));
        }
        for field in [
            "access_token",
            "refresh_token",
            "token_type",
            "expires_in",
            "scope",
        ] {
            let mut candidate = good.clone();
            candidate.as_object_mut().unwrap().remove(field);
            assert!(dropbox_response(&candidate.to_string()).is_err());
        }
        for seconds in [1, i32::MAX as u64] {
            let mut candidate = good.clone();
            candidate["expires_in"] = json!(seconds);
            assert!(dropbox_response(&candidate.to_string()).is_ok());
        }
    }

    #[test]
    fn dropbox_grant_rejects_duplicate_decoded_fields_without_leaking_values() {
        let prefix = r#"{"access_token":"synthetic-access","refresh_token":"synthetic-refresh","token_type":"bearer","expires_in":14400,"scope":"files.metadata.read files.content.read""#;
        for extra in [
            r#", "access_token":"SYNTHETIC_PRIVATE_DUPLICATE"}"#,
            r#", "refresh_token":"SYNTHETIC_PRIVATE_DUPLICATE"}"#,
            r#", "token_type":"bearer"}"#,
            r#", "expires_in":1}"#,
            r#", "sc\u006fpe":"files.metadata.read files.content.read"}"#,
            r#", "SYNTHETIC_PRIVATE_KEY":1,"SYNTHETIC_PRIVATE_KEY":2}"#,
            r#", "future":1,"f\u0075ture":2}"#,
        ] {
            let error = dropbox_response(&format!("{prefix}{extra}")).unwrap_err();
            assert_eq!(error.to_string(), "Invalid OAuth response JSON");
            assert!(!format!("{error:#}").contains("PRIVATE"));
        }
        assert!(dropbox_response(&"x".repeat(MAX_OAUTH_RESPONSE_BYTES as usize + 1)).is_err());
    }

    #[test]
    fn ordinary_grants_keep_ignoring_unrelated_scope_shapes() {
        for scope in [json!(["legacy"]), json!({"legacy": true}), Value::Null] {
            let response = ureq::Response::new(
                200,
                "OK",
                &json!({"access_token":"synthetic", "scope":scope}).to_string(),
            )
            .unwrap();
            let token =
                token_response_to_rclone_json(read_oauth_response(response).unwrap()).unwrap();
            assert_eq!(token, json!({"access_token":"synthetic"}));
        }
    }

    #[test]
    fn token_http_failures_are_bounded_redacted_and_do_not_follow_redirects() {
        for (status, body) in [
            (400, r#"{"error":"SYNTHETIC_PRIVATE_ERROR"}"#.to_string()),
            (
                200,
                r#"{"access_token":{"SYNTHETIC_PRIVATE_ERROR":"value"}}"#.to_string(),
            ),
            (200, r#"{"access_token":""}"#.to_string()),
            (
                200,
                r#"{"access_token":"test","expires_in":18446744073709551615}"#.to_string(),
            ),
            (200, "x".repeat(MAX_OAUTH_RESPONSE_BYTES as usize + 1)),
            (307, "SYNTHETIC_PRIVATE_ERROR".to_string()),
        ] {
            let server = tiny_http::Server::http("127.0.0.1:0").unwrap();
            let forbidden_redirect = tiny_http::Server::http("127.0.0.1:0").unwrap();
            let endpoint = format!("http://{}/SYNTHETIC_PRIVATE_URL", server.server_addr());
            let redirect_url = format!("http://{}/stolen", forbidden_redirect.server_addr());
            let worker = std::thread::spawn(move || {
                let request = server
                    .recv_timeout(StdDuration::from_secs(3))
                    .unwrap()
                    .unwrap();
                let response = tiny_http::Response::from_string(body)
                    .with_status_code(status)
                    .with_header(tiny_http::Header::from_bytes("Location", redirect_url).unwrap());
                let _ = request.respond(response);
                assert!(forbidden_redirect
                    .recv_timeout(StdDuration::from_millis(50))
                    .unwrap()
                    .is_none());
            });
            let error = exchange_code_for_token_with_pkce(
                &endpoint,
                "private-code",
                "http://localhost/",
                "private-client",
                Some("private-secret"),
                Some("private-verifier"),
            )
            .unwrap_err();
            worker.join().unwrap();
            let diagnostic = format!("{error:#}");
            assert!(!diagnostic.contains("PRIVATE"));
            assert!(!diagnostic.contains("private-"));
        }
    }

    #[test]
    fn device_poll_uses_actual_grant_and_handles_pending_success_and_denial() {
        for terminal_status in [200, 400] {
            let server = tiny_http::Server::http("127.0.0.1:0").unwrap();
            let base = format!("http://{}", server.server_addr());
            let mut config = device_code_config_with_credentials(
                CloudProvider::OneDrive,
                Some(OAuthCredentials {
                    client_id: "synthetic-public-client".into(),
                    client_secret: None,
                }),
            )
            .unwrap()
            .unwrap();
            config.device_code_url = format!("{base}/device");
            config.token_url = format!("{base}/token");
            let expected_scope = config.scope.clone();
            let worker = std::thread::spawn(move || {
                for step in 0..3 {
                    let mut request = server
                        .recv_timeout(StdDuration::from_secs(4))
                        .unwrap()
                        .expect("device flow request");
                    assert_eq!(request.method(), &tiny_http::Method::Post);
                    let mut body = String::new();
                    request.as_reader().read_to_string(&mut body).unwrap();
                    assert!(body.contains("client_id=synthetic-public-client"));
                    assert!(!body.contains("client_secret"));
                    let (status, response) = if step == 0 {
                        assert_eq!(request.url(), "/device");
                        assert!(body.contains(&format!("scope={}", urlencoded(&expected_scope))));
                        (
                            200,
                            r#"{"device_code":"synthetic-device","user_code":"CODE","verification_uri":"https://example.invalid/verify","expires_in":10,"interval":1}"#,
                        )
                    } else {
                        assert_eq!(request.url(), "/token");
                        assert!(body
                            .contains("grant_type=urn:ietf:params:oauth:grant-type:device_code"));
                        assert!(body.contains("device_code=synthetic-device"));
                        if step == 1 {
                            (400, r#"{"error":"authorization_pending"}"#)
                        } else if terminal_status == 200 {
                            (
                                200,
                                r#"{"access_token":"synthetic-access","refresh_token":"synthetic-refresh"}"#,
                            )
                        } else {
                            (
                                400,
                                r#"{"error":"access_denied","error_description":"PRIVATE_ERROR"}"#,
                            )
                        }
                    };
                    request
                        .respond(
                            tiny_http::Response::from_string(response).with_status_code(status),
                        )
                        .unwrap();
                }
            });
            let challenge = request_device_code(&config).unwrap();
            let result = poll_device_code_for_token_with_cancel(
                &config,
                &challenge.device_code,
                challenge.interval,
                challenge.expires_in,
                Some(&AtomicBool::new(false)),
            );
            worker.join().unwrap();
            if terminal_status == 200 {
                assert_eq!(result.unwrap()["refresh_token"], "synthetic-refresh");
            } else {
                let error = format!("{:#}", result.unwrap_err());
                assert!(!error.contains("PRIVATE_ERROR"));
                assert!(error.contains("denied"));
            }
            assert!(poll_device_code_for_token_with_cancel(
                &config,
                "unused",
                1,
                10,
                Some(&AtomicBool::new(true))
            )
            .unwrap_err()
            .to_string()
            .contains("cancelled"));
            assert!(
                poll_device_code_for_token_with_cancel(&config, "unused", 1, 0, None)
                    .unwrap_err()
                    .to_string()
                    .contains("expired")
            );
        }
    }

    #[test]
    fn device_poll_interval_observes_cancellation() {
        let cancel = std::sync::Arc::new(AtomicBool::new(false));
        let cancel_worker = cancel.clone();
        let worker = std::thread::spawn(move || {
            std::thread::sleep(StdDuration::from_millis(50));
            cancel_worker.store(true, Ordering::Relaxed);
        });
        let start = Instant::now();
        let result = wait_for_next_poll(StdDuration::from_secs(30), Some(&cancel));
        worker.join().unwrap();
        assert!(result.unwrap_err().to_string().contains("cancelled"));
        assert!(start.elapsed() < StdDuration::from_secs(2));
    }

    #[test]
    fn token_request_binds_code_to_proof_key() {
        let body = token_body_with_pkce(
            "authorization-code",
            "http://localhost/",
            "client",
            None,
            Some("verifier-private"),
        );
        assert!(body.contains("code_verifier=verifier-private"));
        assert!(body.contains("code=authorization-code"));
        assert!(!body.contains("client_secret"));
    }

    #[test]
    fn test_build_token_request_body() {
        let body = build_token_request_body(
            "code123",
            "http://127.0.0.1:53682/",
            "client",
            Some("secret"),
        );

        assert!(body.contains("grant_type=authorization_code"));
        assert!(body.contains("code=code123"));
        assert!(body.contains("client_id=client"));
        assert!(body.contains("client_secret=secret"));
    }

    #[test]
    fn test_render_qr_code() {
        let qr = render_qr_code("https://example.com").unwrap();
        assert!(!qr.trim().is_empty());
    }

    #[test]
    fn test_device_code_config_for_onedrive() {
        let config = device_code_config_with_credentials(CloudProvider::OneDrive, None)
            .unwrap()
            .unwrap();
        assert!(config.device_code_url.contains("devicecode"));
        assert!(config.token_url.contains("token"));
        assert!(config.scope.contains("Files"));
    }

    #[test]
    fn custom_device_code_client_never_borrows_another_clients_secret() {
        let mut defaults = ProviderConfig::for_provider(CloudProvider::OneDrive);
        defaults.oauth.client_id = "bundled-client";
        defaults.oauth.client_secret = "bundled-secret";
        for secret in [None, Some(String::new()), Some("  ".to_string())] {
            let custom = OAuthCredentials {
                client_id: "custom-public-client".into(),
                client_secret: secret,
            };
            let (client_id, secret) = device_code_credentials(&defaults, Some(&custom));
            assert_eq!(client_id, "custom-public-client");
            assert_eq!(secret, None);
        }
        let custom = OAuthCredentials {
            client_id: "custom-confidential-client".into(),
            client_secret: Some("custom-secret".into()),
        };
        assert_eq!(
            device_code_credentials(&defaults, Some(&custom)),
            (
                "custom-confidential-client".into(),
                Some("custom-secret".into())
            )
        );
        assert_eq!(
            device_code_credentials(&defaults, None),
            ("bundled-client".into(), Some("bundled-secret".into()))
        );
    }

    #[test]
    fn google_device_code_is_unavailable_for_required_read_only_scopes() {
        for provider in [CloudProvider::GoogleDrive, CloudProvider::GooglePhotos] {
            assert!(device_code_config_with_credentials(provider, None)
                .unwrap()
                .is_none());
            let custom_public = OAuthCredentials {
                client_id: "synthetic-public-google-client".into(),
                client_secret: None,
            };
            assert!(
                device_code_config_with_credentials(provider, Some(custom_public))
                    .unwrap()
                    .is_none()
            );
            let shared = OAuthCredentials {
                client_id: ProviderConfig::for_provider(provider)
                    .oauth
                    .client_id
                    .into(),
                client_secret: Some("synthetic-secret".into()),
            };
            assert!(device_code_config_with_credentials(provider, Some(shared))
                .unwrap()
                .is_none());
            let custom = OAuthCredentials {
                client_id: "synthetic-own-google-client".into(),
                client_secret: Some("synthetic-own-secret".into()),
            };
            assert!(device_code_config_with_credentials(provider, Some(custom))
                .unwrap()
                .is_none());
        }
    }
}
