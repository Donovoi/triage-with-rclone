//! Mobile authentication helpers (QR code + token exchange)

use anyhow::{bail, Context, Result};
use chrono::{Duration, Utc};
use qrcode::QrCode;
use serde::Deserialize;
use serde_json::{json, Map, Value};
use std::time::{Duration as StdDuration, Instant};

use super::{config::ProviderConfig, credentials::custom_oauth_credentials_for, CloudProvider};

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
    let body = build_token_request_body(code, redirect_uri, client_id, client_secret);

    let response = ureq::post(token_url)
        .set("Content-Type", "application/x-www-form-urlencoded")
        .send_string(&body);

    let response = match response {
        Ok(ok) => ok,
        Err(ureq::Error::Status(code, resp)) => {
            let text = resp.into_string().unwrap_or_default();
            bail!("Token exchange failed ({}): {}", code, text);
        }
        Err(e) => return Err(e.into()),
    };

    let token: TokenResponse =
        serde_json::from_reader(response.into_reader()).context("Failed to parse token JSON")?;

    Ok(token_response_to_rclone_json(token))
}

/// Return device code config for providers that support it.
pub fn device_code_config(provider: CloudProvider) -> Result<Option<DeviceCodeConfig>> {
    let provider_config = ProviderConfig::for_provider(provider);
    if !provider_config.uses_oauth() {
        return Ok(None);
    }

    let custom = custom_oauth_credentials_for(provider).ok().flatten();
    let client_id = custom
        .as_ref()
        .map(|c| c.client_id.as_str())
        .unwrap_or(provider_config.oauth.client_id)
        .to_string();
    let client_secret = custom
        .as_ref()
        .and_then(|c| c.client_secret.clone())
        .filter(|s| !s.trim().is_empty())
        .or_else(|| {
            let secret = provider_config.oauth.client_secret;
            if secret.trim().is_empty() {
                None
            } else {
                Some(secret.to_string())
            }
        });

    let scope = if !provider_config.oauth.scopes.is_empty() {
        provider_config.oauth.scopes.join(" ")
    } else {
        "offline_access".to_string()
    };

    let device_code_url = match provider {
        CloudProvider::OneDrive => {
            "https://login.microsoftonline.com/common/oauth2/v2.0/devicecode".to_string()
        }
        CloudProvider::GoogleDrive | CloudProvider::GooglePhotos => {
            "https://oauth2.googleapis.com/device/code".to_string()
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

/// Request a device code from the OAuth device authorization endpoint.
pub fn request_device_code(config: &DeviceCodeConfig) -> Result<DeviceCodeInfo> {
    let body = format!(
        "client_id={}&scope={}",
        urlencoded(&config.client_id),
        urlencoded(&config.scope)
    );

    let response = ureq::post(&config.device_code_url)
        .set("Content-Type", "application/x-www-form-urlencoded")
        .send_string(&body);

    let response = match response {
        Ok(ok) => ok,
        Err(ureq::Error::Status(code, resp)) => {
            let text = resp.into_string().unwrap_or_default();
            bail!("Device code request failed ({}): {}", code, text);
        }
        Err(e) => return Err(e.into()),
    };

    let payload: DeviceCodeResponse =
        serde_json::from_reader(response.into_reader()).context("Failed to parse device code")?;

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
    let start = Instant::now();
    let mut interval = interval_secs.max(1);

    loop {
        if start.elapsed() > StdDuration::from_secs(expires_in) {
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

        let response = ureq::post(&config.token_url)
            .set("Content-Type", "application/x-www-form-urlencoded")
            .send_string(&body);

        match response {
            Ok(ok) => {
                let token: TokenResponse = serde_json::from_reader(ok.into_reader())
                    .context("Failed to parse token response")?;
                return Ok(token_response_to_rclone_json(token));
            }
            Err(ureq::Error::Status(code, resp)) => {
                let text = resp.into_string().unwrap_or_default();
                if let Ok(error_json) = serde_json::from_str::<serde_json::Value>(&text) {
                    if let Some(err) = error_json.get("error").and_then(|v| v.as_str()) {
                        match err {
                            "authorization_pending" => {
                                std::thread::sleep(StdDuration::from_secs(interval));
                                continue;
                            }
                            "slow_down" => {
                                interval = interval.saturating_add(5);
                                std::thread::sleep(StdDuration::from_secs(interval));
                                continue;
                            }
                            "access_denied" => bail!("User denied access"),
                            "expired_token" => bail!("Device code expired"),
                            _ => {
                                bail!("Token polling failed ({}): {}", code, text);
                            }
                        }
                    }
                }
                bail!("Token polling failed ({}): {}", code, text);
            }
            Err(e) => return Err(e.into()),
        }
    }
}

fn token_response_to_rclone_json(token: TokenResponse) -> Value {
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
        let expiry = Utc::now() + Duration::seconds(expires_in as i64);
        map.insert("expiry".to_string(), json!(expiry.to_rfc3339()));
    }

    Value::Object(map)
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
        let config = device_code_config(CloudProvider::OneDrive).unwrap().unwrap();
        assert!(config.device_code_url.contains("devicecode"));
        assert!(config.token_url.contains("token"));
        assert!(config.scope.contains("Files"));
    }
}
