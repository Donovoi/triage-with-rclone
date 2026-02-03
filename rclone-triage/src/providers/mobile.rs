//! Mobile authentication helpers (QR code + token exchange)

use anyhow::{bail, Context, Result};
use chrono::{Duration, Utc};
use qrcode::QrCode;
use serde::Deserialize;
use serde_json::{json, Map, Value};

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
}
