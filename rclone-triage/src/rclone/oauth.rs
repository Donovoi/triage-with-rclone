//! OAuth authentication flow for rclone
//!
//! Implements browser-based OAuth 2.0 authentication by:
//! 1. Starting a local HTTP server to capture redirects
//! 2. Opening the browser to the OAuth authorization URL
//! 3. Capturing the authorization code from the redirect
//! 4. Returning the code for token exchange

use anyhow::{bail, Context, Result};
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine;
use rand::rngs::OsRng;
use rand::RngCore;
use std::time::{Duration, Instant};
use tiny_http::{Response, Server};

/// Default port for OAuth redirect (same as rclone)
pub const DEFAULT_OAUTH_PORT: u16 = 53682;

const OAUTH_STATE_LEN_BYTES: usize = 32;

/// OAuth flow handler
pub struct OAuthFlow {
    /// Port to listen on
    port: u16,
    /// Timeout for waiting for auth
    timeout: Duration,
    /// Host/interface to bind the local server to
    bind_host: String,
    /// Host to use for redirect URIs (defaults to bind_host)
    redirect_host: Option<String>,
}

impl OAuthFlow {
    /// Create a new OAuth flow handler
    pub fn new() -> Self {
        Self {
            port: DEFAULT_OAUTH_PORT,
            timeout: Duration::from_secs(120),
            bind_host: "127.0.0.1".to_string(),
            redirect_host: None,
        }
    }

    /// Set the port to listen on
    pub fn with_port(mut self, port: u16) -> Self {
        self.port = port;
        self
    }

    /// Set the timeout for waiting for authentication
    pub fn with_timeout(mut self, timeout: Duration) -> Self {
        self.timeout = timeout;
        self
    }

    /// Set the host/interface to bind the local server to.
    pub fn with_bind_host(mut self, host: impl Into<String>) -> Self {
        self.bind_host = host.into();
        self
    }

    /// Set the host to embed in redirect URIs (e.g., LAN IP).
    pub fn with_redirect_host(mut self, host: impl Into<String>) -> Self {
        self.redirect_host = Some(host.into());
        self
    }

    /// Run the OAuth flow
    ///
    /// 1. Starts a local HTTP server
    /// 2. Opens the browser to the auth URL
    /// 3. Waits for the redirect with the auth code
    ///
    /// # Arguments
    /// * `auth_url` - The OAuth authorization URL to open in the browser
    ///
    /// # Returns
    /// The authorization code from the OAuth redirect
    pub fn run(&self, auth_url: &str) -> Result<OAuthResult> {
        // Open browser
        open::that(auth_url)
            .with_context(|| format!("Failed to open browser with URL: {}", auth_url))?;

        let expected_state = extract_param(auth_url, "state");
        self.wait_for_redirect_with_state(expected_state.as_deref())
    }

    /// Wait for the OAuth redirect and optionally validate an expected `state` parameter.
    ///
    /// This variant:
    /// - Ignores non-callback requests (e.g. `/favicon.ico`)
    /// - Ignores callbacks with mismatched `state` (when provided)
    ///
    /// Note: some OAuth providers omit `state` on the callback even if it was provided in the
    /// authorization URL. In that case, we accept the callback as a best-effort behavior.
    pub fn wait_for_redirect_with_state(&self, expected_state: Option<&str>) -> Result<OAuthResult> {
        // Start local server
        let bind_addr = format!("{}:{}", self.bind_host, self.port);
        let server = Server::http(&bind_addr)
            .map_err(|e| anyhow::anyhow!("Failed to start OAuth server on {}: {}", bind_addr, e))?;

        let deadline = Instant::now() + self.timeout;

        loop {
            let now = Instant::now();
            if now >= deadline {
                bail!(
                    "OAuth timeout: no response received within {} seconds",
                    self.timeout.as_secs()
                );
            }
            let remaining = deadline - now;

            let request = server.recv_timeout(remaining)?.ok_or_else(|| {
                anyhow::anyhow!(
                    "OAuth timeout: no response received within {} seconds",
                    self.timeout.as_secs()
                )
            })?;

            let url = request.url().to_string();

            match parse_oauth_callback_url(&url, expected_state) {
                CallbackParse::Ignore => {
                    // Common extra request from browsers.
                    let response = if url.starts_with("/favicon") {
                        Response::from_string("").with_header(content_type_header())
                    } else {
                        Response::from_string(
                            r#"<html>
                            <head><title>rclone-triage OAuth</title></head>
                            <body>
                            <h1>rclone-triage OAuth Callback</h1>
                            <p>Waiting for authentication callback...</p>
                            <p>You can close this window and return to the application.</p>
                            </body>
                            </html>"#,
                        )
                        .with_header(content_type_header())
                    };
                    let _ = request.respond(response);
                    continue;
                }
                CallbackParse::StateMismatch { got } => {
                    let expected = expected_state.unwrap_or("<none>");
                    let got = got.as_deref().unwrap_or("<missing>");
                    let response = Response::from_string(format!(
                        r#"<html>
                        <head><title>Authentication Session Mismatch</title></head>
                        <body>
                        <h1>Authentication Session Mismatch</h1>
                        <p>This callback does not match the current authentication session.</p>
                        <p>Expected state: <code>{}</code></p>
                        <p>Received state: <code>{}</code></p>
                        <p>Please return to the application and try again.</p>
                        </body>
                        </html>"#,
                        escape_html(expected),
                        escape_html(got)
                    ))
                    .with_header(content_type_header());
                    let _ = request.respond(response);
                    continue;
                }
                CallbackParse::Error { error, description } => {
                    let response = Response::from_string(format!(
                        r#"<html>
                        <head><title>Authentication Failed</title></head>
                        <body>
                        <h1>Authentication Failed</h1>
                        <p>Error: {}</p>
                        <p>{}</p>
                        <p>You can close this window.</p>
                        </body>
                        </html>"#,
                        escape_html(&error),
                        escape_html(&description)
                    ))
                    .with_header(content_type_header());
                    let _ = request.respond(response);

                    bail!("OAuth error: {} - {}", error, description);
                }
                CallbackParse::Success { code, state } => {
                    let response = Response::from_string(
                        r#"<html>
                        <head><title>Authentication Successful</title>
                        <style>
                            body { font-family: system-ui, sans-serif; text-align: center; padding: 50px; }
                            h1 { color: #2e7d32; }
                        </style>
                        </head>
                        <body>
                        <h1>✓ Authentication Successful</h1>
                        <p>You have been authenticated successfully.</p>
                        <p>You can close this window and return to the application.</p>
                        </body>
                        </html>"#,
                    )
                    .with_header(content_type_header());
                    let _ = request.respond(response);

                    return Ok(OAuthResult { code, state });
                }
            }
        }
    }

    /// Generate an OAuth `state` parameter value (CSRF protection).
    pub fn generate_state() -> String {
        let mut bytes = [0u8; OAUTH_STATE_LEN_BYTES];
        OsRng.fill_bytes(&mut bytes);
        URL_SAFE_NO_PAD.encode(bytes)
    }

    /// Build an OAuth authorization URL
    ///
    /// # Arguments
    /// * `base_url` - The OAuth authorization endpoint
    /// * `client_id` - The OAuth client ID
    /// * `scope` - The requested scope(s)
    /// * `state` - Optional state parameter for CSRF protection
    pub fn build_auth_url(
        &self,
        base_url: &str,
        client_id: &str,
        scope: &str,
        state: Option<&str>,
    ) -> String {
        let redirect_uri = self.redirect_uri();

        let mut url = format!(
            "{}?client_id={}&redirect_uri={}&response_type=code&scope={}",
            base_url,
            urlencoded(client_id),
            urlencoded(&redirect_uri),
            urlencoded(scope),
        );

        if let Some(state) = state {
            url.push_str(&format!("&state={}", urlencoded(state)));
        }

        url
    }

    /// Get the redirect URI for this OAuth flow
    pub fn redirect_uri(&self) -> String {
        let host = self
            .redirect_host
            .as_deref()
            .unwrap_or(self.bind_host.as_str());
        format!("http://{}:{}/", host, self.port)
    }
}

impl Default for OAuthFlow {
    fn default() -> Self {
        Self::new()
    }
}

/// Result of a successful OAuth flow
#[derive(Debug, Clone)]
pub struct OAuthResult {
    /// The authorization code
    pub code: String,
    /// The state parameter (if provided)
    pub state: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
enum CallbackParse {
    Ignore,
    StateMismatch { got: Option<String> },
    Error { error: String, description: String },
    Success { code: String, state: Option<String> },
}

fn parse_oauth_callback_url(url: &str, expected_state: Option<&str>) -> CallbackParse {
    // Ignore "extra" requests browsers might send.
    if url.starts_with("/favicon") {
        return CallbackParse::Ignore;
    }

    let code = extract_param(url, "code");
    let error = extract_param(url, "error");

    if code.is_none() && error.is_none() {
        return CallbackParse::Ignore;
    }

    let state = extract_param(url, "state");

    if let Some(expected) = expected_state {
        match state.as_deref() {
            Some(got) if got != expected => {
                return CallbackParse::StateMismatch { got: state };
            }
            None => {
                // SECURITY: reject callbacks that omit `state` when we expected one.
                // Accepting a missing state would defeat CSRF protection.
                return CallbackParse::StateMismatch { got: None };
            }
            _ => {} // state matches
        }
    }

    if let Some(error) = error {
        let description =
            extract_param(url, "error_description").unwrap_or_else(|| "No description".to_string());
        return CallbackParse::Error { error, description };
    }

    CallbackParse::Success {
        code: code.unwrap_or_default(),
        state,
    }
}

fn content_type_header() -> tiny_http::Header {
    tiny_http::Header::from_bytes(&b"Content-Type"[..], &b"text/html; charset=utf-8"[..]).unwrap()
}

fn escape_html(s: &str) -> String {
    s.replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
        .replace('"', "&quot;")
        .replace('\'', "&#x27;")
}

/// Extract a query parameter from a URL
pub(crate) fn extract_param(url: &str, param: &str) -> Option<String> {
    let query = url.split('?').nth(1)?;
    for part in query.split('&') {
        if let Some((key, value)) = part.split_once('=') {
            if key == param {
                return Some(urldecoded(value));
            }
        }
    }
    None
}

/// Simple URL encoding (minimal implementation)
fn urlencoded(s: &str) -> String {
    let mut result = String::with_capacity(s.len() * 3);
    for c in s.chars() {
        match c {
            'a'..='z' | 'A'..='Z' | '0'..='9' | '-' | '_' | '.' | '~' => {
                result.push(c);
            }
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

/// Simple URL decoding
pub(crate) fn urldecoded(s: &str) -> String {
    let mut result = Vec::new();
    let mut chars = s.chars().peekable();

    while let Some(c) = chars.next() {
        if c == '%' {
            let hex: String = chars.by_ref().take(2).collect();
            if let Ok(byte) = u8::from_str_radix(&hex, 16) {
                result.push(byte);
            }
        } else if c == '+' {
            result.push(b' ');
        } else {
            result.extend_from_slice(c.to_string().as_bytes());
        }
    }

    String::from_utf8_lossy(&result).to_string()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_build_auth_url() {
        let flow = OAuthFlow::new().with_port(53682);
        let url = flow.build_auth_url(
            "https://accounts.google.com/o/oauth2/auth",
            "test_client_id",
            "https://www.googleapis.com/auth/drive",
            Some("test_state"),
        );

        assert!(url.contains("client_id=test_client_id"));
        assert!(url.contains("redirect_uri=http%3A%2F%2F127.0.0.1%3A53682%2F"));
        assert!(url.contains("response_type=code"));
        assert!(url.contains("state=test_state"));
    }

    #[test]
    fn test_extract_param() {
        let url = "/?code=test_code&state=test_state";
        assert_eq!(extract_param(url, "code"), Some("test_code".to_string()));
        assert_eq!(extract_param(url, "state"), Some("test_state".to_string()));
        assert_eq!(extract_param(url, "unknown"), None);
    }

    #[test]
    fn test_extract_param_with_encoding() {
        let url = "/?code=test%20code&error_description=Something%20went%20wrong";
        assert_eq!(extract_param(url, "code"), Some("test code".to_string()));
        assert_eq!(
            extract_param(url, "error_description"),
            Some("Something went wrong".to_string())
        );
    }

    #[test]
    fn test_urlencoded() {
        assert_eq!(urlencoded("hello world"), "hello%20world");
        assert_eq!(urlencoded("test@example.com"), "test%40example.com");
        assert_eq!(urlencoded("simple"), "simple");
    }

    #[test]
    fn test_redirect_uri() {
        let flow = OAuthFlow::new().with_port(12345);
        assert_eq!(flow.redirect_uri(), "http://127.0.0.1:12345/");
    }

    #[test]
    fn test_redirect_uri_with_custom_host() {
        let flow = OAuthFlow::new()
            .with_port(9999)
            .with_bind_host("0.0.0.0")
            .with_redirect_host("192.168.1.5");
        assert_eq!(flow.redirect_uri(), "http://192.168.1.5:9999/");
    }

    #[test]
    fn test_parse_oauth_callback_success_requires_state_when_expected() {
        let url = "/?code=test_code&state=test_state";
        assert_eq!(
            parse_oauth_callback_url(url, Some("test_state")),
            CallbackParse::Success {
                code: "test_code".to_string(),
                state: Some("test_state".to_string())
            }
        );
    }

    #[test]
    fn test_parse_oauth_callback_state_mismatch() {
        let url = "/?code=test_code&state=wrong";
        assert_eq!(
            parse_oauth_callback_url(url, Some("expected")),
            CallbackParse::StateMismatch {
                got: Some("wrong".to_string())
            }
        );
    }

    #[test]
    fn test_parse_oauth_callback_state_missing_is_rejected() {
        let url = "/?code=test_code";
        assert_eq!(
            parse_oauth_callback_url(url, Some("expected")),
            CallbackParse::StateMismatch { got: None }
        );
    }

    #[test]
    fn test_parse_oauth_callback_error_requires_state_when_expected() {
        let url = "/?error=access_denied&error_description=Denied&state=wrong";
        assert_eq!(
            parse_oauth_callback_url(url, Some("expected")),
            CallbackParse::StateMismatch {
                got: Some("wrong".to_string())
            }
        );
    }

    #[test]
    fn test_parse_oauth_callback_error() {
        let url = "/?error=access_denied&error_description=Denied";
        assert_eq!(
            parse_oauth_callback_url(url, None),
            CallbackParse::Error {
                error: "access_denied".to_string(),
                description: "Denied".to_string()
            }
        );
    }

    #[test]
    fn test_parse_oauth_callback_ignore_favicon() {
        assert_eq!(
            parse_oauth_callback_url("/favicon.ico", Some("expected")),
            CallbackParse::Ignore
        );
    }
}
