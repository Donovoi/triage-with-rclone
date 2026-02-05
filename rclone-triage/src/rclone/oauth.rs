//! OAuth authentication flow for rclone
//!
//! Implements browser-based OAuth 2.0 authentication by:
//! 1. Starting a local HTTP server to capture redirects
//! 2. Opening the browser to the OAuth authorization URL
//! 3. Capturing the authorization code from the redirect
//! 4. Returning the code for token exchange

use anyhow::{bail, Context, Result};
use std::time::Duration;
use tiny_http::{Response, Server};

/// Default port for OAuth redirect (same as rclone)
pub const DEFAULT_OAUTH_PORT: u16 = 53682;

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

        self.wait_for_redirect()
    }

    /// Wait for the OAuth redirect without opening a browser.
    ///
    /// Useful for mobile/QR flows where the user opens the URL on another device.
    pub fn wait_for_redirect(&self) -> Result<OAuthResult> {
        // Start local server
        let bind_addr = format!("{}:{}", self.bind_host, self.port);
        let server = Server::http(&bind_addr)
            .map_err(|e| anyhow::anyhow!("Failed to start OAuth server on {}: {}", bind_addr, e))?;

        // Wait for redirect with timeout
        let request = server.recv_timeout(self.timeout)?.ok_or_else(|| {
            anyhow::anyhow!(
                "OAuth timeout: no response received within {} seconds",
                self.timeout.as_secs()
            )
        })?;

        // Parse the request URL
        let url = request.url();

        // Check for error
        if url.contains("error=") {
            let error = extract_param(url, "error").unwrap_or_else(|| "unknown".to_string());
            let description = extract_param(url, "error_description")
                .unwrap_or_else(|| "No description".to_string());

            // Send error response to browser
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
                error, description
            ))
            .with_header(
                tiny_http::Header::from_bytes(
                    &b"Content-Type"[..],
                    &b"text/html; charset=utf-8"[..],
                )
                .unwrap(),
            );
            let _ = request.respond(response);

            bail!("OAuth error: {} - {}", error, description);
        }

        // Extract authorization code
        let code = extract_param(url, "code")
            .ok_or_else(|| anyhow::anyhow!("No authorization code in OAuth redirect"))?;

        // Extract state if present
        let state = extract_param(url, "state");

        // Send success response to browser
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
        .with_header(
            tiny_http::Header::from_bytes(&b"Content-Type"[..], &b"text/html; charset=utf-8"[..])
                .unwrap(),
        );
        let _ = request.respond(response);

        Ok(OAuthResult { code, state })
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
}
