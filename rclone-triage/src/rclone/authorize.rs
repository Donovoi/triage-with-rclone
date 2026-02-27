//! rclone authorize fallback helpers.
//!
//! Runs `rclone authorize` and extracts an OAuth URL from the output.

use anyhow::{bail, Context, Result};
use regex::Regex;
use std::io::{BufRead, BufReader};
use std::process::{Child, Command, Stdio};
use std::sync::mpsc;
use std::thread;
use std::time::{Duration, Instant};

use crate::rclone::process::{wait_with_timeout, RcloneRunner};

/// Windows-specific: CREATE_NO_WINDOW flag
#[cfg(windows)]
const CREATE_NO_WINDOW: u32 = 0x08000000;

#[derive(Debug, Clone)]
pub struct AuthorizeFallbackResult {
    pub backend: String,
    pub auth_url: Option<String>,
    pub stdout: Vec<String>,
    pub stderr: Vec<String>,
    pub status: i32,
    pub timed_out: bool,
}

/// Run `rclone authorize <backend> --auth-no-open-browser` and extract an auth URL.
pub fn authorize_fallback(
    runner: &RcloneRunner,
    backend: &str,
    timeout: Duration,
) -> Result<AuthorizeFallbackResult> {
    let backend = normalize_backend(backend)?;
    let args = ["authorize", backend.as_str(), "--auth-no-open-browser"];
    let output = runner.run_with_timeout(&args, Some(timeout))?;
    let auth_url = extract_auth_url(&output.stdout, &output.stderr);

    Ok(AuthorizeFallbackResult {
        backend,
        auth_url,
        stdout: output.stdout,
        stderr: output.stderr,
        status: output.status,
        timed_out: output.timed_out,
    })
}

pub fn normalize_backend(backend: &str) -> Result<String> {
    let trimmed = backend.trim().trim_end_matches(':');
    if trimmed.is_empty() {
        bail!("Backend cannot be empty");
    }
    Ok(trimmed.to_string())
}

pub fn extract_auth_url(stdout: &[String], stderr: &[String]) -> Option<String> {
    let notice_re =
        Regex::new(r#"NOTICE.*(?:link|go to).*:\s*(https?://[^\s"]+)"#).ok()?;
    let url_re = Regex::new(r#"(https?://[^\s"]+)"#).ok()?;

    for line in stdout.iter().chain(stderr.iter()) {
        if let Some(cap) = notice_re.captures(line) {
            if let Some(url) = cap.get(1) {
                return Some(url.as_str().to_string());
            }
        }
        if let Some(cap) = url_re.captures(line) {
            if let Some(url) = cap.get(1) {
                return Some(url.as_str().to_string());
            }
        }
    }
    None
}

pub fn extract_token_json(stdout: &[String], stderr: &[String]) -> Option<String> {
    for line in stdout.iter().chain(stderr.iter()) {
        let trimmed = line.trim();
        if trimmed.starts_with('{') && trimmed.ends_with('}') {
            if let Ok(value) = serde_json::from_str::<serde_json::Value>(trimmed) {
                if let Ok(compact) = serde_json::to_string(&value) {
                    return Some(compact);
                }
            }
        }
    }

    // Fall back to scanning the combined output for the last JSON object.
    let combined = stdout
        .iter()
        .chain(stderr.iter())
        .map(|s| s.as_str())
        .collect::<Vec<_>>()
        .join("\n");

    let start = combined.rfind('{')?;
    let end_rel = combined[start..].rfind('}')?;
    let end = start + end_rel + 1;
    let slice = &combined[start..end];

    let value = serde_json::from_str::<serde_json::Value>(slice).ok()?;
    serde_json::to_string(&value).ok()
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AuthorizeOutputStream {
    Stdout,
    Stderr,
}

#[derive(Debug)]
pub struct RunningAuthorize {
    backend: String,
    child: Child,
    rx: mpsc::Receiver<(AuthorizeOutputStream, String)>,
    stdout: Vec<String>,
    stderr: Vec<String>,
    auth_url: Option<String>,
    redirect_uri: Option<String>,
    expected_state: Option<String>,
    stdout_handle: Option<thread::JoinHandle<()>>,
    stderr_handle: Option<thread::JoinHandle<()>>,
}

impl RunningAuthorize {
    pub fn backend(&self) -> &str {
        &self.backend
    }

    pub fn auth_url(&self) -> Option<&str> {
        self.auth_url.as_deref()
    }

    pub fn redirect_uri(&self) -> Option<&str> {
        self.redirect_uri.as_deref()
    }

    pub fn expected_state(&self) -> Option<&str> {
        self.expected_state.as_deref()
    }

    fn push_line(&mut self, stream: AuthorizeOutputStream, line: String) {
        match stream {
            AuthorizeOutputStream::Stdout => self.stdout.push(line),
            AuthorizeOutputStream::Stderr => self.stderr.push(line),
        }

        if self.auth_url.is_none() {
            if let Some(url) = extract_auth_url(&self.stdout, &self.stderr) {
                self.expected_state = crate::rclone::oauth::extract_param(&url, "state");
                self.redirect_uri = crate::rclone::oauth::extract_param(&url, "redirect_uri");
                self.auth_url = Some(url);
            }
        }
    }

    /// Drain output until an auth URL is found or the timeout expires.
    pub fn wait_for_auth_url(&mut self, timeout: Duration) -> Result<Option<String>> {
        if self.auth_url.is_some() {
            return Ok(self.auth_url.clone());
        }

        let deadline = Instant::now() + timeout;
        while Instant::now() < deadline {
            let remaining = deadline.saturating_duration_since(Instant::now());
            let chunk = remaining.min(Duration::from_millis(200));
            match self.rx.recv_timeout(chunk) {
                Ok((stream, line)) => {
                    self.push_line(stream, line);
                    if self.auth_url.is_some() {
                        break;
                    }
                }
                Err(mpsc::RecvTimeoutError::Timeout) => continue,
                Err(mpsc::RecvTimeoutError::Disconnected) => break,
            }
        }

        Ok(self.auth_url.clone())
    }

    /// Wait for the authorize process to exit and return combined output + parsed token JSON.
    pub fn wait(mut self, timeout: Option<Duration>) -> Result<AuthorizeInteractiveResult> {
        let (status, timed_out) = match timeout {
            Some(timeout) => wait_with_timeout(&mut self.child, timeout)?,
            None => (self.child.wait()?, false),
        };

        // Ensure readers are done so the channel is fully populated.
        if let Some(handle) = self.stdout_handle.take() {
            let _ = handle.join();
        }
        if let Some(handle) = self.stderr_handle.take() {
            let _ = handle.join();
        }

        // Drain remaining lines.
        let drained: Vec<(AuthorizeOutputStream, String)> = self.rx.try_iter().collect();
        for (stream, line) in drained {
            self.push_line(stream, line);
        }

        let token_json = extract_token_json(&self.stdout, &self.stderr);

        Ok(AuthorizeInteractiveResult {
            backend: self.backend,
            auth_url: self.auth_url,
            redirect_uri: self.redirect_uri,
            expected_state: self.expected_state,
            token_json,
            stdout: self.stdout,
            stderr: self.stderr,
            status: status.code().unwrap_or(-1),
            timed_out,
        })
    }
}

#[derive(Debug, Clone)]
pub struct AuthorizeInteractiveResult {
    pub backend: String,
    pub auth_url: Option<String>,
    pub redirect_uri: Option<String>,
    pub expected_state: Option<String>,
    pub token_json: Option<String>,
    pub stdout: Vec<String>,
    pub stderr: Vec<String>,
    pub status: i32,
    pub timed_out: bool,
}

#[derive(Debug, Clone)]
pub struct AuthorizeCallback {
    pub code: String,
    pub state: Option<String>,
}

/// Parse a callback value pasted from another device.
///
/// Accepts:
/// - full URL (e.g. `http://127.0.0.1:53682/?code=...&state=...`)
/// - raw query string (e.g. `code=...&state=...`)
/// - just the `code` value
pub fn parse_authorize_callback_input(input: &str) -> Result<AuthorizeCallback> {
    let trimmed = input.trim();
    if trimmed.is_empty() {
        bail!("Callback input was empty");
    }

    let (code, state) = if trimmed.starts_with("http://") || trimmed.starts_with("https://") {
        // Strip fragment, then parse query string.
        let without_fragment = trimmed.split('#').next().unwrap_or(trimmed);
        let query = without_fragment.split_once('?').map(|(_, q)| q).unwrap_or("");
        let synthetic = format!("/?{}", query);
        (
            crate::rclone::oauth::extract_param(&synthetic, "code"),
            crate::rclone::oauth::extract_param(&synthetic, "state"),
        )
    } else if trimmed.starts_with('?') || trimmed.contains("code=") {
        let qs = trimmed.trim_start_matches('?');
        let synthetic = format!("/?{}", qs);
        (
            crate::rclone::oauth::extract_param(&synthetic, "code"),
            crate::rclone::oauth::extract_param(&synthetic, "state"),
        )
    } else {
        (Some(trimmed.to_string()), None)
    };

    let code = code.ok_or_else(|| anyhow::anyhow!("Callback did not contain a code"))?;
    Ok(AuthorizeCallback { code, state })
}

/// Send the captured callback parameters to the local `rclone authorize` server.
pub fn send_local_authorize_callback(
    redirect_uri: &str,
    code: &str,
    state: Option<&str>,
) -> Result<()> {
    let redirect_uri = redirect_uri.trim();
    if redirect_uri.is_empty() {
        bail!("redirect_uri was empty");
    }
    if code.trim().is_empty() {
        bail!("code was empty");
    }

    let agent = ureq::AgentBuilder::new()
        .timeout_connect(Duration::from_secs(5))
        .timeout_read(Duration::from_secs(15))
        .timeout_write(Duration::from_secs(15))
        .build();

    let mut req = agent.get(redirect_uri).query("code", code);
    if let Some(state) = state.filter(|s| !s.trim().is_empty()) {
        req = req.query("state", state);
    }

    match req.call() {
        Ok(resp) => {
            let _ = resp.into_string();
            Ok(())
        }
        Err(ureq::Error::Status(status, resp)) => {
            let body = resp.into_string().unwrap_or_default();
            bail!("Local callback returned HTTP {}: {}", status, body);
        }
        Err(e) => Err(e.into()),
    }
}

/// Spawn `rclone authorize <backend>` and stream output lines.
pub fn spawn_authorize(runner: &RcloneRunner, backend: &str, auth_no_open_browser: bool) -> Result<RunningAuthorize> {
    let backend = normalize_backend(backend)?;

    let mut cmd = Command::new(runner.exe_path());
    if let Some(config) = runner.config_path() {
        cmd.arg("--config").arg(config);
    }
    cmd.arg("authorize").arg(&backend);
    if auth_no_open_browser {
        cmd.arg("--auth-no-open-browser");
    }

    cmd.stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .stdin(Stdio::null());

    // Windows: hide console window
    #[cfg(windows)]
    {
        use std::os::windows::process::CommandExt;
        cmd.creation_flags(CREATE_NO_WINDOW);
    }

    let mut child = cmd
        .spawn()
        .with_context(|| format!("Failed to spawn rclone authorize for {}", backend))?;

    let stdout = child.stdout.take().ok_or_else(|| anyhow::anyhow!("stdout was not captured"))?;
    let stderr = child.stderr.take().ok_or_else(|| anyhow::anyhow!("stderr was not captured"))?;

    let (tx, rx) = mpsc::channel::<(AuthorizeOutputStream, String)>();
    let tx_out = tx.clone();
    let tx_err = tx.clone();

    let stdout_handle = thread::spawn(move || {
        let reader = BufReader::new(stdout);
        for line in reader.lines().map_while(Result::ok) {
            let _ = tx_out.send((AuthorizeOutputStream::Stdout, line));
        }
    });

    let stderr_handle = thread::spawn(move || {
        let reader = BufReader::new(stderr);
        for line in reader.lines().map_while(Result::ok) {
            let _ = tx_err.send((AuthorizeOutputStream::Stderr, line));
        }
    });

    Ok(RunningAuthorize {
        backend,
        child,
        rx,
        stdout: Vec::new(),
        stderr: Vec::new(),
        auth_url: None,
        redirect_uri: None,
        expected_state: None,
        stdout_handle: Some(stdout_handle),
        stderr_handle: Some(stderr_handle),
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_extract_auth_url_notice() {
        let stdout = vec!["NOTICE: please go to: https://example.com/auth".to_string()];
        let url = extract_auth_url(&stdout, &[]).unwrap();
        assert_eq!(url, "https://example.com/auth");
    }

    #[test]
    fn test_extract_auth_url_fallback() {
        let stdout = vec!["Open https://example.com/other to continue".to_string()];
        let url = extract_auth_url(&stdout, &[]).unwrap();
        assert_eq!(url, "https://example.com/other");
    }

    #[test]
    fn test_extract_token_json_single_line() {
        let stdout = vec!["{\"access_token\":\"abc\",\"token_type\":\"Bearer\"}".to_string()];
        let token = extract_token_json(&stdout, &[]).unwrap();
        let value: serde_json::Value = serde_json::from_str(&token).unwrap();
        assert_eq!(value.get("access_token").and_then(|v| v.as_str()), Some("abc"));
    }

    #[test]
    fn test_extract_token_json_multi_line_fallback() {
        let stdout = vec![
            "some output".to_string(),
            "{".to_string(),
            "  \"access_token\": \"abc\"".to_string(),
            "}".to_string(),
        ];
        let token = extract_token_json(&stdout, &[]).unwrap();
        let value: serde_json::Value = serde_json::from_str(&token).unwrap();
        assert_eq!(value.get("access_token").and_then(|v| v.as_str()), Some("abc"));
    }
}
