//! rclone authorize fallback helpers.
//!
//! Runs `rclone authorize` and extracts an OAuth URL from the output.

use anyhow::{bail, Result};
use regex::Regex;
use std::time::Duration;

use crate::rclone::process::RcloneRunner;

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

fn normalize_backend(backend: &str) -> Result<String> {
    let trimmed = backend.trim().trim_end_matches(':');
    if trimmed.is_empty() {
        bail!("Backend cannot be empty");
    }
    Ok(trimmed.to_string())
}

fn extract_auth_url(stdout: &[String], stderr: &[String]) -> Option<String> {
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
}
