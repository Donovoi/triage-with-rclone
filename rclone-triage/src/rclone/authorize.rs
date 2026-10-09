//! rclone authorize fallback helpers.
//!
//! Runs `rclone authorize` and extracts an OAuth URL from the output.

use anyhow::{bail, Context, Result};
use regex::Regex;
use std::io::{self, Read};
use std::process::{Command, Stdio};
use std::sync::{
    atomic::{AtomicBool, AtomicUsize, Ordering},
    mpsc, Arc,
};
use std::thread;
use std::time::{Duration, Instant};

use crate::rclone::process::{DrainHandle, ManagedChild, RcloneRunner, JOIN_TIMEOUT, STOP_TIMEOUT};

const MAX_AUTHORIZE_BYTES: usize = 1024 * 1024;
const MAX_AUTHORIZE_LINE: usize = 256 * 1024;
const MAX_AUTHORIZE_LINES: usize = 4096;

#[derive(Debug, Default)]
struct AuthorizeOutputLimit {
    bytes: AtomicUsize,
    lines: AtomicUsize,
    failed: AtomicBool,
}

fn read_authorize_output<R: Read>(
    mut reader: R,
    tx: mpsc::Sender<(AuthorizeOutputStream, String)>,
    stream: AuthorizeOutputStream,
    limit: &AuthorizeOutputLimit,
) -> io::Result<()> {
    let operation = (|| {
        let mut buffer = [0u8; 8192];
        let mut line = Vec::new();
        let emit = |line: &mut Vec<u8>| -> io::Result<()> {
            if line.is_empty() {
                return Ok(());
            }
            if limit.lines.fetch_add(1, Ordering::SeqCst) >= MAX_AUTHORIZE_LINES {
                return Err(io::Error::other(
                    "Authorization output exceeded the line limit",
                ));
            }
            tx.send((stream, String::from_utf8_lossy(line).into_owned()))
                .map_err(|_| {
                    io::Error::new(
                        io::ErrorKind::BrokenPipe,
                        "Authorization output receiver closed",
                    )
                })?;
            line.clear();
            Ok(())
        };
        loop {
            let count = reader.read(&mut buffer)?;
            if count == 0 {
                break;
            }
            if limit
                .bytes
                .fetch_add(count, Ordering::SeqCst)
                .saturating_add(count)
                > MAX_AUTHORIZE_BYTES
            {
                return Err(io::Error::other(
                    "Authorization output exceeded the byte limit",
                ));
            }
            for &byte in &buffer[..count] {
                if byte == b'\r' || byte == b'\n' {
                    emit(&mut line)?;
                } else {
                    if line.len() == MAX_AUTHORIZE_LINE {
                        return Err(io::Error::other(
                            "Authorization output line exceeded its limit",
                        ));
                    }
                    line.push(byte);
                }
            }
        }
        emit(&mut line)
    })();
    if operation.is_err() {
        limit.failed.store(true, Ordering::SeqCst);
    }
    operation
}

fn finish_authorize_result<T>(operation: Result<T>, cleanup: Result<()>) -> Result<T> {
    match (operation, cleanup) {
        (Ok(value), Ok(())) => Ok(value),
        (Err(error), Ok(())) => Err(error),
        (Ok(_), Err(error)) => Err(error),
        (Err(error), Err(cleanup)) => {
            Err(error.context(format!("Authorization cleanup also failed: {cleanup:#}")))
        }
    }
}

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
    let envs = authorization_env(&backend)?;
    let env_refs: Vec<_> = envs
        .iter()
        .map(|(key, value)| (key.as_str(), value.as_str()))
        .collect();
    let mut args = vec!["authorize", backend.as_str(), "--auth-no-open-browser"];
    args.extend(read_only_scope_args(&backend));
    let output = runner.run_with_timeout_env(&args, Some(timeout), &env_refs)?;
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

fn read_only_scope_args(backend: &str) -> Vec<&'static str> {
    match backend {
        "drive" => vec!["--drive-scope", "drive.readonly"],
        "onedrive" => vec![
            "--onedrive-access-scopes",
            "Files.Read Files.Read.All Sites.Read.All offline_access",
        ],
        "google photos" | "gphotos" => vec!["--gphotos-read-only"],
        "hidrive" => vec![
            "--hidrive-scope-access",
            "ro",
            "--hidrive-scope-role",
            "user",
        ],
        _ => Vec::new(),
    }
}

fn authorization_env(backend: &str) -> Result<Vec<(String, String)>> {
    use crate::providers::CloudProvider;
    let (provider, prefix) = match backend {
        "drive" => (CloudProvider::GoogleDrive, "RCLONE_DRIVE"),
        "google photos" | "gphotos" => (CloudProvider::GooglePhotos, "RCLONE_GPHOTOS"),
        _ => return Ok(Vec::new()),
    };
    crate::providers::auth::ensure_new_auth_credentials(provider)?;
    let creds = crate::providers::credentials::custom_oauth_credentials_for(provider)?
        .context("Custom OAuth credentials unavailable")?;
    let mut envs = vec![(format!("{prefix}_CLIENT_ID"), creds.client_id)];
    if let Some(secret) = creds.client_secret {
        envs.push((format!("{prefix}_CLIENT_SECRET"), secret));
    }
    Ok(envs)
}

pub fn normalize_backend(backend: &str) -> Result<String> {
    let trimmed = backend.trim().trim_end_matches(':');
    if trimmed.is_empty() {
        bail!("Backend cannot be empty");
    }
    Ok(trimmed.to_string())
}

pub fn extract_auth_url(stdout: &[String], stderr: &[String]) -> Option<String> {
    let notice_re = Regex::new(r#"NOTICE.*(?:link|go to).*:\s*(https?://[^\s"]+)"#).ok()?;
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
    runner: RcloneRunner,
    backend: String,
    child: ManagedChild,
    rx: mpsc::Receiver<(AuthorizeOutputStream, String)>,
    stdout: Vec<String>,
    stderr: Vec<String>,
    auth_url: Option<String>,
    redirect_uri: Option<String>,
    expected_state: Option<String>,
    stdout_handle: Option<DrainHandle<io::Result<()>>>,
    stderr_handle: Option<DrainHandle<io::Result<()>>>,
    output_limit: Arc<AuthorizeOutputLimit>,
    finalized: bool,
}

impl RunningAuthorize {
    fn finalize(&mut self) -> Result<()> {
        if self.finalized {
            bail!("Authorization finalization was already attempted");
        }
        // Explicit finalization is authoritative, including a refused stop/join.
        self.finalized = true;
        let mut result = self
            .child
            .stop_and_reap(STOP_TIMEOUT)
            .map(|_| ())
            .context("Could not confirm authorization child exit");
        for handle in [self.stdout_handle.take(), self.stderr_handle.take()]
            .into_iter()
            .flatten()
        {
            let joined = handle
                .join(JOIN_TIMEOUT)
                .and_then(|reader| reader)
                .context("Authorization output reader did not finish successfully");
            result = finish_authorize_result(result, joined);
        }
        if result.is_err() {
            self.child.retain();
        }
        let finished = self
            .child
            .finish()
            .map(|_| ())
            .context("Authorization runtime finalization failed");
        finish_authorize_result(result, finished)
    }

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
        if self.runner.is_cancelled() {
            return finish_authorize_result(
                Err(anyhow::anyhow!("Authorization cancelled")),
                self.finalize(),
            );
        }
        if self.output_limit.failed.load(Ordering::SeqCst) {
            return finish_authorize_result(
                Err(anyhow::anyhow!(
                    "Authorization output could not be read safely"
                )),
                self.finalize(),
            );
        }
        if self.auth_url.is_some() {
            return Ok(self.auth_url.clone());
        }

        let deadline = Instant::now() + timeout;
        while Instant::now() < deadline {
            if self.runner.is_cancelled() {
                return finish_authorize_result(
                    Err(anyhow::anyhow!("Authorization cancelled")),
                    self.finalize(),
                );
            }
            if self.output_limit.failed.load(Ordering::SeqCst) {
                return finish_authorize_result(
                    Err(anyhow::anyhow!(
                        "Authorization output could not be read safely"
                    )),
                    self.finalize(),
                );
            }
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

        if self.runner.is_cancelled() {
            return finish_authorize_result(
                Err(anyhow::anyhow!("Authorization cancelled")),
                self.finalize(),
            );
        }
        if self.output_limit.failed.load(Ordering::SeqCst) {
            return finish_authorize_result(
                Err(anyhow::anyhow!(
                    "Authorization output could not be read safely"
                )),
                self.finalize(),
            );
        }
        Ok(self.auth_url.clone())
    }

    /// Wait for the authorize process to exit and return combined output + parsed token JSON.
    pub fn wait(mut self, timeout: Option<Duration>) -> Result<AuthorizeInteractiveResult> {
        let started = Instant::now();
        let mut timed_out = false;
        let mut operation = (|| -> Result<_> {
            loop {
                if self.output_limit.failed.load(Ordering::SeqCst) {
                    bail!("Authorization output could not be read safely");
                }
                if self.runner.is_cancelled() {
                    bail!("Authorization cancelled");
                }
                if timeout.is_some_and(|t| started.elapsed() >= t) {
                    timed_out = true;
                    break Ok(self.child.stop_and_reap(STOP_TIMEOUT)?);
                }
                if let Some(status) = self.child.try_wait()? {
                    break Ok(status);
                }
                thread::sleep(Duration::from_millis(25));
            }
        })();
        let cleanup = self.finalize();
        // Cancellation during a successful child's drain joins must not turn
        // into a token that a caller can persist as a completed authorization.
        if self.runner.is_cancelled() && operation.is_ok() {
            operation = Err(anyhow::anyhow!("Authorization cancelled"));
        }
        let status = finish_authorize_result(operation, cleanup)?;

        // Drain remaining lines.
        let drained: Vec<(AuthorizeOutputStream, String)> = self.rx.try_iter().collect();
        for (stream, line) in drained {
            self.push_line(stream, line);
        }

        let token_json = extract_token_json(&self.stdout, &self.stderr);
        if self.runner.is_cancelled() {
            bail!("Authorization cancelled");
        }

        Ok(AuthorizeInteractiveResult {
            backend: std::mem::take(&mut self.backend),
            auth_url: self.auth_url.take(),
            redirect_uri: self.redirect_uri.take(),
            expected_state: self.expected_state.take(),
            token_json,
            stdout: std::mem::take(&mut self.stdout),
            stderr: std::mem::take(&mut self.stderr),
            status: status.code().unwrap_or(-1),
            timed_out,
        })
    }
}

impl Drop for RunningAuthorize {
    fn drop(&mut self) {
        if !self.finalized {
            let _ = self.finalize();
        }
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
        let query = without_fragment
            .split_once('?')
            .map(|(_, q)| q)
            .unwrap_or("");
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
pub fn spawn_authorize(
    runner: &RcloneRunner,
    backend: &str,
    auth_no_open_browser: bool,
) -> Result<RunningAuthorize> {
    if runner.is_cancelled() {
        bail!("Authorization cancelled");
    }
    let backend = normalize_backend(backend)?;
    let envs = authorization_env(&backend)?;

    let mut cmd = Command::new(runner.exe_path());
    if let Some(config) = runner.config_path() {
        crate::rclone::process::isolate_rclone_environment(&mut cmd);
        cmd.arg("--config").arg(config);
    }
    cmd.envs(envs);
    cmd.arg("authorize").arg(&backend);
    cmd.args(read_only_scope_args(&backend));
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

    let child = runner
        .spawn_command(&mut cmd)
        .with_context(|| format!("Failed to spawn rclone authorize for {}", backend))?;
    own_authorize_readers(runner, backend, child)
}

fn own_authorize_readers(
    runner: &RcloneRunner,
    backend: String,
    child: ManagedChild,
) -> Result<RunningAuthorize> {
    let (tx, rx) = mpsc::channel::<(AuthorizeOutputStream, String)>();
    // Establish the complete owner before pipe extraction or fallible readers.
    let mut running = RunningAuthorize {
        runner: runner.clone(),
        backend,
        child,
        rx,
        stdout: Vec::new(),
        stderr: Vec::new(),
        auth_url: None,
        redirect_uri: None,
        expected_state: None,
        stdout_handle: None,
        stderr_handle: None,
        output_limit: Arc::new(AuthorizeOutputLimit::default()),
        finalized: false,
    };
    let operation = (|| -> Result<()> {
        let stdout = running
            .child
            .stdout
            .take()
            .context("stdout was not captured")?;
        let stderr = running
            .child
            .stderr
            .take()
            .context("stderr was not captured")?;
        let tx_out = tx.clone();
        let limit = running.output_limit.clone();
        running.stdout_handle =
            Some(running.child.spawn_reader("authorize-stdout", move || {
                read_authorize_output(stdout, tx_out, AuthorizeOutputStream::Stdout, &limit)
            })?);
        let limit = running.output_limit.clone();
        running.stderr_handle =
            Some(running.child.spawn_reader("authorize-stderr", move || {
                read_authorize_output(stderr, tx, AuthorizeOutputStream::Stderr, &limit)
            })?);
        Ok(())
    })();
    if let Err(error) = operation {
        return finish_authorize_result(Err(error), running.finalize());
    }
    Ok(running)
}

#[cfg(test)]
mod tests {
    use super::*;

    // These process tests run only in the hosted suite. The child is the test
    // harness itself and emits synthetic output; it never contacts a provider.
    #[test]
    fn authorize_output_fixture() {
        if std::env::var_os("TRIAGE_AUTHORIZE_FIXTURE_CHILD").is_some() {
            println!(r#"{{"access_token":"fixture-token","token_type":"Bearer"}}"#);
        }
    }

    fn completed_authorize_fixture() -> (RunningAuthorize, Arc<AtomicBool>) {
        let exe = std::env::current_exe().unwrap();
        let cancel = Arc::new(AtomicBool::new(false));
        let runner = RcloneRunner::new(&exe)
            .with_cancel_flag(cancel.clone())
            .with_timeout(Duration::from_secs(15));
        let mut command = Command::new(&exe);
        command
            .args([
                "--exact",
                "rclone::authorize::tests::authorize_output_fixture",
                "--nocapture",
            ])
            .env("TRIAGE_AUTHORIZE_FIXTURE_CHILD", "1")
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .stdin(Stdio::null());
        let child = runner.spawn_command(&mut command).unwrap();
        let mut running = own_authorize_readers(&runner, "synthetic".into(), child).unwrap();
        assert!(running.child.wait().unwrap().success());
        (running, cancel)
    }

    #[test]
    fn completed_authorization_fixture_returns_its_synthetic_token() {
        let (running, _) = completed_authorize_fixture();
        let result = running.wait(Some(Duration::from_secs(5))).unwrap();
        let token: serde_json::Value =
            serde_json::from_str(result.token_json.as_deref().unwrap()).unwrap();
        assert_eq!(token["access_token"], "fixture-token");
        assert!(!result.timed_out);
        assert_eq!(result.status, 0);
    }

    #[test]
    fn cancelled_completed_authorization_cannot_return_a_token() {
        let (running, cancel) = completed_authorize_fixture();
        cancel.store(true, Ordering::SeqCst);
        let error = running.wait(Some(Duration::from_secs(5))).unwrap_err();
        assert!(format!("{error:#}").contains("Authorization cancelled"));
    }

    #[test]
    fn cached_authorization_url_cannot_hide_cancellation_or_reader_failure() {
        for cancelled in [false, true] {
            let (mut running, cancel) = completed_authorize_fixture();
            running.auth_url = Some("https://example.invalid/synthetic-authorize".into());
            if cancelled {
                cancel.store(true, Ordering::SeqCst);
            } else {
                running.output_limit.failed.store(true, Ordering::SeqCst);
            }
            let error = running
                .wait_for_auth_url(Duration::from_secs(1))
                .unwrap_err();
            assert!(format!("{error:#}").contains(if cancelled {
                "Authorization cancelled"
            } else {
                "Authorization output could not be read safely"
            }));
        }
    }

    #[test]
    fn authorize_readers_bound_lines_and_total_output_without_losing_final_line() {
        let limit = AuthorizeOutputLimit::default();
        let (tx, rx) = mpsc::channel();
        read_authorize_output(
            &b"first\r\nsecond"[..],
            tx,
            AuthorizeOutputStream::Stdout,
            &limit,
        )
        .unwrap();
        assert_eq!(
            rx.try_iter().map(|(_, text)| text).collect::<Vec<_>>(),
            ["first", "second"]
        );
        let (tx, _rx) = mpsc::channel();
        assert!(read_authorize_output(
            &vec![b'x'; MAX_AUTHORIZE_LINE + 1][..],
            tx,
            AuthorizeOutputStream::Stderr,
            &limit
        )
        .is_err());
        assert!(limit.failed.load(Ordering::SeqCst));
    }

    #[test]
    fn authorize_readers_share_a_finite_byte_and_line_budget() {
        for (bytes, lines) in [(MAX_AUTHORIZE_BYTES, 0), (0, MAX_AUTHORIZE_LINES)] {
            let limit = AuthorizeOutputLimit::default();
            limit.bytes.store(bytes, Ordering::SeqCst);
            limit.lines.store(lines, Ordering::SeqCst);
            let (tx, rx) = mpsc::channel();
            assert!(
                read_authorize_output(&b"x\n"[..], tx, AuthorizeOutputStream::Stdout, &limit)
                    .is_err()
            );
            assert!(rx.try_iter().next().is_none());
            assert!(limit.failed.load(Ordering::SeqCst));
        }
    }

    #[test]
    fn authorize_finalization_keeps_both_operation_and_cleanup_errors() {
        let error = finish_authorize_result::<()>(
            Err(anyhow::anyhow!("operation-marker")),
            Err(anyhow::anyhow!("cleanup-marker")),
        )
        .unwrap_err();
        let text = format!("{error:#}");
        assert!(text.contains("operation-marker") && text.contains("cleanup-marker"));
        assert!(finish_authorize_result(Ok(()), Err(anyhow::anyhow!("cleanup-marker"))).is_err());
    }

    #[test]
    fn hidrive_authorize_uses_read_only_user_scope() {
        assert_eq!(
            read_only_scope_args("hidrive"),
            [
                "--hidrive-scope-access",
                "ro",
                "--hidrive-scope-role",
                "user"
            ]
        );
    }

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
        assert_eq!(
            value.get("access_token").and_then(|v| v.as_str()),
            Some("abc")
        );
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
        assert_eq!(
            value.get("access_token").and_then(|v| v.as_str()),
            Some("abc")
        );
    }
}
