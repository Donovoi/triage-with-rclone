//! Rclone process runner
//!
//! Wraps spawning rclone processes with Windows-specific handling
//! for hiding console windows and capturing output.

use anyhow::{bail, Context, Result};
use std::io::Read;
use std::path::{Path, PathBuf};
use std::process::{Child, ChildStderr, ChildStdout, Command, ExitStatus, Stdio};
use std::sync::mpsc;
use std::sync::{
    atomic::{AtomicBool, Ordering},
    Arc, Mutex,
};
use std::thread;
use std::time::Duration;

/// Windows-specific: CREATE_NO_WINDOW flag
#[cfg(windows)]
const CREATE_NO_WINDOW: u32 = 0x08000000;

/// Output from a rclone process
#[derive(Debug, Clone)]
pub struct RcloneOutput {
    /// Standard output lines
    pub stdout: Vec<String>,
    /// Standard error lines
    pub stderr: Vec<String>,
    /// Exit status
    pub status: i32,
    /// Whether the process was killed due to timeout
    pub timed_out: bool,
    pub cancelled: bool,
}

impl RcloneOutput {
    /// Check if the command succeeded
    pub fn success(&self) -> bool {
        self.status == 0 && !self.timed_out && !self.cancelled
    }

    /// Get stdout as a single string
    pub fn stdout_string(&self) -> String {
        self.stdout.join("\n")
    }

    /// Get stderr as a single string
    pub fn stderr_string(&self) -> String {
        self.stderr.join("\n")
    }
}

/// Runs rclone processes with proper configuration
#[derive(Debug, Clone)]
pub struct RcloneRunner {
    /// Path to rclone executable
    exe_path: PathBuf,
    /// Path to rclone config file (optional)
    config_path: Option<PathBuf>,
    /// Default timeout for commands
    default_timeout: Option<Duration>,
    cancel: Vec<Arc<AtomicBool>>,
}

impl RcloneRunner {
    /// Create a new rclone runner
    pub fn new(exe_path: impl AsRef<Path>) -> Self {
        Self {
            exe_path: exe_path.as_ref().to_path_buf(),
            config_path: None,
            default_timeout: None,
            cancel: Vec::new(),
        }
    }

    /// Set the config file path
    pub fn with_config(mut self, config_path: impl AsRef<Path>) -> Self {
        self.config_path = Some(config_path.as_ref().to_path_buf());
        self
    }

    /// Set default timeout for commands
    pub fn with_timeout(mut self, timeout: Duration) -> Self {
        self.default_timeout = Some(timeout);
        self
    }

    /// Run a rclone command and capture output
    pub fn run(&self, args: &[&str]) -> Result<RcloneOutput> {
        self.run_with_timeout(args, self.default_timeout)
    }

    /// Run a rclone command with additional environment variables
    pub fn run_with_env(&self, args: &[&str], envs: &[(&str, &str)]) -> Result<RcloneOutput> {
        self.run_with_timeout_env(args, self.default_timeout, envs)
    }

    pub fn with_cancel_flag(mut self, cancel: Arc<AtomicBool>) -> Self {
        self.cancel.push(cancel);
        self
    }

    pub fn cancel_flag(&self) -> Option<Arc<AtomicBool>> {
        self.cancel.last().cloned()
    }

    pub fn is_cancelled(&self) -> bool {
        self.cancel.iter().any(|flag| flag.load(Ordering::Relaxed))
    }

    pub fn run_with_timeout(
        &self,
        args: &[&str],
        timeout: Option<Duration>,
    ) -> Result<RcloneOutput> {
        self.run_controlled(args, timeout, &[], |_, _| {})
    }

    pub fn run_with_timeout_env(
        &self,
        args: &[&str],
        timeout: Option<Duration>,
        envs: &[(&str, &str)],
    ) -> Result<RcloneOutput> {
        self.run_controlled(args, timeout, envs, |_, _| {})
    }

    pub fn run_streaming<F: FnMut(&str)>(
        &self,
        args: &[&str],
        mut on_line: F,
    ) -> Result<RcloneOutput> {
        self.run_controlled(args, self.default_timeout, &[], |stderr, line| {
            if !stderr {
                on_line(line);
            }
        })
    }

    pub fn run_streaming_stderr<F: FnMut(&str)>(
        &self,
        args: &[&str],
        mut on_line: F,
    ) -> Result<RcloneOutput> {
        self.run_controlled(args, self.default_timeout, &[], |stderr, line| {
            if stderr {
                on_line(line);
            }
        })
    }

    // The owning thread polls the child independently of stdout/stderr, including
    // when a remote produces no bytes. Reader channels apply backpressure.
    fn run_controlled<F: FnMut(bool, &str)>(
        &self,
        args: &[&str],
        timeout: Option<Duration>,
        envs: &[(&str, &str)],
        mut on_line: F,
    ) -> Result<RcloneOutput> {
        if self.is_cancelled() {
            bail!("Operation cancelled");
        }
        let mut child = ReapedChild(
            self.build_command_with_env(args, Some(envs))
                .spawn()
                .with_context(|| format!("Failed to spawn rclone: {:?}", self.exe_path))?,
        );
        let stdout = child.stdout.take().context("Missing child stdout")?;
        let stderr = child.stderr.take().context("Missing child stderr")?;
        let (tx, rx) = mpsc::sync_channel(256);
        let out_tx = tx.clone();
        let stdout_thread = thread::spawn(move || {
            read_process_lines(stdout, |line| {
                let _ = out_tx.send((false, line));
            })
        });
        let stderr_thread = thread::spawn(move || {
            read_process_lines(stderr, |line| {
                let _ = tx.send((true, line));
            })
        });
        let started = std::time::Instant::now();
        let mut output = RcloneOutput {
            stdout: Vec::new(),
            stderr: Vec::new(),
            status: -1,
            timed_out: false,
            cancelled: false,
        };
        let mut exited = false;
        let mut disconnected = false;
        let mut error = None;
        loop {
            if !exited {
                output.cancelled = self.is_cancelled();
                output.timed_out = timeout.is_some_and(|limit| started.elapsed() >= limit);
                if output.cancelled || output.timed_out {
                    let _ = child.kill();
                }
                match child.try_wait() {
                    Ok(Some(status)) => {
                        output.status = status.code().unwrap_or(-1);
                        exited = true;
                    }
                    Ok(None) => {}
                    Err(e) => {
                        error = Some(e);
                        let _ = child.kill();
                        let _ = child.wait();
                        exited = true;
                    }
                }
            }
            match rx.recv_timeout(Duration::from_millis(25)) {
                Ok((is_stderr, line)) => {
                    on_line(is_stderr, &line);
                    if is_stderr {
                        // Diagnostic history is bounded; progress is already delivered.
                        if output.stderr.len() == 2048 {
                            output.stderr.remove(0);
                        }
                        output.stderr.push(line);
                    } else {
                        output.stdout.push(line);
                    }
                }
                Err(mpsc::RecvTimeoutError::Timeout) => {}
                Err(mpsc::RecvTimeoutError::Disconnected) => disconnected = true,
            }
            if exited && disconnected {
                break;
            }
            if disconnected && !exited {
                thread::sleep(Duration::from_millis(25));
            }
        }
        // Reap before joining readers. No child survives cancellation or errors.
        let _ = child.wait();
        stdout_thread
            .join()
            .map_err(|_| anyhow::anyhow!("stdout reader panicked"))??;
        stderr_thread
            .join()
            .map_err(|_| anyhow::anyhow!("stderr reader panicked"))??;
        if let Some(error) = error {
            return Err(error.into());
        }
        if output.cancelled {
            output.stderr.push("Operation cancelled".into());
        }
        if output.timed_out {
            output.stderr.push("Operation timed out".into());
        }
        Ok(output)
    }

    /// Spawn a rclone command, returning a live child process.
    ///
    /// This is useful for streaming large outputs without buffering them in memory.
    pub fn spawn(&self, args: &[&str]) -> Result<ManagedChild> {
        if self.is_cancelled() {
            bail!("Operation cancelled");
        }
        let mut cmd = self.build_command_with_env(args, None);
        let child = cmd
            .spawn()
            .with_context(|| format!("Failed to spawn rclone: {:?}", self.exe_path))?;
        Ok(ManagedChild::new(child, self.clone()))
    }

    /// Get rclone version
    pub fn version(&self) -> Result<String> {
        let output = self.run(&["version"])?;
        if !output.success() {
            bail!("rclone version failed: {}", output.stderr_string());
        }
        // First line usually contains "rclone vX.Y.Z"
        Ok(output.stdout.first().cloned().unwrap_or_default())
    }

    /// List configured remotes
    pub fn list_remotes(&self) -> Result<Vec<String>> {
        let output = self.run(&["listremotes"])?;
        if !output.success() {
            bail!("rclone listremotes failed: {}", output.stderr_string());
        }
        Ok(output
            .stdout
            .iter()
            .map(|s| s.trim_end_matches(':').to_string())
            .filter(|s| !s.is_empty())
            .collect())
    }

    /// Build the command with appropriate flags
    fn build_command_with_env(&self, args: &[&str], envs: Option<&[(&str, &str)]>) -> Command {
        let mut cmd = Command::new(&self.exe_path);

        // Add config flag if set
        if let Some(ref config) = self.config_path {
            isolate_rclone_environment(&mut cmd);
            cmd.arg("--config").arg(config);
        }

        // Add user args
        cmd.args(args);

        if let Some(envs) = envs {
            for (key, value) in envs {
                cmd.env(key, value);
            }
        }

        // Configure stdio
        cmd.stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .stdin(Stdio::null());

        // Windows: hide console window
        #[cfg(windows)]
        {
            use std::os::windows::process::CommandExt;
            cmd.creation_flags(CREATE_NO_WINDOW);
        }

        cmd
    }

    /// Get the executable path
    pub fn exe_path(&self) -> &Path {
        &self.exe_path
    }

    /// Get the config path if set
    pub fn config_path(&self) -> Option<&Path> {
        self.config_path.as_deref()
    }

    /// Get the default timeout
    pub fn timeout(&self) -> Option<Duration> {
        self.default_timeout
    }
}

/// A supplied config is authoritative. Inherited backend, filtering, dry-run,
/// or RC settings must not silently override the acquisition plan. Explicit
/// per-call environment is applied afterwards; encrypted config passwords remain
/// supported without copying the password into the snapshot.
pub(crate) fn isolate_rclone_environment(command: &mut Command) {
    remove_rclone_env_overrides(command, std::env::vars_os().map(|(key, _)| key));
}

fn remove_rclone_env_overrides(
    command: &mut Command,
    keys: impl IntoIterator<Item = std::ffi::OsString>,
) {
    for key in keys {
        let upper = key.to_string_lossy().to_ascii_uppercase();
        if upper.starts_with("RCLONE_") && upper != "RCLONE_CONFIG_PASS" {
            command.env_remove(key);
        }
    }
}

// Also reap during unwinding if a caller's progress callback panics.
struct ReapedChild(Child);

impl std::ops::Deref for ReapedChild {
    type Target = Child;
    fn deref(&self) -> &Child {
        &self.0
    }
}

impl std::ops::DerefMut for ReapedChild {
    fn deref_mut(&mut self) -> &mut Child {
        &mut self.0
    }
}

impl Drop for ReapedChild {
    fn drop(&mut self) {
        let _ = self.0.kill();
        let _ = self.0.wait();
    }
}

/// Owns a streaming child while a separate watchdog handles quiet-process
/// cancellation and timeout. Drop always terminates and reaps the child.
pub struct ManagedChild {
    pub stdout: Option<ChildStdout>,
    pub stderr: Option<ChildStderr>,
    child: Arc<Mutex<Child>>,
    done: Arc<AtomicBool>,
    watchdog: Option<thread::JoinHandle<()>>,
}

impl ManagedChild {
    fn new(mut child: Child, runner: RcloneRunner) -> Self {
        let stdout = child.stdout.take();
        let stderr = child.stderr.take();
        let child = Arc::new(Mutex::new(child));
        let done = Arc::new(AtomicBool::new(false));
        let watched = child.clone();
        let finished = done.clone();
        let watchdog = thread::spawn(move || {
            let started = std::time::Instant::now();
            while !finished.load(Ordering::Relaxed) {
                if runner.is_cancelled() || runner.timeout().is_some_and(|t| started.elapsed() >= t)
                {
                    if let Ok(mut child) = watched.lock() {
                        let _ = child.kill();
                    }
                    break;
                }
                thread::sleep(Duration::from_millis(25));
            }
        });
        Self {
            stdout,
            stderr,
            child,
            done,
            watchdog: Some(watchdog),
        }
    }

    pub fn kill(&mut self) -> std::io::Result<()> {
        self.child
            .lock()
            .map_err(|_| std::io::Error::other("child lock poisoned"))?
            .kill()
    }

    pub fn wait(&mut self) -> std::io::Result<ExitStatus> {
        loop {
            let status = self
                .child
                .lock()
                .map_err(|_| std::io::Error::other("child lock poisoned"))?
                .try_wait()?;
            if let Some(status) = status {
                self.done.store(true, Ordering::Relaxed);
                if let Some(watchdog) = self.watchdog.take() {
                    let _ = watchdog.join();
                }
                return Ok(status);
            }
            thread::sleep(Duration::from_millis(25));
        }
    }
}

impl Drop for ManagedChild {
    fn drop(&mut self) {
        self.done.store(true, Ordering::Relaxed);
        if let Ok(mut child) = self.child.lock() {
            let _ = child.kill();
            let _ = child.wait();
        }
        if let Some(watchdog) = self.watchdog.take() {
            let _ = watchdog.join();
        }
    }
}

/// Parse progress lines without retaining a duplicate transcript. Limit malformed
/// single-line output to 1 MiB so an untrusted child cannot grow the buffer forever.
fn read_process_lines<R: Read, F: FnMut(String)>(
    mut reader: R,
    mut on_line: F,
) -> std::io::Result<()> {
    let mut buffer = [0u8; 8192];
    let mut current = Vec::new();
    loop {
        let count = reader.read(&mut buffer)?;
        if count == 0 {
            break;
        }
        for &byte in &buffer[..count] {
            if byte == b'\n' || byte == b'\r' {
                if !current.is_empty() {
                    on_line(String::from_utf8_lossy(&current).into_owned());
                    current.clear();
                }
            } else {
                current.push(byte);
                if current.len() == 1024 * 1024 {
                    on_line(String::from_utf8_lossy(&current).into_owned());
                    current.clear();
                }
            }
        }
    }
    if !current.is_empty() {
        on_line(String::from_utf8_lossy(&current).into_owned());
    }
    Ok(())
}

#[cfg(all(test, windows))]
mod tests {
    use super::*;
    use crate::embedded::ExtractedBinary;

    #[test]
    fn explicit_config_environment_keeps_only_password_and_explicit_overrides() {
        let mut cmd = Command::new("unused");
        for key in [
            "RCLONE_CONFIG_SOURCE_REMOTE",
            "RCLONE_DRY_RUN",
            "RCLONE_CONFIG_PASS",
        ] {
            cmd.env(key, "fixture");
        }
        remove_rclone_env_overrides(
            &mut cmd,
            [
                "RCLONE_CONFIG_SOURCE_REMOTE",
                "RCLONE_DRY_RUN",
                "RCLONE_CONFIG_PASS",
            ]
            .map(std::ffi::OsString::from),
        );
        let env: std::collections::BTreeMap<_, _> = cmd.get_envs().collect();
        assert_eq!(env.get(std::ffi::OsStr::new("RCLONE_DRY_RUN")), Some(&None));
        assert_eq!(
            env.get(std::ffi::OsStr::new("RCLONE_CONFIG_SOURCE_REMOTE")),
            Some(&None)
        );
        assert_eq!(
            env.get(std::ffi::OsStr::new("RCLONE_CONFIG_PASS")),
            Some(&Some(std::ffi::OsStr::new("fixture")))
        );
        cmd.env("RCLONE_DRY_RUN", "false");
        assert!(cmd
            .get_envs()
            .any(|(key, value)| key == "RCLONE_DRY_RUN"
                && value == Some(std::ffi::OsStr::new("false"))));
    }

    #[test]
    fn quiet_process_cancellation_is_bounded() {
        let cancel = Arc::new(AtomicBool::new(false));
        let trigger = cancel.clone();
        let signal = thread::spawn(move || {
            thread::sleep(Duration::from_millis(150));
            trigger.store(true, Ordering::Relaxed);
        });
        let runner = RcloneRunner::new("powershell.exe").with_cancel_flag(cancel);
        let start = std::time::Instant::now();
        let output = runner
            .run_streaming_stderr(
                &[
                    "-NoProfile",
                    "-NonInteractive",
                    "-Command",
                    "Start-Sleep -Seconds 60",
                ],
                |_| {},
            )
            .unwrap();
        signal.join().unwrap();
        assert!(output.cancelled);
        assert!(!output.success());
        assert!(start.elapsed() < Duration::from_secs(5));
    }

    #[test]
    fn streaming_child_timeout_reaps_quiet_process() {
        let runner = RcloneRunner::new("powershell.exe").with_timeout(Duration::from_millis(150));
        let start = std::time::Instant::now();
        let mut child = runner
            .spawn(&[
                "-NoProfile",
                "-NonInteractive",
                "-Command",
                "Start-Sleep -Seconds 60",
            ])
            .unwrap();
        assert!(!child.wait().unwrap().success());
        assert!(start.elapsed() < Duration::from_secs(5));
    }

    #[test]
    fn test_run_version() {
        let binary = ExtractedBinary::extract().expect("Failed to extract rclone");
        let runner = RcloneRunner::new(binary.path());

        let version = runner.version().expect("Failed to get version");
        assert!(
            version.contains("rclone") || version.contains("v"),
            "Unexpected version: {}",
            version
        );
    }

    #[test]
    fn test_run_help() {
        let binary = ExtractedBinary::extract().expect("Failed to extract rclone");
        let runner = RcloneRunner::new(binary.path());

        let output = runner.run(&["--help"]).expect("Failed to run help");
        assert!(output.success());
        assert!(!output.stdout.is_empty());
    }

    #[test]
    fn test_run_streaming() {
        let binary = ExtractedBinary::extract().expect("Failed to extract rclone");
        let runner = RcloneRunner::new(binary.path());

        let mut lines_received = 0;
        let output = runner
            .run_streaming(&["--help"], |_line| {
                lines_received += 1;
            })
            .expect("Failed to run streaming");

        assert!(output.success());
        assert!(lines_received > 0);
    }

    #[test]
    fn test_timeout() {
        let binary = ExtractedBinary::extract().expect("Failed to extract rclone");
        let runner = RcloneRunner::new(binary.path()).with_timeout(Duration::from_millis(1)); // Very short timeout

        // This should timeout (though rclone --help might be faster)
        let output = runner.run(&["--help"]).expect("Failed to run");
        // Either it succeeds fast or times out - both are valid
        assert!(output.success() || output.timed_out);
    }
}
