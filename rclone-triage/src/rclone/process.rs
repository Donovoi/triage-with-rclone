//! Rclone process runner
//!
//! Wraps spawning rclone processes with Windows-specific handling
//! for hiding console windows and capturing output.

use anyhow::{bail, Context, Result};
use std::io::{BufRead, BufReader};
use std::path::{Path, PathBuf};
use std::process::{Child, Command, ExitStatus, Stdio};
use std::sync::mpsc::{self, Receiver, Sender};
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
}

impl RcloneOutput {
    /// Check if the command succeeded
    pub fn success(&self) -> bool {
        self.status == 0 && !self.timed_out
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
pub struct RcloneRunner {
    /// Path to rclone executable
    exe_path: PathBuf,
    /// Path to rclone config file (optional)
    config_path: Option<PathBuf>,
    /// Default timeout for commands
    default_timeout: Option<Duration>,
}

impl RcloneRunner {
    /// Create a new rclone runner
    pub fn new(exe_path: impl AsRef<Path>) -> Self {
        Self {
            exe_path: exe_path.as_ref().to_path_buf(),
            config_path: None,
            default_timeout: None,
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

    /// Run a rclone command with a specific timeout
    pub fn run_with_timeout(
        &self,
        args: &[&str],
        timeout: Option<Duration>,
    ) -> Result<RcloneOutput> {
        let mut cmd = self.build_command_with_env(args, None);

        // Spawn the process
        let mut child = cmd
            .spawn()
            .with_context(|| format!("Failed to spawn rclone: {:?}", self.exe_path))?;

        // Set up output capture
        let stdout = child.stdout.take().expect("stdout piped");
        let stderr = child.stderr.take().expect("stderr piped");

        let (stdout_tx, stdout_rx) = mpsc::channel();
        let (stderr_tx, stderr_rx) = mpsc::channel();

        // Spawn threads to capture output
        let stdout_thread = thread::spawn(move || {
            capture_output(stdout, stdout_tx);
        });

        let stderr_thread = thread::spawn(move || {
            capture_output(stderr, stderr_tx);
        });

        // Wait for process with optional timeout
        let (status, timed_out) = match timeout {
            Some(duration) => wait_with_timeout(&mut child, duration)?,
            None => (child.wait()?, false),
        };

        // Wait for output threads
        stdout_thread.join().expect("stdout thread panicked");
        stderr_thread.join().expect("stderr thread panicked");

        // Collect output
        let stdout: Vec<String> = stdout_rx.try_iter().collect();
        let stderr: Vec<String> = stderr_rx.try_iter().collect();

        Ok(RcloneOutput {
            stdout,
            stderr,
            status: status.code().unwrap_or(-1),
            timed_out,
        })
    }

    /// Run a rclone command with a specific timeout and env overrides
    pub fn run_with_timeout_env(
        &self,
        args: &[&str],
        timeout: Option<Duration>,
        envs: &[(&str, &str)],
    ) -> Result<RcloneOutput> {
        let mut cmd = self.build_command_with_env(args, Some(envs));

        // Spawn the process
        let mut child = cmd
            .spawn()
            .with_context(|| format!("Failed to spawn rclone: {:?}", self.exe_path))?;

        // Set up output capture
        let stdout = child.stdout.take().expect("stdout piped");
        let stderr = child.stderr.take().expect("stderr piped");

        let (stdout_tx, stdout_rx) = mpsc::channel();
        let (stderr_tx, stderr_rx) = mpsc::channel();

        // Spawn threads to capture output
        let stdout_thread = thread::spawn(move || {
            capture_output(stdout, stdout_tx);
        });

        let stderr_thread = thread::spawn(move || {
            capture_output(stderr, stderr_tx);
        });

        // Wait for process with optional timeout
        let (status, timed_out) = match timeout {
            Some(duration) => wait_with_timeout(&mut child, duration)?,
            None => (child.wait()?, false),
        };

        // Wait for output threads
        stdout_thread.join().expect("stdout thread panicked");
        stderr_thread.join().expect("stderr thread panicked");

        // Collect output
        let stdout: Vec<String> = stdout_rx.try_iter().collect();
        let stderr: Vec<String> = stderr_rx.try_iter().collect();

        Ok(RcloneOutput {
            stdout,
            stderr,
            status: status.code().unwrap_or(-1),
            timed_out,
        })
    }

    /// Run rclone with streaming callback for stdout
    pub fn run_streaming<F>(&self, args: &[&str], mut on_line: F) -> Result<RcloneOutput>
    where
        F: FnMut(&str),
    {
        let mut cmd = self.build_command_with_env(args, None);

        let mut child = cmd
            .spawn()
            .with_context(|| format!("Failed to spawn rclone: {:?}", self.exe_path))?;

        let stdout = child.stdout.take().expect("stdout piped");
        let stderr = child.stderr.take().expect("stderr piped");

        // Capture stderr in background
        let (stderr_tx, stderr_rx) = mpsc::channel();
        let stderr_thread = thread::spawn(move || {
            capture_output(stderr, stderr_tx);
        });

        // Stream stdout
        let mut stdout_lines: Vec<String> = Vec::new();
        let reader = BufReader::new(stdout);
        for line in reader.lines() {
            if let Ok(line) = line {
                on_line(&line);
                stdout_lines.push(line);
            }
        }

        let status = child.wait()?;
        stderr_thread.join().expect("stderr thread panicked");
        let stderr: Vec<String> = stderr_rx.try_iter().collect();

        Ok(RcloneOutput {
            stdout: stdout_lines,
            stderr,
            status: status.code().unwrap_or(-1),
            timed_out: false,
        })
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
}

/// Capture output from a reader and send it through a channel
fn capture_output<R: std::io::Read>(reader: R, tx: Sender<String>) {
    let reader = BufReader::new(reader);
    for line in reader.lines() {
        if let Ok(line) = line {
            let _ = tx.send(line);
        }
    }
}

/// Wait for a child process with timeout
fn wait_with_timeout(child: &mut Child, timeout: Duration) -> Result<(ExitStatus, bool)> {
    let start = std::time::Instant::now();
    loop {
        match child.try_wait()? {
            Some(status) => return Ok((status, false)),
            None => {
                if start.elapsed() > timeout {
                    // Kill the process
                    let _ = child.kill();
                    // Wait for it to finish
                    let status = child.wait()?;
                    return Ok((status, true));
                }
                thread::sleep(Duration::from_millis(100));
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::embedded::ExtractedBinary;

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
