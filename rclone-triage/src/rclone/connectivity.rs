//! Connectivity tests for rclone remotes

use anyhow::Result;
use std::time::{Duration, Instant};

use crate::rclone::RcloneRunner;

/// Result of a connectivity check
#[derive(Debug, Clone)]
pub struct ConnectivityResult {
    pub ok: bool,
    pub duration: Duration,
    pub error: Option<String>,
    /// Number of attempts made before success or final failure
    pub attempts: u32,
}

/// Test connectivity to a remote by running a shallow lsjson (single attempt).
pub fn test_connectivity(rclone: &RcloneRunner, remote_name: &str) -> Result<ConnectivityResult> {
    let target = format!("{}:", remote_name);
    let start = Instant::now();
    let output = rclone.run(&["lsjson", "--max-depth", "1", "-v", &target])?;
    let duration = start.elapsed();

    if output.success() {
        Ok(ConnectivityResult {
            ok: true,
            duration,
            error: None,
            attempts: 1,
        })
    } else {
        let error = if output.stderr_string().trim().is_empty() {
            if output.stdout_string().trim().is_empty() {
                format!(
                    "rclone lsjson failed (exit code {}). Check that the remote is properly configured and the token is valid.",
                    output.status
                )
            } else {
                output.stdout_string()
            }
        } else {
            output.stderr_string()
        };
        Ok(ConnectivityResult {
            ok: false,
            duration,
            error: Some(error),
            attempts: 1,
        })
    }
}

/// Compute the retry delay for a given attempt (exponential backoff: 1s, 2s, 4s, …).
pub fn retry_delay(attempt: u32) -> Duration {
    Duration::from_secs(1u64 << attempt.min(4))
}
