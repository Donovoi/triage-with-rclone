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

/// Test connectivity with automatic retries and exponential backoff.
///
/// Returns after the first successful check or after all `max_retries` extra attempts fail.
pub fn test_connectivity_with_retry(
    rclone: &RcloneRunner,
    remote_name: &str,
    max_retries: u32,
) -> Result<ConnectivityResult> {
    let mut result = test_connectivity(rclone, remote_name)?;
    let mut attempt = 1u32;
    while !result.ok && attempt <= max_retries {
        let delay = retry_delay(attempt - 1);
        std::thread::sleep(delay);
        result = test_connectivity(rclone, remote_name)?;
        attempt += 1;
    }
    Ok(ConnectivityResult {
        attempts: attempt,
        ..result
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_retry_delay_exponential_backoff() {
        assert_eq!(retry_delay(0), Duration::from_secs(1));
        assert_eq!(retry_delay(1), Duration::from_secs(2));
        assert_eq!(retry_delay(2), Duration::from_secs(4));
        assert_eq!(retry_delay(3), Duration::from_secs(8));
        assert_eq!(retry_delay(4), Duration::from_secs(16));
    }

    #[test]
    fn test_retry_delay_caps_at_16s() {
        // Attempts >= 4 should all be 16s (capped by min(4))
        assert_eq!(retry_delay(5), Duration::from_secs(16));
        assert_eq!(retry_delay(10), Duration::from_secs(16));
        assert_eq!(retry_delay(100), Duration::from_secs(16));
    }
}
