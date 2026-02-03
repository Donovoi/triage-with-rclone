//! HTTP helpers with retry logic.

use anyhow::{bail, Context, Result};
use serde_json::Value;
use std::thread::sleep;
use std::time::Duration;

/// GET JSON with exponential backoff retries.
pub fn http_get_json_with_retry(
    url: &str,
    max_retries: usize,
    base_delay_secs: u64,
) -> Result<Value> {
    let mut attempt = 0usize;
    let mut delay = base_delay_secs.max(1);

    loop {
        attempt += 1;
        let response = ureq::get(url).call();
        match response {
            Ok(resp) => {
                let value: Value = serde_json::from_reader(resp.into_reader())
                    .context("Failed to parse JSON response")?;
                return Ok(value);
            }
            Err(ureq::Error::Status(code, resp)) => {
                let text = resp.into_string().unwrap_or_default();
                if attempt > max_retries {
                    bail!("HTTP {} after {} attempts: {}", code, attempt, text);
                }
            }
            Err(e) => {
                if attempt > max_retries {
                    return Err(e.into());
                }
            }
        }

        sleep(Duration::from_secs(delay));
        delay = (delay * 2).min(60);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_http_get_json_with_retry_invalid_url() {
        let result = http_get_json_with_retry("http://127.0.0.1:1", 1, 1);
        assert!(result.is_err());
    }
}
