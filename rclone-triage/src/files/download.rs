//! Download queue and file copy operations

use anyhow::{bail, Result};
use sha2::{Digest, Sha256};
use std::collections::VecDeque;
use std::fs::File;
use std::io::{BufReader, Read};
use std::path::Path;
use std::sync::{mpsc, Arc, Mutex};
use std::thread;
use std::time::Duration;

use crate::rclone::{RcloneOutput, RcloneRunner};

/// Download mode
#[allow(dead_code)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DownloadMode {
    /// Copy directory or remote path
    Copy,
    /// Copy a single file to a specific destination
    CopyTo,
}

/// Phase of a download operation
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DownloadPhase {
    Starting,
    InProgress,
    Completed,
    Failed,
}

/// Progress of a download operation
#[derive(Debug, Clone)]
pub struct DownloadProgress {
    /// Current phase
    pub phase: DownloadPhase,
    /// Current file index (0-based)
    pub current: usize,
    /// Total number of files
    pub total: usize,
    /// Current file path being downloaded
    pub current_file: String,
    /// Status message
    pub status: String,
    /// Bytes downloaded so far for current file (if available)
    pub bytes_done: Option<u64>,
    /// Total bytes for current file (if available)
    pub bytes_total: Option<u64>,
}

impl DownloadProgress {
    /// Create a new progress update for starting a file download
    pub fn starting(current: usize, total: usize, file: &str) -> Self {
        Self {
            phase: DownloadPhase::Starting,
            current,
            total,
            current_file: file.to_string(),
            status: format!("Downloading {}/{}: {}", current + 1, total, file),
            bytes_done: None,
            bytes_total: None,
        }
    }

    /// Create a progress update during a download
    pub fn progress(current: usize, total: usize, file: &str, done: u64, total_bytes: u64) -> Self {
        let percent = if total_bytes > 0 {
            (done as f64 / total_bytes as f64) * 100.0
        } else {
            0.0
        };
        Self {
            phase: DownloadPhase::InProgress,
            current,
            total,
            current_file: file.to_string(),
            status: format!(
                "Downloading {}/{}: {} ({:.0}% - {} / {} bytes)",
                current + 1,
                total,
                file,
                percent,
                done,
                total_bytes
            ),
            bytes_done: Some(done),
            bytes_total: Some(total_bytes),
        }
    }

    /// Create a progress update for completed file
    pub fn completed(current: usize, total: usize, file: &str, size: u64) -> Self {
        Self {
            phase: DownloadPhase::Completed,
            current,
            total,
            current_file: file.to_string(),
            status: format!(
                "Downloaded {}/{}: {} ({} bytes)",
                current + 1,
                total,
                file,
                size
            ),
            bytes_done: Some(size),
            bytes_total: Some(size),
        }
    }

    /// Create a progress update for failed file
    pub fn failed(current: usize, total: usize, file: &str, error: &str) -> Self {
        Self {
            phase: DownloadPhase::Failed,
            current,
            total,
            current_file: file.to_string(),
            status: format!("Failed {}/{}: {} - {}", current + 1, total, file, error),
            bytes_done: None,
            bytes_total: None,
        }
    }

    /// Get percentage complete (0-100)
    pub fn percent(&self) -> u8 {
        if self.total == 0 {
            return 0;
        }
        ((self.current as f64 / self.total as f64) * 100.0) as u8
    }
}

/// Result of a single download
#[derive(Debug, Clone)]
pub struct DownloadResult {
    /// Source path
    pub source: String,
    /// Destination path
    pub destination: String,
    /// Whether download succeeded
    pub success: bool,
    /// Error message if failed
    pub error: Option<String>,
    /// File size after download
    pub size: Option<u64>,
    /// Computed hash after download
    pub hash: Option<String>,
    /// Hash type used
    pub hash_type: Option<String>,
    /// Whether hash was verified against expected
    pub hash_verified: Option<bool>,
    /// Hash verification error (best-effort; download still succeeds)
    pub hash_error: Option<String>,
}

/// A single download request
#[derive(Debug, Clone)]
pub struct DownloadRequest {
    pub source: String,
    pub destination: String,
    pub mode: DownloadMode,
    /// Expected hash for verification (from file listing)
    pub expected_hash: Option<String>,
    /// Hash type (sha256, md5, etc.)
    pub expected_hash_type: Option<String>,
    /// Expected size (bytes) for progress calculations
    pub expected_size: Option<u64>,
}

#[allow(dead_code)]
impl DownloadRequest {
    pub fn new_copy(source: impl Into<String>, destination: impl Into<String>) -> Self {
        Self {
            source: source.into(),
            destination: destination.into(),
            mode: DownloadMode::Copy,
            expected_hash: None,
            expected_hash_type: None,
            expected_size: None,
        }
    }

    pub fn new_copyto(source: impl Into<String>, destination: impl Into<String>) -> Self {
        Self {
            source: source.into(),
            destination: destination.into(),
            mode: DownloadMode::CopyTo,
            expected_hash: None,
            expected_hash_type: None,
            expected_size: None,
        }
    }

    /// Set expected hash for verification
    pub fn with_hash(mut self, hash: Option<String>, hash_type: Option<String>) -> Self {
        self.expected_hash = hash;
        self.expected_hash_type = hash_type;
        self
    }

    /// Set expected size for progress calculations
    pub fn with_size(mut self, size: Option<u64>) -> Self {
        self.expected_size = size;
        self
    }
}

/// Download queue
#[derive(Debug, Clone)]
pub struct DownloadQueue {
    pub requests: Vec<DownloadRequest>,
    pub parallel: usize,
    pub timeout: Option<Duration>,
    pub dry_run: bool,
    /// Whether to verify hashes after download
    pub verify_hashes: bool,
}

#[allow(dead_code)]
impl DownloadQueue {
    pub fn new() -> Self {
        Self {
            requests: Vec::new(),
            parallel: 4,
            timeout: None,
            dry_run: false,
            verify_hashes: true,
        }
    }

    pub fn add(&mut self, request: DownloadRequest) {
        self.requests.push(request);
    }

    pub fn set_parallel(&mut self, parallel: usize) {
        self.parallel = parallel.max(1);
    }

    pub fn set_timeout(&mut self, timeout: Duration) {
        self.timeout = Some(timeout);
    }

    pub fn set_dry_run(&mut self, dry_run: bool) {
        self.dry_run = dry_run;
    }

    pub fn set_verify_hashes(&mut self, verify: bool) {
        self.verify_hashes = verify;
    }

    /// Build rclone args for a request
    pub fn build_args(&self, request: &DownloadRequest) -> Vec<String> {
        let mut args = match request.mode {
            DownloadMode::Copy => vec![
                "copy".to_string(),
                request.source.clone(),
                request.destination.clone(),
            ],
            DownloadMode::CopyTo => vec![
                "copyto".to_string(),
                request.source.clone(),
                request.destination.clone(),
            ],
        };

        // Add progress stats for both copy and copyto (used by TUI)
        args.push("--progress".to_string());
        args.push("--stats".to_string());
        args.push("1s".to_string());

        if self.dry_run {
            args.push("--dry-run".to_string());
        }
        args
    }

    /// Execute all downloads sequentially (parallel execution can be added later)
    pub fn download_all(&self, rclone: &RcloneRunner) -> Result<Vec<RcloneOutput>> {
        let mut outputs = Vec::new();
        for request in &self.requests {
            let output = self.download_one(rclone, request)?;
            outputs.push(output);
        }
        Ok(outputs)
    }

    /// Execute all downloads with progress callback
    ///
    /// The callback is called before each download starts, after each completes,
    /// and when a download fails.
    pub fn download_all_with_progress<F>(
        &self,
        rclone: &RcloneRunner,
        mut progress_callback: F,
    ) -> Vec<DownloadResult>
    where
        F: FnMut(DownloadProgress),
    {
        if self.parallel <= 1 {
        let total = self.requests.len();
        let mut results = Vec::with_capacity(total);

        for (i, request) in self.requests.iter().enumerate() {
            // Notify starting
            progress_callback(DownloadProgress::starting(i, total, &request.source));

            let result = if self.timeout.is_some() {
                // Timeout handling isn't supported for streaming progress yet
                self.download_one_verified(rclone, request)
            } else {
                self.download_one_verified_with_progress(rclone, request, |done, total_bytes| {
                    progress_callback(DownloadProgress::progress(
                        i,
                        total,
                        &request.source,
                        done,
                        total_bytes,
                    ));
                })
            };
            match &result {
                DownloadResult {
                    success: true,
                    size,
                    ..
                } => {
                    progress_callback(DownloadProgress::completed(
                        i,
                        total,
                        &request.source,
                        size.unwrap_or(0),
                    ));
                }
                DownloadResult {
                    success: false,
                    error,
                    ..
                } => {
                    progress_callback(DownloadProgress::failed(
                        i,
                        total,
                        &request.source,
                        error.as_deref().unwrap_or("Unknown error"),
                    ));
                }
            }
            results.push(result);
        }

        results
        } else {
            self.download_all_parallel_with_progress(rclone, &mut progress_callback)
        }
    }

    fn download_all_parallel_with_progress<F>(
        &self,
        rclone: &RcloneRunner,
        progress_callback: &mut F,
    ) -> Vec<DownloadResult>
    where
        F: FnMut(DownloadProgress),
    {
        #[derive(Debug)]
        enum Event {
            Progress(DownloadProgress),
            Result(usize, DownloadResult),
        }

        let total = self.requests.len();
        let queue: Arc<Mutex<VecDeque<(usize, DownloadRequest)>>> = Arc::new(Mutex::new(
            self.requests
                .iter()
                .cloned()
                .enumerate()
                .collect::<VecDeque<_>>(),
        ));

        let (event_tx, event_rx) = mpsc::channel::<Event>();
        let mut handles = Vec::new();

        for _ in 0..self.parallel {
            let queue = Arc::clone(&queue);
            let event_tx = event_tx.clone();

            let mut runner = RcloneRunner::new(rclone.exe_path());
            if let Some(config) = rclone.config_path() {
                runner = runner.with_config(config);
            }
            if let Some(timeout) = rclone.timeout() {
                runner = runner.with_timeout(timeout);
            }

            let verify_hashes = self.verify_hashes;

            let handle = thread::spawn(move || {
                loop {
                    let next = {
                        let mut guard = queue.lock().expect("download queue lock");
                        guard.pop_front()
                    };

                    let (index, request) = match next {
                        Some(item) => item,
                        None => break,
                    };

                    let total_files = total;
                    let _ = event_tx.send(Event::Progress(DownloadProgress::starting(
                        index,
                        total_files,
                        &request.source,
                    )));

                    let result = if runner.timeout().is_some() {
                        let mut queue = DownloadQueue::new();
                        queue.set_verify_hashes(verify_hashes);
                        queue.download_one_verified(&runner, &request)
                    } else {
                        let mut queue = DownloadQueue::new();
                        queue.set_verify_hashes(verify_hashes);
                        queue.download_one_verified_with_progress(
                            &runner,
                            &request,
                            |done, total_bytes| {
                                let _ = event_tx.send(Event::Progress(
                                    DownloadProgress::progress(
                                        index,
                                        total_files,
                                        &request.source,
                                        done,
                                        total_bytes,
                                    ),
                                ));
                            },
                        )
                    };

                    match &result {
                        DownloadResult {
                            success: true,
                            size,
                            ..
                        } => {
                            let _ = event_tx.send(Event::Progress(DownloadProgress::completed(
                                index,
                                total_files,
                                &request.source,
                                size.unwrap_or(0),
                            )));
                        }
                        DownloadResult {
                            success: false,
                            error,
                            ..
                        } => {
                            let _ = event_tx.send(Event::Progress(DownloadProgress::failed(
                                index,
                                total_files,
                                &request.source,
                                error.as_deref().unwrap_or("Unknown error"),
                            )));
                        }
                    }

                    let _ = event_tx.send(Event::Result(index, result));
                }
            });

            handles.push(handle);
        }

        drop(event_tx);

        let mut results: Vec<Option<DownloadResult>> = vec![None; total];
        let mut completed = 0;

        while completed < total {
            match event_rx.recv() {
                Ok(Event::Progress(progress)) => progress_callback(progress),
                Ok(Event::Result(index, result)) => {
                    if results[index].is_none() {
                        results[index] = Some(result);
                        completed += 1;
                    }
                }
                Err(_) => break,
            }
        }

        for handle in handles {
            let _ = handle.join();
        }

        results.into_iter().flatten().collect()
    }

    /// Execute a single download with hash verification and progress parsing
    fn download_one_verified_with_progress<F>(
        &self,
        rclone: &RcloneRunner,
        request: &DownloadRequest,
        mut progress_callback: F,
    ) -> DownloadResult
    where
        F: FnMut(u64, u64),
    {
        let args = self.build_args(request);
        let args_ref: Vec<&str> = args.iter().map(|s| s.as_str()).collect();

        let expected_size = request.expected_size;

        let output = rclone.run_streaming_stderr(&args_ref, |line| {
            if let Some((done, total)) = parse_transferred_progress(line, expected_size) {
                progress_callback(done, total);
            }
        });

        match output {
            Ok(output) if output.success() => {
                // Get file metadata
                let dest_path = Path::new(&request.destination);
                let size = std::fs::metadata(dest_path).ok().map(|m| m.len());

                // Compute hash if verification enabled and we have an expected hash
                let (hash, hash_type, hash_verified, hash_error) =
                    if self.verify_hashes && request.expected_hash.is_some() {
                        match request.expected_hash_type.as_deref() {
                            Some(hash_type) => match compute_file_hash_best_effort(rclone, dest_path, hash_type) {
                                Ok(computed) => {
                                    let verified = request
                                        .expected_hash
                                        .as_ref()
                                        .map(|expected| expected.eq_ignore_ascii_case(&computed))
                                        .unwrap_or(false);
                                    (Some(computed), Some(hash_type.to_string()), Some(verified), None)
                                }
                                Err(e) => (
                                    None,
                                    Some(hash_type.to_string()),
                                    None,
                                    Some(format!("Hash verification skipped: {}", e)),
                                ),
                            },
                            None => (
                                None,
                                None,
                                None,
                                Some("Expected hash present but no hash type provided".to_string()),
                            ),
                        }
                    } else {
                        (None, None, None, None)
                    };

                DownloadResult {
                    source: request.source.clone(),
                    destination: request.destination.clone(),
                    success: true,
                    error: None,
                    size,
                    hash,
                    hash_type,
                    hash_verified,
                    hash_error,
                }
            }
            Ok(output) => DownloadResult {
                source: request.source.clone(),
                destination: request.destination.clone(),
                success: false,
                error: Some(output.stderr_string()),
                size: None,
                hash: None,
                hash_type: None,
                hash_verified: None,
                hash_error: None,
            },
            Err(e) => DownloadResult {
                source: request.source.clone(),
                destination: request.destination.clone(),
                success: false,
                error: Some(e.to_string()),
                size: None,
                hash: None,
                hash_type: None,
                hash_verified: None,
                hash_error: None,
            },
        }
    }

    /// Execute a single download with hash verification
    pub fn download_one_verified(
        &self,
        rclone: &RcloneRunner,
        request: &DownloadRequest,
    ) -> DownloadResult {
        let args = self.build_args(request);
        let args_ref: Vec<&str> = args.iter().map(|s| s.as_str()).collect();

        let output = match self.timeout {
            Some(timeout) => rclone.run_with_timeout(&args_ref, Some(timeout)),
            None => rclone.run(&args_ref),
        };

        match output {
            Ok(output) if output.success() => {
                // Get file metadata
                let dest_path = Path::new(&request.destination);
                let size = std::fs::metadata(dest_path).ok().map(|m| m.len());

                // Compute hash if verification enabled and we have an expected hash
                let (hash, hash_type, hash_verified, hash_error) =
                    if self.verify_hashes && request.expected_hash.is_some() {
                        match request.expected_hash_type.as_deref() {
                            Some(hash_type) => match compute_file_hash_best_effort(rclone, dest_path, hash_type) {
                                Ok(computed) => {
                                    let verified = request
                                        .expected_hash
                                        .as_ref()
                                        .map(|expected| expected.eq_ignore_ascii_case(&computed))
                                        .unwrap_or(false);
                                    (Some(computed), Some(hash_type.to_string()), Some(verified), None)
                                }
                                Err(e) => (
                                    None,
                                    Some(hash_type.to_string()),
                                    None,
                                    Some(format!("Hash verification skipped: {}", e)),
                                ),
                            },
                            None => (
                                None,
                                None,
                                None,
                                Some("Expected hash present but no hash type provided".to_string()),
                            ),
                        }
                    } else {
                        (None, None, None, None)
                    };

                DownloadResult {
                    source: request.source.clone(),
                    destination: request.destination.clone(),
                    success: true,
                    error: None,
                    size,
                    hash,
                    hash_type,
                    hash_verified,
                    hash_error,
                }
            }
            Ok(output) => DownloadResult {
                source: request.source.clone(),
                destination: request.destination.clone(),
                success: false,
                error: Some(output.stderr_string()),
                size: None,
                hash: None,
                hash_type: None,
                hash_verified: None,
                hash_error: None,
            },
            Err(e) => DownloadResult {
                source: request.source.clone(),
                destination: request.destination.clone(),
                success: false,
                error: Some(e.to_string()),
                size: None,
                hash: None,
                hash_type: None,
                hash_verified: None,
                hash_error: None,
            },
        }
    }

    /// Execute a single download
    pub fn download_one(
        &self,
        rclone: &RcloneRunner,
        request: &DownloadRequest,
    ) -> Result<RcloneOutput> {
        let args = self.build_args(request);
        let args_ref: Vec<&str> = args.iter().map(|s| s.as_str()).collect();

        let output = match self.timeout {
            Some(timeout) => rclone.run_with_timeout(&args_ref, Some(timeout))?,
            None => rclone.run(&args_ref)?,
        };

        if !output.success() {
            bail!("Download failed: {}", output.stderr_string());
        }

        Ok(output)
    }
}

impl Default for DownloadQueue {
    fn default() -> Self {
        Self::new()
    }
}

/// Compute hash of a file
pub fn compute_file_hash(path: &Path, hash_type: &str) -> Result<String> {
    let mut file = File::open(path)?;
    let mut reader = BufReader::new(&mut file);
    let mut buffer = vec![0u8; 1024 * 1024];

    match hash_type.to_lowercase().as_str() {
        "sha256" => {
            let mut hasher = Sha256::new();
            loop {
                let read = reader.read(&mut buffer)?;
                if read == 0 {
                    break;
                }
                hasher.update(&buffer[..read]);
            }
            Ok(format!("{:x}", hasher.finalize()))
        }
        "md5" => {
            let mut context = md5::Context::new();
            loop {
                let read = reader.read(&mut buffer)?;
                if read == 0 {
                    break;
                }
                context.consume(&buffer[..read]);
            }
            Ok(format!("{:x}", context.compute()))
        }
        "sha1" => {
            use sha1::{Digest as Sha1Digest, Sha1};
            let mut hasher = Sha1::new();
            loop {
                let read = reader.read(&mut buffer)?;
                if read == 0 {
                    break;
                }
                hasher.update(&buffer[..read]);
            }
            Ok(format!("{:x}", hasher.finalize()))
        }
        _ => bail!("Unsupported hash type: {}", hash_type),
    }
}

fn compute_file_hash_with_rclone(rclone: &RcloneRunner, path: &Path, hash_type: &str) -> Result<String> {
    let path_str = path.to_string_lossy();
    let args = ["hashsum", hash_type, path_str.as_ref()];
    let output = rclone.run(&args)?;
    if !output.success() {
        bail!("rclone hashsum failed: {}", output.stderr_string());
    }
    let first_line = output
        .stdout
        .iter()
        .find(|line| !line.trim().is_empty())
        .ok_or_else(|| anyhow::anyhow!("rclone hashsum returned no output"))?;
    let hash = first_line
        .split_whitespace()
        .next()
        .ok_or_else(|| anyhow::anyhow!("Failed to parse rclone hashsum output"))?;
    Ok(hash.to_string())
}

fn compute_file_hash_best_effort(
    rclone: &RcloneRunner,
    path: &Path,
    hash_type: &str,
) -> Result<String> {
    match hash_type.to_lowercase().as_str() {
        "sha256" | "sha1" | "md5" => compute_file_hash(path, hash_type),
        _ => compute_file_hash_with_rclone(rclone, path, hash_type),
    }
}

fn parse_transferred_progress(line: &str, expected_total: Option<u64>) -> Option<(u64, u64)> {
    if let Some((done, total)) = parse_transferred_bytes(line) {
        return Some((done, total));
    }

    if let (Some(percent), Some(total)) = (parse_transferred_percent(line), expected_total) {
        let done = ((total as f64) * (percent / 100.0)).round() as u64;
        return Some((done.min(total), total));
    }

    None
}

fn parse_transferred_bytes(line: &str) -> Option<(u64, u64)> {
    let idx = line.find("Transferred:")?;
    let after = line[idx + "Transferred:".len()..].trim();
    let first = after.split(',').next()?.trim();
    let mut parts = first.split('/');
    let done_str = parts.next()?.trim();
    let total_str = parts.next()?.trim();

    let done = parse_size_to_bytes(done_str)?;
    let total = parse_size_to_bytes(total_str)?;
    Some((done, total))
}

fn parse_transferred_percent(line: &str) -> Option<f64> {
    if !line.contains("Transferred:") {
        return None;
    }
    for part in line.split(',') {
        let trimmed = part.trim();
        if let Some(percent_idx) = trimmed.find('%') {
            let mut number = trimmed[..percent_idx].trim();
            if let Some(rest) = number.strip_prefix("Transferred:") {
                number = rest.trim();
            }
            if let Ok(value) = number.parse::<f64>() {
                return Some(value);
            }
        }
    }
    None
}

fn parse_size_to_bytes(input: &str) -> Option<u64> {
    let trimmed = input.trim();
    if trimmed.is_empty() {
        return None;
    }

    let mut parts = trimmed.split_whitespace();
    let first = parts.next()?;
    let (number_str, unit_str) = if let Some(unit) = parts.next() {
        (first, unit)
    } else if let Some(idx) = first.find(|c: char| c.is_ascii_alphabetic()) {
        first.split_at(idx)
    } else {
        return None;
    };

    let number_str = number_str.replace(',', "");
    let value: f64 = number_str.parse().ok()?;
    let unit = unit_str.trim().trim_end_matches("/s").to_ascii_lowercase();

    let multiplier = match unit.as_str() {
        "b" | "byte" | "bytes" => 1.0,
        "kb" => 1_000.0,
        "kib" => 1_024.0,
        "mb" => 1_000_000.0,
        "mib" => 1_048_576.0,
        "gb" => 1_000_000_000.0,
        "gib" => 1_073_741_824.0,
        "tb" => 1_000_000_000_000.0,
        "tib" => 1_099_511_627_776.0,
        "pb" => 1_000_000_000_000_000.0,
        "pib" => 1_125_899_906_842_624.0,
        "eb" => 1_000_000_000_000_000_000.0,
        "eib" => 1_152_921_504_606_846_976.0,
        _ => return None,
    };

    Some((value * multiplier) as u64)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;
    use tempfile::tempdir;

    #[cfg(windows)]
    use crate::embedded::ExtractedBinary;

    #[test]
    fn test_build_args_copy() {
        let queue = DownloadQueue::new();
        let req = DownloadRequest::new_copy("src", "dest");
        let args = queue.build_args(&req);
        assert_eq!(args[0], "copy");
    }

    #[test]
    fn test_build_args_copyto() {
        let queue = DownloadQueue::new();
        let req = DownloadRequest::new_copyto("src", "dest");
        let args = queue.build_args(&req);
        assert_eq!(args[0], "copyto");
    }

    #[test]
    fn test_download_request_with_hash() {
        let req = DownloadRequest::new_copyto("src", "dest")
            .with_hash(Some("abc123".to_string()), Some("sha256".to_string()));
        assert_eq!(req.expected_hash, Some("abc123".to_string()));
        assert_eq!(req.expected_hash_type, Some("sha256".to_string()));
    }

    #[test]
    fn test_parse_transferred_bytes() {
        let line =
            "Transferred:   1.00 MiB / 2.00 MiB, 50%, 1.00 MiB/s, ETA 1s";
        let parsed = parse_transferred_bytes(line).unwrap();
        assert_eq!(parsed.0, 1_048_576);
        assert_eq!(parsed.1, 2_097_152);
    }

    #[test]
    fn test_parse_transferred_bytes_compact_units() {
        let line = "Transferred: 512KiB / 1MiB, 50%, 1MiB/s, ETA 1s";
        let parsed = parse_transferred_bytes(line).unwrap();
        assert_eq!(parsed.0, 524_288);
        assert_eq!(parsed.1, 1_048_576);
    }

    #[test]
    fn test_parse_transferred_percent_fallback() {
        let line = "Transferred: 50%, 1.00 MiB/s, ETA 1s";
        let parsed = parse_transferred_progress(line, Some(2_000)).unwrap();
        assert_eq!(parsed.0, 1_000);
        assert_eq!(parsed.1, 2_000);
    }

    #[test]
    fn test_download_progress_percent() {
        let progress = DownloadProgress::starting(5, 10, "test.txt");
        assert_eq!(progress.percent(), 50);

        let progress = DownloadProgress::starting(0, 10, "test.txt");
        assert_eq!(progress.percent(), 0);

        let progress = DownloadProgress::starting(9, 10, "test.txt");
        assert_eq!(progress.percent(), 90);
    }

    #[test]
    fn test_compute_file_hash_sha256() {
        let dir = tempdir().unwrap();
        let file_path = dir.path().join("test.txt");
        fs::write(&file_path, "hello world").unwrap();

        let hash = compute_file_hash(&file_path, "sha256").unwrap();
        // SHA256 of "hello world"
        assert_eq!(
            hash,
            "b94d27b9934d3e08a52e52d7da7dabfac484efe37a5380ee9088f7ace2efcde9"
        );
    }

    #[test]
    fn test_compute_file_hash_md5() {
        let dir = tempdir().unwrap();
        let file_path = dir.path().join("test.txt");
        fs::write(&file_path, "hello world").unwrap();

        let hash = compute_file_hash(&file_path, "md5").unwrap();
        // MD5 of "hello world"
        assert_eq!(hash, "5eb63bbbe01eeed093cb22bb8f5acdc3");
    }

    #[cfg(windows)]
    #[test]
    fn test_download_copyto_local() {
        let binary = ExtractedBinary::extract().expect("Failed to extract rclone");
        let runner = RcloneRunner::new(binary.path());
        let mut queue = DownloadQueue::new();
        queue.set_dry_run(true);

        let src_dir = tempdir().unwrap();
        let dst_dir = tempdir().unwrap();

        let src_file = src_dir.path().join("test.txt");
        let dst_file = dst_dir.path().join("test.txt");
        fs::write(&src_file, "hello").unwrap();

        let request =
            DownloadRequest::new_copyto(src_file.to_string_lossy(), dst_file.to_string_lossy());
        queue.add(request.clone());

        let output = queue
            .download_one(&runner, &request)
            .expect("Download failed");
        assert!(output.success());
    }

    #[cfg(windows)]
    #[test]
    fn test_download_with_progress_callback() {
        // This test verifies the progress callback mechanism works correctly.
        // Due to rclone WSL/filesystem quirks with local-to-local copies,
        // we use dry-run mode to avoid false failures from size checks.
        let binary = ExtractedBinary::extract().expect("Failed to extract rclone");
        let runner = RcloneRunner::new(binary.path());
        let mut queue = DownloadQueue::new();
        queue.set_verify_hashes(false);
        queue.set_dry_run(true); // Use dry-run to avoid WSL copy quirks

        let src_dir = tempdir().unwrap();
        let dst_dir = tempdir().unwrap();

        // Create test file
        let src_file = src_dir.path().join("test.txt");
        let dst_file = dst_dir.path().join("test.txt");
        fs::write(&src_file, "hello").unwrap();

        let request =
            DownloadRequest::new_copyto(src_file.to_string_lossy(), dst_file.to_string_lossy());
        queue.add(request);

        let mut progress_updates = Vec::new();
        let results = queue.download_all_with_progress(&runner, |p| {
            progress_updates.push(p.status.clone());
        });

        assert_eq!(results.len(), 1);
        assert!(
            results[0].success,
            "Download should succeed (dry-run), error: {:?}",
            results[0].error
        );
        // Should have at least 2 updates: starting and completed
        assert!(
            progress_updates.len() >= 2,
            "Should have at least 2 progress updates, got {}",
            progress_updates.len()
        );
    }
}
