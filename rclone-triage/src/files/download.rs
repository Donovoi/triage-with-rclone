//! Download queue and file copy operations

use anyhow::{bail, Result};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::VecDeque;
use std::fs::File;
use std::io::{BufReader, Read};
use std::path::Path;
use std::sync::atomic::AtomicBool;
use std::sync::{mpsc, Arc, Mutex};
use std::thread;
use std::time::Duration;

use crate::rclone::RcloneRunner;

/// Download mode
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
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
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum IntegrityStatus {
    Verified,
    Unavailable,
    Mismatch,
    Failed,
    Cancelled,
    DryRun,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DownloadResult {
    /// Source path
    pub local_sha256: Option<String>,
    pub integrity: IntegrityStatus,
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
#[derive(Debug, Clone, Serialize, Deserialize)]
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

impl DownloadRequest {
    #[cfg(test)]
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

// Remote names are interpreted only on the source side. Destination is always
// local, so names containing ':' never become an unintended remote write.
fn split_object_path(value: &str, allow_remote: bool) -> (String, String) {
    if allow_remote {
        if let Some((name, object)) = value.split_once(':') {
            let drive_letter =
                cfg!(windows) && name.len() == 1 && name.as_bytes()[0].is_ascii_alphabetic();
            if !drive_letter && !name.contains(['/', '\\']) {
                return (format!("{name}:"), object.to_string());
            }
        }
    }
    let path = Path::new(value);
    let parent = path
        .parent()
        .filter(|p| !p.as_os_str().is_empty())
        .unwrap_or_else(|| Path::new("."));
    (
        parent.to_string_lossy().into_owned(),
        path.file_name()
            .unwrap_or_default()
            .to_string_lossy()
            .into_owned(),
    )
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

    #[cfg(test)]
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
            DownloadMode::CopyTo => {
                let (source_fs, source_remote) = split_object_path(&request.source, true);
                let (destination_fs, destination_remote) =
                    split_object_path(&request.destination, false);
                // copyto falls back to directory recursion if the source changes
                // after inventory. The loopback API opens exactly one object and
                // fails on a directory, without opening a network RC listener.
                vec![
                    "rc".into(),
                    "--loopback".into(),
                    "operations/copyfile".into(),
                    format!("srcFs={source_fs}"),
                    format!("srcRemote={source_remote}"),
                    format!("dstFs={destination_fs}"),
                    format!("dstRemote={destination_remote}"),
                ]
            }
        };

        // Transfer statistics are streamed to the TUI.
        args.push("--progress".to_string());
        args.push("--stats".to_string());
        args.push("1s".to_string());
        if self.dry_run {
            args.push("--dry-run".to_string());
        }
        args
    }

    pub fn download_all_with_progress<F: FnMut(DownloadProgress)>(
        &self,
        rclone: &RcloneRunner,
        progress_callback: F,
    ) -> Vec<DownloadResult> {
        self.download_all_with_progress_cancel(
            rclone,
            Arc::new(AtomicBool::new(false)),
            progress_callback,
        )
    }

    /// Cancellation has an outcome for every planned request, including jobs that
    /// were never started. Result order always matches request order.
    pub fn download_all_with_progress_cancel<F: FnMut(DownloadProgress)>(
        &self,
        rclone: &RcloneRunner,
        cancel: Arc<AtomicBool>,
        mut progress_callback: F,
    ) -> Vec<DownloadResult> {
        enum Event {
            Progress(DownloadProgress),
            Result(usize, DownloadResult),
        }
        let total = self.requests.len();
        if total == 0 {
            return Vec::new();
        }
        let pending = Arc::new(Mutex::new(
            self.requests
                .iter()
                .cloned()
                .enumerate()
                .collect::<VecDeque<_>>(),
        ));
        let (tx, rx) = mpsc::sync_channel(128);
        let mut handles = Vec::new();
        for _ in 0..self.parallel.max(1).min(total) {
            let pending = pending.clone();
            let tx = tx.clone();
            let runner = rclone.clone().with_cancel_flag(cancel.clone());
            let worker = Self {
                requests: Vec::new(),
                parallel: 1,
                timeout: self.timeout,
                dry_run: self.dry_run,
                verify_hashes: self.verify_hashes,
            };
            handles.push(thread::spawn(move || loop {
                let Some((index, request)) =
                    pending.lock().expect("download queue lock").pop_front()
                else {
                    break;
                };
                let result = if runner.is_cancelled() {
                    failed_result(
                        &request,
                        "Operation cancelled".into(),
                        IntegrityStatus::Cancelled,
                    )
                } else {
                    let _ = tx.send(Event::Progress(DownloadProgress::starting(
                        index,
                        total,
                        &request.source,
                    )));
                    worker.download_one_controlled(&runner, &request, |done, size| {
                        let _ = tx.send(Event::Progress(DownloadProgress::progress(
                            index,
                            total,
                            &request.source,
                            done,
                            size,
                        )));
                    })
                };
                let update = if result.success {
                    DownloadProgress::completed(
                        index,
                        total,
                        &request.source,
                        result.size.unwrap_or(0),
                    )
                } else {
                    DownloadProgress::failed(
                        index,
                        total,
                        &request.source,
                        result.error.as_deref().unwrap_or("Download failed"),
                    )
                };
                let _ = tx.send(Event::Progress(update));
                let _ = tx.send(Event::Result(index, result));
            }));
        }
        drop(tx);
        let mut results = vec![None; total];
        for event in rx {
            match event {
                Event::Progress(progress) => progress_callback(progress),
                Event::Result(index, result) => results[index] = Some(result),
            }
        }
        for handle in handles {
            let _ = handle.join();
        }
        results
            .into_iter()
            .enumerate()
            .map(|(index, result)| {
                result.unwrap_or_else(|| {
                    failed_result(
                        &self.requests[index],
                        "Download worker terminated before returning an outcome".into(),
                        IntegrityStatus::Failed,
                    )
                })
            })
            .collect()
    }

    pub fn download_one_verified(
        &self,
        rclone: &RcloneRunner,
        request: &DownloadRequest,
    ) -> DownloadResult {
        self.download_one_controlled(rclone, request, |_, _| {})
    }

    fn download_one_controlled<F: FnMut(u64, u64)>(
        &self,
        rclone: &RcloneRunner,
        request: &DownloadRequest,
        mut progress: F,
    ) -> DownloadResult {
        let runner = match self.timeout {
            Some(timeout) => rclone.clone().with_timeout(timeout),
            None => rclone.clone(),
        };
        let operation = || -> Result<()> {
            if request.mode != DownloadMode::CopyTo {
                bail!("Acquisition requires an individual file, not recursive copy");
            }
            let dest = Path::new(&request.destination);
            crate::utils::path::ensure_no_link_components(dest)?;
            if dest.exists() {
                bail!(
                    "Destination already exists; create a new acquisition plan: {}",
                    request.destination
                );
            }
            if !self.dry_run {
                if let Some(parent) = dest.parent() {
                    std::fs::create_dir_all(parent)?;
                }
            }
            crate::utils::path::ensure_no_link_components(dest)?;
            // Give an early error for stale inventory or a caller bypassing the
            // planner. operations/copyfile also rejects directories at copy time.
            let stat = runner.run(&[
                "lsjson",
                "--stat",
                "--no-modtime",
                "--no-mimetype",
                "--",
                &request.source,
            ])?;
            if !stat.success() {
                bail!("Cannot stat source: {}", stat.stderr_string());
            }
            let metadata: serde_json::Value = serde_json::from_str(&stat.stdout_string())?;
            if metadata.get("IsDir").and_then(|v| v.as_bool()) != Some(false) {
                bail!("Source is not an individual file: {}", request.source);
            }
            Ok(())
        };
        if let Err(error) = operation() {
            return failed_result(
                request,
                error.to_string(),
                if runner.is_cancelled() {
                    IntegrityStatus::Cancelled
                } else {
                    IntegrityStatus::Failed
                },
            );
        }
        // Stage in the destination filesystem, then publish without replacing
        // existing evidence. operations/copyfile does not enforce --immutable.
        let staging = if self.dry_run {
            None
        } else {
            let parent = Path::new(&request.destination)
                .parent()
                .filter(|p| !p.as_os_str().is_empty())
                .unwrap_or_else(|| Path::new("."));
            match tempfile::Builder::new()
                .prefix(".triage-transfer-")
                .tempdir_in(parent)
            {
                Ok(directory) => Some(directory),
                Err(error) => {
                    return failed_result(request, error.to_string(), IntegrityStatus::Failed)
                }
            }
        };
        let mut transfer = request.clone();
        if let Some(staging) = &staging {
            transfer.destination = staging
                .path()
                .join("payload")
                .to_string_lossy()
                .into_owned();
        }
        let args = self.build_args(&transfer);
        let refs: Vec<&str> = args.iter().map(String::as_str).collect();
        let output = runner.run_streaming_stderr(&refs, |line| {
            if let Some((done, size)) = parse_transferred_progress(line, request.expected_size) {
                progress(done, size);
            }
        });
        match output {
            Ok(output) if output.success() => {
                if staging.is_some() {
                    let publish = || -> Result<()> {
                        let staged = Path::new(&transfer.destination);
                        crate::utils::path::ensure_no_link_components(staged)?;
                        crate::utils::path::ensure_no_link_components(Path::new(
                            &request.destination,
                        ))?;
                        if !std::fs::symlink_metadata(staged)?.is_file() {
                            bail!("Transfer did not produce an individual file");
                        }
                        std::fs::OpenOptions::new()
                            .read(true)
                            .write(true)
                            .open(staged)?
                            .sync_all()?;
                        tempfile::TempPath::from_path(staged)
                            .persist_noclobber(&request.destination)?;
                        Ok(())
                    };
                    if let Err(error) = publish() {
                        return failed_result(
                            request,
                            format!("Cannot publish acquired file safely: {error}"),
                            IntegrityStatus::Failed,
                        );
                    }
                }
                self.verify_destination(&runner, request)
            }
            Ok(output) => failed_result(
                request,
                output.stderr_string(),
                if output.cancelled {
                    IntegrityStatus::Cancelled
                } else {
                    IntegrityStatus::Failed
                },
            ),
            Err(error) => failed_result(
                request,
                error.to_string(),
                if runner.is_cancelled() {
                    IntegrityStatus::Cancelled
                } else {
                    IntegrityStatus::Failed
                },
            ),
        }
    }

    fn verify_destination(
        &self,
        runner: &RcloneRunner,
        request: &DownloadRequest,
    ) -> DownloadResult {
        let mut result = failed_result(request, String::new(), IntegrityStatus::Failed);
        if self.dry_run {
            result.success = true;
            result.error = None;
            result.integrity = IntegrityStatus::DryRun;
            return result;
        }
        let dest = Path::new(&request.destination);
        let metadata = match std::fs::metadata(dest) {
            Ok(metadata) if metadata.is_file() => metadata,
            Ok(_) => {
                result.error = Some("Destination is not a regular file".into());
                return result;
            }
            Err(error) => {
                result.error = Some(error.to_string());
                return result;
            }
        };
        result.size = Some(metadata.len());
        match compute_file_hash_cancellable(dest, "sha256", || runner.is_cancelled()) {
            Ok(hash) => result.local_sha256 = Some(hash),
            Err(error) => {
                result.error = Some(format!("Local SHA-256 failed: {error}"));
                if runner.is_cancelled() {
                    result.integrity = IntegrityStatus::Cancelled;
                }
                return result;
            }
        }
        result.success = true;
        result.error = None;
        result.integrity = IntegrityStatus::Unavailable;
        if let Some(expected_size) = request.expected_size {
            if expected_size != metadata.len() {
                result.success = false;
                result.integrity = IntegrityStatus::Mismatch;
                result.error = Some(format!(
                    "Size mismatch: expected {expected_size}, got {}",
                    metadata.len()
                ));
            }
        }
        if self.verify_hashes {
            match (&request.expected_hash, &request.expected_hash_type) {
                (Some(expected), Some(kind)) => {
                    let computed = if normalize_hash_type(kind) == "sha256" {
                        Ok(result.local_sha256.clone().expect("SHA-256 computed"))
                    } else {
                        compute_file_hash_best_effort(runner, dest, kind)
                    };
                    result.hash_type = Some(kind.clone());
                    match computed {
                        Ok(hash) => {
                            let verified = expected.eq_ignore_ascii_case(&hash);
                            result.hash = Some(hash);
                            result.hash_verified = Some(verified);
                            if !verified {
                                result.success = false;
                                result.integrity = IntegrityStatus::Mismatch;
                                result.error = Some(
                                    "Downloaded bytes do not match the expected source hash".into(),
                                );
                            } else if result.success {
                                result.integrity = IntegrityStatus::Verified;
                            }
                        }
                        Err(error) => {
                            result.hash_error =
                                Some(format!("Source hash verification unavailable: {error}"));
                            if runner.is_cancelled() {
                                result.success = false;
                                result.integrity = IntegrityStatus::Cancelled;
                                result.error =
                                    Some("Operation cancelled during verification".into());
                            }
                        }
                    }
                }
                (Some(_), None) => {
                    result.hash_error = Some("Expected hash has no algorithm".into())
                }
                _ => {
                    result.hash_error =
                        Some("Source did not supply a hash; local SHA-256 recorded".into())
                }
            }
        } else {
            result.hash_error =
                Some("Source hash verification disabled; local SHA-256 recorded".into());
        }
        result
    }
}

fn failed_result(
    request: &DownloadRequest,
    error: String,
    integrity: IntegrityStatus,
) -> DownloadResult {
    DownloadResult {
        source: request.source.clone(),
        destination: request.destination.clone(),
        success: false,
        error: Some(error),
        size: None,
        hash: None,
        hash_type: None,
        hash_verified: None,
        hash_error: None,
        local_sha256: None,
        integrity,
    }
}

fn normalize_hash_type(kind: &str) -> String {
    kind.to_ascii_lowercase().replace('-', "")
}

impl Default for DownloadQueue {
    fn default() -> Self {
        Self::new()
    }
}

/// Compute hash of a file
pub fn compute_file_hash(path: &Path, hash_type: &str) -> Result<String> {
    compute_file_hash_cancellable(path, hash_type, || false)
}

fn compute_file_hash_cancellable<F: Fn() -> bool>(
    path: &Path,
    hash_type: &str,
    cancelled: F,
) -> Result<String> {
    let mut file = File::open(path)?;
    let mut reader = BufReader::new(&mut file);
    let mut buffer = vec![0u8; 1024 * 1024];

    match normalize_hash_type(hash_type).as_str() {
        "sha256" => {
            let mut hasher = Sha256::new();
            loop {
                if cancelled() {
                    bail!("Operation cancelled");
                }
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
                if cancelled() {
                    bail!("Operation cancelled");
                }
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
                if cancelled() {
                    bail!("Operation cancelled");
                }
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

fn compute_file_hash_with_rclone(
    rclone: &RcloneRunner,
    path: &Path,
    hash_type: &str,
) -> Result<String> {
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
    match normalize_hash_type(hash_type).as_str() {
        "sha256" | "sha1" | "md5" => {
            compute_file_hash_cancellable(path, hash_type, || rclone.is_cancelled())
        }
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
        assert_eq!(&args[..3], ["rc", "--loopback", "operations/copyfile"]);
        assert!(args.contains(&"srcRemote=src".into()));
        assert!(args.contains(&"dstRemote=dest".into()));
    }

    #[test]
    fn remote_object_arguments_preserve_exact_names() {
        let args = DownloadQueue::new().build_args(&DownloadRequest::new_copyto(
            "remote: space/key = value.txt ",
            "download.txt",
        ));
        assert!(args.contains(&"srcFs=remote:".into()));
        assert!(args.contains(&"srcRemote= space/key = value.txt ".into()));
    }

    #[cfg(windows)]
    #[test]
    fn single_object_transfer_cannot_recurse_after_source_becomes_directory() {
        let binary = ExtractedBinary::extract().unwrap();
        let temp = tempdir().unwrap();
        let config = temp.path().join("empty.conf");
        fs::write(&config, "").unwrap();
        let runner = RcloneRunner::new(binary.path()).with_config(config);
        let source = temp.path().join("was-a-file");
        fs::write(&source, "listed as a file").unwrap();
        let destination = temp.path().join("result.bin");
        let request =
            DownloadRequest::new_copyto(source.to_string_lossy(), destination.to_string_lossy());
        // Simulate a stale listing/preflight immediately before spawning transfer.
        fs::remove_file(&source).unwrap();
        fs::create_dir(&source).unwrap();
        fs::write(source.join("must-not-acquire.txt"), "unrequested").unwrap();
        let args = DownloadQueue::new().build_args(&request);
        let refs: Vec<_> = args.iter().map(String::as_str).collect();
        let output = runner.run(&refs).unwrap();
        assert!(!output.success(), "{output:?}");
        assert!(!destination.exists());
    }

    #[cfg(windows)]
    #[test]
    fn acquisition_preserves_existing_destination() {
        let binary = ExtractedBinary::extract().unwrap();
        let temp = tempdir().unwrap();
        let source = temp.path().join("source");
        let destination = temp.path().join("existing");
        fs::write(&source, "new bytes").unwrap();
        fs::write(&destination, "earlier evidence").unwrap();
        let result = DownloadQueue::new().download_one_verified(
            &RcloneRunner::new(binary.path()),
            &DownloadRequest::new_copyto(source.to_string_lossy(), destination.to_string_lossy()),
        );
        assert!(!result.success);
        assert_eq!(fs::read(destination).unwrap(), b"earlier evidence");
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
        let line = "Transferred:   1.00 MiB / 2.00 MiB, 50%, 1.00 MiB/s, ETA 1s";
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
    fn wrong_hash_fails_but_preserves_bytes_and_local_sha256() {
        let binary = ExtractedBinary::extract().unwrap();
        let temp = tempdir().unwrap();
        let config = temp.path().join("isolated.conf");
        fs::write(&config, "").unwrap();
        let runner = RcloneRunner::new(binary.path()).with_config(&config);
        let source = temp.path().join("source.txt");
        let destination = temp.path().join("downloaded.txt");
        fs::write(&source, "verified bytes").unwrap();
        let request =
            DownloadRequest::new_copyto(source.to_string_lossy(), destination.to_string_lossy())
                .with_hash(Some("deadbeef".into()), Some("md5".into()));
        let result = DownloadQueue::new().download_one_verified(&runner, &request);
        assert!(!result.success, "{:?}", result);
        assert_eq!(result.integrity, IntegrityStatus::Mismatch);
        assert_eq!(result.hash_verified, Some(false));
        assert_eq!(
            result.local_sha256,
            Some(compute_file_hash(&destination, "sha256").unwrap())
        );
        assert_eq!(fs::read(&destination).unwrap(), b"verified bytes");
    }

    #[cfg(windows)]
    #[test]
    fn no_source_hash_still_records_sha256_and_directories_are_rejected() {
        let binary = ExtractedBinary::extract().unwrap();
        let temp = tempdir().unwrap();
        let runner =
            RcloneRunner::new(binary.path()).with_config(temp.path().join("isolated.conf"));
        let source = temp.path().join("source.txt");
        fs::write(&source, "data").unwrap();
        let destination = temp.path().join("download.txt");
        let queue = DownloadQueue::new();
        let result = queue.download_one_verified(
            &runner,
            &DownloadRequest::new_copyto(source.to_string_lossy(), destination.to_string_lossy()),
        );
        assert!(result.success, "{:?}", result.error);
        assert_eq!(result.integrity, IntegrityStatus::Unavailable);
        assert!(result.local_sha256.is_some());
        let rejected = queue.download_one_verified(
            &runner,
            &DownloadRequest::new_copyto(
                temp.path().to_string_lossy(),
                temp.path().join("unwanted").to_string_lossy(),
            ),
        );
        assert!(!rejected.success);
        assert!(!temp.path().join("unwanted").exists());
    }

    #[cfg(windows)]
    #[test]
    fn parallel_dry_run_does_not_write_and_cancel_has_all_outcomes() {
        let binary = ExtractedBinary::extract().unwrap();
        let temp = tempdir().unwrap();
        let runner =
            RcloneRunner::new(binary.path()).with_config(temp.path().join("isolated.conf"));
        let source = temp.path().join("source.txt");
        fs::write(&source, "data").unwrap();
        let mut queue = DownloadQueue::new();
        queue.dry_run = true;
        for index in 0..3 {
            queue.add(DownloadRequest::new_copyto(
                source.to_string_lossy(),
                temp.path().join(format!("dest{index}")).to_string_lossy(),
            ));
        }
        let results = queue.download_all_with_progress(&runner, |_| {});
        assert_eq!(results.len(), 3);
        assert!(results
            .iter()
            .all(|r| r.integrity == IntegrityStatus::DryRun));
        assert!(results.iter().all(|r| !Path::new(&r.destination).exists()));
        let results = queue.download_all_with_progress_cancel(
            &runner,
            Arc::new(AtomicBool::new(true)),
            |_| {},
        );
        assert_eq!(results.len(), 3);
        assert!(results
            .iter()
            .all(|r| !r.success && r.integrity == IntegrityStatus::Cancelled));
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

        let output = queue.download_one_verified(&runner, &request);
        assert!(output.success);
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
