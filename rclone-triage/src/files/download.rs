//! Download queue and file copy operations

use anyhow::{bail, Result};
use sha2::{Digest, Sha256};
use std::fs::File;
use std::io::Read;
use std::path::Path;
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

/// Progress of a download operation
#[derive(Debug, Clone)]
pub struct DownloadProgress {
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
            current,
            total,
            current_file: file.to_string(),
            status: format!("Downloading {}/{}: {}", current + 1, total, file),
            bytes_done: None,
            bytes_total: None,
        }
    }

    /// Create a progress update for completed file
    pub fn completed(current: usize, total: usize, file: &str, size: u64) -> Self {
        Self {
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
        }
    }

    pub fn new_copyto(source: impl Into<String>, destination: impl Into<String>) -> Self {
        Self {
            source: source.into(),
            destination: destination.into(),
            mode: DownloadMode::CopyTo,
            expected_hash: None,
            expected_hash_type: None,
        }
    }

    /// Set expected hash for verification
    pub fn with_hash(mut self, hash: Option<String>, hash_type: Option<String>) -> Self {
        self.expected_hash = hash;
        self.expected_hash_type = hash_type;
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

        // Only add progress stats for Copy mode (directories)
        // CopyTo is single file and doesn't benefit from stats
        if request.mode == DownloadMode::Copy {
            args.push("--progress".to_string());
            args.push("--stats".to_string());
            args.push("1s".to_string());
        }

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
        let total = self.requests.len();
        let mut results = Vec::with_capacity(total);

        for (i, request) in self.requests.iter().enumerate() {
            // Notify starting
            progress_callback(DownloadProgress::starting(i, total, &request.source));

            let result = self.download_one_verified(rclone, request);
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
                let (hash, hash_type, hash_verified) =
                    if self.verify_hashes && request.expected_hash.is_some() {
                        let hash_type = request.expected_hash_type.as_deref().unwrap_or("sha256");
                        match compute_file_hash(dest_path, hash_type) {
                            Ok(computed) => {
                                let verified = request
                                    .expected_hash
                                    .as_ref()
                                    .map(|expected| expected.eq_ignore_ascii_case(&computed))
                                    .unwrap_or(false);
                                (Some(computed), Some(hash_type.to_string()), Some(verified))
                            }
                            Err(_) => (None, None, None),
                        }
                    } else {
                        (None, None, None)
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

/// Compute hash of a file
pub fn compute_file_hash(path: &Path, hash_type: &str) -> Result<String> {
    let mut file = File::open(path)?;
    let mut buffer = Vec::new();
    file.read_to_end(&mut buffer)?;

    match hash_type.to_lowercase().as_str() {
        "sha256" => {
            let mut hasher = Sha256::new();
            hasher.update(&buffer);
            Ok(format!("{:x}", hasher.finalize()))
        }
        "md5" => {
            let digest = md5::compute(&buffer);
            Ok(format!("{:x}", digest))
        }
        "sha1" => {
            use sha1::{Digest as Sha1Digest, Sha1};
            let mut hasher = Sha1::new();
            hasher.update(&buffer);
            Ok(format!("{:x}", hasher.finalize()))
        }
        _ => bail!("Unsupported hash type: {}", hash_type),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::embedded::ExtractedBinary;
    use std::fs;
    use tempfile::tempdir;

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

    #[test]
    fn test_download_with_progress_callback() {
        let binary = ExtractedBinary::extract().expect("Failed to extract rclone");
        let runner = RcloneRunner::new(binary.path());
        let mut queue = DownloadQueue::new();
        queue.set_verify_hashes(false);

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
        // Debug: print result before assertion
        if !results[0].success {
            eprintln!("Download failed: {:?}", results[0].error);
            eprintln!("Source: {:?}", results[0].source);
            eprintln!("Dest: {:?}", results[0].destination);
        }
        assert!(
            results[0].success,
            "Download should succeed, error: {:?}",
            results[0].error
        );
        // Should have at least 2 updates: starting and completed
        assert!(progress_updates.len() >= 2);
    }
}
