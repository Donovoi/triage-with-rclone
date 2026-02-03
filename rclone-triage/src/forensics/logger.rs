//! Forensic logger with hash chaining
//!
//! Provides tamper-evident logging by chaining SHA256 hashes of each entry.
//! Each log entry includes:
//! - Timestamp (ISO 8601)
//! - Hash of current entry (first 16 chars)
//! - Hash of previous entry (first 16 chars)
//! - Log message

use anyhow::{Context, Result};
use chrono::Utc;
use sha2::{Digest, Sha256};
use std::fs::{File, OpenOptions};
use std::io::{BufRead, BufReader, Write};
use std::path::{Path, PathBuf};
use std::sync::Mutex;

/// Genesis hash for the first entry in a log chain
const GENESIS_HASH: &str = "0000000000000000";

/// Forensic logger with hash chaining for tamper evidence
pub struct ForensicLogger {
    /// Path to the log file
    path: PathBuf,
    /// File handle for appending
    file: Mutex<File>,
    /// Hash of the last entry
    last_hash: Mutex<String>,
}

impl ForensicLogger {
    /// Create a new forensic logger
    ///
    /// If the file exists, it reads the last entry to continue the hash chain.
    /// If the file doesn't exist, a new log is started with a genesis entry.
    pub fn new(path: impl AsRef<Path>) -> Result<Self> {
        let path = path.as_ref().to_path_buf();

        // Create parent directories if needed
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent)
                .with_context(|| format!("Failed to create log directory: {:?}", parent))?;
        }

        // Check if file exists and get last hash
        let last_hash = if path.exists() {
            Self::read_last_hash(&path)?
        } else {
            GENESIS_HASH.to_string()
        };

        // Open file for appending
        let file = OpenOptions::new()
            .create(true)
            .append(true)
            .open(&path)
            .with_context(|| format!("Failed to open log file: {:?}", path))?;

        let logger = Self {
            path,
            file: Mutex::new(file),
            last_hash: Mutex::new(last_hash),
        };

        // Write header if new file
        if logger.last_hash.lock().unwrap().as_str() == GENESIS_HASH {
            logger.write_header()?;
        }

        Ok(logger)
    }

    /// Write the log header
    fn write_header(&self) -> Result<()> {
        let mut file = self.file.lock().unwrap();
        writeln!(file, "# rclone-triage Forensic Log")?;
        writeln!(file, "# Format: timestamp|current_hash|prev_hash|message")?;
        writeln!(file, "# Hash chain provides tamper evidence")?;
        writeln!(file, "#")?;
        file.sync_all()?;
        Ok(())
    }

    /// Read the hash from the last entry in an existing log file
    fn read_last_hash(path: &Path) -> Result<String> {
        let file = File::open(path)?;
        let reader = BufReader::new(file);

        let mut last_hash = GENESIS_HASH.to_string();

        for line in reader.lines() {
            let line = line?;
            // Skip comments and empty lines
            if line.starts_with('#') || line.is_empty() {
                continue;
            }
            // Parse the current hash from the entry
            // Format: timestamp|current_hash|prev_hash|message
            if let Some(hash) = line.split('|').nth(1) {
                last_hash = hash.to_string();
            }
        }

        Ok(last_hash)
    }

    /// Log an event with hash chaining
    ///
    /// # Arguments
    /// * `message` - The log message
    pub fn log(&self, message: impl AsRef<str>) -> Result<()> {
        let message = message.as_ref();
        let timestamp = Utc::now();
        let timestamp_str = timestamp.format("%Y-%m-%dT%H:%M:%S%.3fZ").to_string();

        let mut last_hash = self.last_hash.lock().unwrap();

        // Calculate new hash: SHA256(prev_hash || timestamp || message)
        let mut hasher = Sha256::new();
        hasher.update(last_hash.as_bytes());
        hasher.update(timestamp_str.as_bytes());
        hasher.update(message.as_bytes());
        let full_hash = hex::encode(hasher.finalize());
        let current_hash = &full_hash[..16]; // First 16 chars

        // Format entry
        let entry = format!(
            "{}|{}|{}|{}\n",
            timestamp_str, current_hash, &*last_hash, message,
        );

        // Write to file
        let mut file = self.file.lock().unwrap();
        file.write_all(entry.as_bytes())?;
        file.sync_all()?;

        // Update last hash
        *last_hash = current_hash.to_string();

        Ok(())
    }

    /// Log an event with a specific severity level
    pub fn log_level(&self, level: LogLevel, message: impl AsRef<str>) -> Result<()> {
        self.log(format!("[{}] {}", level, message.as_ref()))
    }

    /// Log an info message
    pub fn info(&self, message: impl AsRef<str>) -> Result<()> {
        self.log_level(LogLevel::Info, message)
    }

    /// Log a warning message
    pub fn warn(&self, message: impl AsRef<str>) -> Result<()> {
        self.log_level(LogLevel::Warn, message)
    }

    /// Log an error message
    pub fn error(&self, message: impl AsRef<str>) -> Result<()> {
        self.log_level(LogLevel::Error, message)
    }

    /// Log a debug message
    pub fn debug(&self, message: impl AsRef<str>) -> Result<()> {
        self.log_level(LogLevel::Debug, message)
    }

    /// Get the path to the log file
    pub fn path(&self) -> &Path {
        &self.path
    }

    /// Verify the integrity of the log file
    ///
    /// Returns Ok(true) if the hash chain is valid, Ok(false) if corrupted
    pub fn verify_integrity(&self) -> Result<bool> {
        Self::verify_log_file(&self.path)
    }

    /// Verify the integrity of any forensic log file
    pub fn verify_log_file(path: &Path) -> Result<bool> {
        let file = File::open(path)?;
        let reader = BufReader::new(file);

        let mut expected_prev_hash = GENESIS_HASH.to_string();

        for line in reader.lines() {
            let line = line?;

            // Skip comments and empty lines
            if line.starts_with('#') || line.is_empty() {
                continue;
            }

            // Parse entry: timestamp|current_hash|prev_hash|message
            let parts: Vec<&str> = line.splitn(4, '|').collect();
            if parts.len() != 4 {
                return Ok(false); // Malformed entry
            }

            let timestamp = parts[0];
            let current_hash = parts[1];
            let prev_hash = parts[2];
            let message = parts[3];

            // Verify prev_hash matches expected
            if prev_hash != expected_prev_hash {
                return Ok(false); // Chain broken
            }

            // Verify current_hash
            let mut hasher = Sha256::new();
            hasher.update(prev_hash.as_bytes());
            hasher.update(timestamp.as_bytes());
            hasher.update(message.as_bytes());
            let computed_hash = &hex::encode(hasher.finalize())[..16];

            if computed_hash != current_hash {
                return Ok(false); // Hash mismatch
            }

            expected_prev_hash = current_hash.to_string();
        }

        Ok(true)
    }

    /// Get the final hash of the log file (for including in reports)
    pub fn final_hash(&self) -> String {
        self.last_hash.lock().unwrap().clone()
    }
}

/// Log severity levels
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LogLevel {
    Debug,
    Info,
    Warn,
    Error,
}

impl std::fmt::Display for LogLevel {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            LogLevel::Debug => write!(f, "DEBUG"),
            LogLevel::Info => write!(f, "INFO"),
            LogLevel::Warn => write!(f, "WARN"),
            LogLevel::Error => write!(f, "ERROR"),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::tempdir;

    #[test]
    fn test_new_logger_creates_file() {
        let dir = tempdir().unwrap();
        let log_path = dir.path().join("test.log");

        let _logger = ForensicLogger::new(&log_path).unwrap();
        assert!(log_path.exists());
    }

    #[test]
    fn test_log_entries() {
        let dir = tempdir().unwrap();
        let log_path = dir.path().join("test.log");

        let logger = ForensicLogger::new(&log_path).unwrap();
        logger.log("First entry").unwrap();
        logger.log("Second entry").unwrap();
        logger.info("Info message").unwrap();

        // Read back and verify
        let content = std::fs::read_to_string(&log_path).unwrap();
        assert!(content.contains("First entry"));
        assert!(content.contains("Second entry"));
        assert!(content.contains("[INFO] Info message"));
    }

    #[test]
    fn test_hash_chain_integrity() {
        let dir = tempdir().unwrap();
        let log_path = dir.path().join("test.log");

        let logger = ForensicLogger::new(&log_path).unwrap();
        logger.log("Entry 1").unwrap();
        logger.log("Entry 2").unwrap();
        logger.log("Entry 3").unwrap();

        // Verify integrity
        assert!(logger.verify_integrity().unwrap());
    }

    #[test]
    fn test_detect_tampering() {
        let dir = tempdir().unwrap();
        let log_path = dir.path().join("test.log");

        // Create valid log
        {
            let logger = ForensicLogger::new(&log_path).unwrap();
            logger.log("Entry 1").unwrap();
            logger.log("Entry 2").unwrap();
        }

        // Tamper with the file
        let content = std::fs::read_to_string(&log_path).unwrap();
        let tampered = content.replace("Entry 1", "TAMPERED");
        std::fs::write(&log_path, tampered).unwrap();

        // Should detect tampering
        assert!(!ForensicLogger::verify_log_file(&log_path).unwrap());
    }

    #[test]
    fn test_continue_existing_log() {
        let dir = tempdir().unwrap();
        let log_path = dir.path().join("test.log");

        // Create log with some entries
        {
            let logger = ForensicLogger::new(&log_path).unwrap();
            logger.log("Entry 1").unwrap();
            logger.log("Entry 2").unwrap();
        }

        // Reopen and continue
        {
            let logger = ForensicLogger::new(&log_path).unwrap();
            logger.log("Entry 3").unwrap();
        }

        // Verify entire chain
        assert!(ForensicLogger::verify_log_file(&log_path).unwrap());

        let content = std::fs::read_to_string(&log_path).unwrap();
        assert!(content.contains("Entry 1"));
        assert!(content.contains("Entry 2"));
        assert!(content.contains("Entry 3"));
    }
}
