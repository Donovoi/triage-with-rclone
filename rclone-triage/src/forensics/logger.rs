//! Versioned forensic hash chains. Version 2 stores canonical, escaped JSON records.
//! Legacy pipe-delimited entries remain readable; unverified chains cannot be appended.
use anyhow::{bail, Context, Result};
use chrono::Utc;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::fs::{File, OpenOptions};
use std::io::{BufRead, BufReader, Read, Seek, SeekFrom, Write};
use std::path::{Path, PathBuf};
use std::sync::Mutex;

const GENESIS_HASH: &str = "0000000000000000000000000000000000000000000000000000000000000000";

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct LogCheckpoint {
    pub hash: String,
    pub entry_count: u64,
}
impl Default for LogCheckpoint {
    fn default() -> Self {
        Self {
            hash: GENESIS_HASH.into(),
            entry_count: 0,
        }
    }
}
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Record {
    version: u8,
    timestamp: String,
    current_hash: String,
    prev_hash: String,
    message: String,
}
fn is_hex_hash(s: &str) -> bool {
    (s.len() == 16 || s.len() == 64) && s.bytes().all(|c| c.is_ascii_hexdigit())
}
fn compute_entry_hash(prev_hash: &str, timestamp: &str, message: &str) -> String {
    let mut hasher = Sha256::new();
    hasher.update(prev_hash.as_bytes());
    hasher.update(timestamp.as_bytes());
    hasher.update(message.as_bytes());
    hex::encode(hasher.finalize())
}
fn canonical_hash(prev: &str, timestamp: &str, message: &str) -> Result<String> {
    let bytes = serde_json::to_vec(&(2u8, prev, timestamp, message))?;
    Ok(hex::encode(Sha256::digest(bytes)))
}
fn advance_checkpoint(line: &str, state: &mut LogCheckpoint) -> Result<()> {
    let (hash, prev, computed) = if line.starts_with('{') {
        let entry: Record = serde_json::from_str(line)?;
        if entry.version != 2 {
            bail!("Unsupported forensic log version");
        }
        let computed = canonical_hash(&entry.prev_hash, &entry.timestamp, &entry.message)?;
        (entry.current_hash, entry.prev_hash, computed)
    } else {
        let fields: Vec<_> = line.splitn(4, '|').collect();
        if fields.len() != 4 {
            bail!("Malformed legacy log record");
        }
        let computed = compute_entry_hash(fields[2], fields[0], fields[3]);
        let computed = if fields[1].len() == 16 {
            computed[..16].to_owned()
        } else {
            computed
        };
        (fields[1].to_owned(), fields[2].to_owned(), computed)
    };
    let genesis = state.entry_count == 0
        && (prev.len() == 16 || prev.len() == 64)
        && prev.bytes().all(|b| b == b'0');
    if !is_hex_hash(&hash)
        || !is_hex_hash(&prev)
        || (!genesis && prev != state.hash)
        || hash != computed
    {
        bail!("Forensic log hash chain mismatch");
    }
    state.hash = hash;
    state.entry_count += 1;
    Ok(())
}
fn read_checkpoint(path: &Path, count: Option<u64>) -> Result<LogCheckpoint> {
    let reader = BufReader::new(File::open(path)?);
    let mut state = LogCheckpoint::default();
    for line in reader.lines() {
        let line = line?;
        if line.starts_with('#') || line.is_empty() {
            continue;
        }
        if count == Some(state.entry_count) {
            break;
        }
        advance_checkpoint(&line, &mut state)?;
    }
    if let Some(count) = count {
        if state.entry_count != count {
            bail!("Log truncated before checkpoint");
        }
    }
    Ok(state)
}

pub struct ForensicLogger {
    path: PathBuf,
    file: Mutex<File>,
    state: Mutex<LogCheckpoint>,
}
impl ForensicLogger {
    pub fn new(path: impl AsRef<Path>) -> Result<Self> {
        let path = path.as_ref().to_path_buf();
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent)?;
        }
        let state = if path.exists() {
            read_checkpoint(&path, None).context("Refusing to append to an invalid forensic log")?
        } else {
            LogCheckpoint::default()
        };
        let mut file = OpenOptions::new()
            .create(true)
            .read(true)
            .append(true)
            .open(&path)?;
        if file.metadata()?.len() == 0 {
            writeln!(file, "# rclone-triage Forensic Log\n# Format v2: JSON Lines; SHA256(JSON([2,prev_hash,timestamp,message]))")?;
            file.sync_all()?;
        } else {
            file.seek(SeekFrom::End(-1))?;
            let mut last = [0u8; 1];
            file.read_exact(&mut last)?;
            if last[0] != b'\n' {
                // A valid final record need not have had a terminating newline.
                file.write_all(b"\n")?;
                file.sync_all()?;
            }
        }
        Ok(Self {
            path,
            file: Mutex::new(file),
            state: Mutex::new(state),
        })
    }
    pub fn log(&self, message: impl AsRef<str>) -> Result<()> {
        let message = message.as_ref();
        let timestamp = Utc::now().format("%Y-%m-%dT%H:%M:%S%.3fZ").to_string();
        let mut state = self
            .state
            .lock()
            .map_err(|e| anyhow::anyhow!("forensic logger mutex poisoned: {e}"))?;
        let hash = canonical_hash(&state.hash, &timestamp, message)?;
        let entry = Record {
            version: 2,
            timestamp,
            current_hash: hash.clone(),
            prev_hash: state.hash.clone(),
            message: message.into(),
        };
        let mut bytes = serde_json::to_vec(&entry)?;
        bytes.push(b'\n');
        let mut file = self
            .file
            .lock()
            .map_err(|e| anyhow::anyhow!("forensic logger mutex poisoned: {e}"))?;
        file.write_all(&bytes)?;
        file.sync_all()?;
        state.hash = hash;
        state.entry_count += 1;
        Ok(())
    }
    pub fn log_level(&self, level: LogLevel, message: impl AsRef<str>) -> Result<()> {
        self.log(format!("[{}] {}", level, message.as_ref()))
    }
    pub fn info(&self, message: impl AsRef<str>) -> Result<()> {
        self.log_level(LogLevel::Info, message)
    }
    pub fn warn(&self, message: impl AsRef<str>) -> Result<()> {
        self.log_level(LogLevel::Warn, message)
    }
    pub fn error(&self, message: impl AsRef<str>) -> Result<()> {
        self.log_level(LogLevel::Error, message)
    }
    pub fn debug(&self, message: impl AsRef<str>) -> Result<()> {
        self.log_level(LogLevel::Debug, message)
    }
    pub fn path(&self) -> &Path {
        &self.path
    }
    pub fn verify_integrity(&self) -> Result<bool> {
        Self::verify_log_file(&self.path)
    }
    pub fn verify_log_file(path: &Path) -> Result<bool> {
        // Preserve I/O errors while malformed/corrupt content is a failed verification.
        File::open(path)?;
        Ok(read_checkpoint(path, None).is_ok())
    }
    /// An explicit prefix anchor; later events do not invalidate this checkpoint.
    pub fn checkpoint(&self) -> Result<LogCheckpoint> {
        Ok(self
            .state
            .lock()
            .map_err(|e| anyhow::anyhow!("forensic logger mutex poisoned: {e}"))?
            .clone())
    }
    pub fn verify_checkpoint(path: &Path, checkpoint: &LogCheckpoint) -> Result<bool> {
        File::open(path)?;
        Ok(read_checkpoint(path, Some(checkpoint.entry_count))
            .map(|actual| actual == *checkpoint)
            .unwrap_or(false))
    }
    /// Current chain hash, retained for compatibility. Prefer checkpoint() in reports.
    pub fn final_hash(&self) -> Result<String> {
        Ok(self.checkpoint()?.hash)
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
    fn multiline_messages_round_trip_and_checkpoint_survives_later_events() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("events.log");
        let logger = ForensicLogger::new(&path).unwrap();
        logger
            .log("error\r\nline 2 | Unicode é\n# comment-looking content")
            .unwrap();
        let checkpoint = logger.checkpoint().unwrap();
        assert_eq!(checkpoint.entry_count, 1);
        logger.log("later event").unwrap();
        assert!(logger.verify_integrity().unwrap());
        assert!(ForensicLogger::verify_checkpoint(&path, &checkpoint).unwrap());
        drop(logger);
        let logger = ForensicLogger::new(&path).unwrap();
        assert_eq!(logger.checkpoint().unwrap().entry_count, 2);
        logger.log("reopened").unwrap();
        assert!(logger.verify_integrity().unwrap());
    }

    #[test]
    fn legacy_records_can_be_verified_and_extended_without_rewriting() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("legacy.log");
        let timestamp = "2026-01-01T00:00:00Z";
        let hash = compute_entry_hash(GENESIS_HASH, timestamp, "legacy");
        let old = format!("{timestamp}|{hash}|{GENESIS_HASH}|legacy");
        std::fs::write(&path, &old).unwrap();
        let logger = ForensicLogger::new(&path).unwrap();
        logger.log("new\nrecord").unwrap();
        assert!(logger.verify_integrity().unwrap());
        assert!(std::fs::read_to_string(&path).unwrap().starts_with(&old));
    }

    #[test]
    fn corrupted_chain_cannot_be_reopened_for_append() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("bad.log");
        std::fs::write(&path, "broken entry\n").unwrap();
        assert!(ForensicLogger::new(&path).is_err());
    }

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
