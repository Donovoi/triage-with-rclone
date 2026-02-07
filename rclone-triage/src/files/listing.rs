//! File listing utilities

use anyhow::{bail, Context, Result};
use chrono::{DateTime, Utc};
use serde::de::{self, SeqAccess, Visitor};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::fmt;
use std::io::{self, BufRead, BufReader, Read};
use std::path::Path;
use std::thread;

use crate::rclone::RcloneRunner;

#[derive(Debug, Clone, Copy)]
pub struct ListPathOptions {
    /// If true, request hashes from rclone (when the backend supports it).
    pub include_hashes: bool,
}

impl ListPathOptions {
    pub fn with_hashes() -> Self {
        Self {
            include_hashes: true,
        }
    }

    pub fn without_hashes() -> Self {
        Self {
            include_hashes: false,
        }
    }
}

/// File entry returned by rclone listing
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FileEntry {
    pub path: String,
    pub size: u64,
    pub modified: Option<DateTime<Utc>>,
    pub is_dir: bool,
    pub hash: Option<String>,
    pub hash_type: Option<String>,
}

/// Result of a large listing, where only a subset may be kept in memory.
#[derive(Debug, Clone)]
pub struct LargeListingResult {
    /// Entries retained in memory for UI usage.
    pub entries: Vec<FileEntry>,
    /// Total number of entries seen in the remote listing.
    pub total_entries: usize,
    /// True if `entries` is a truncated subset of the full listing.
    pub truncated: bool,
}

/// Internal representation of rclone lsjson output
#[derive(Debug, Clone, Deserialize)]
struct RcloneLsJsonEntry {
    #[serde(rename = "Path")]
    path: String,
    #[serde(rename = "Size")]
    size: u64,
    #[serde(rename = "ModTime")]
    mod_time: Option<DateTime<Utc>>,
    #[serde(rename = "IsDir")]
    is_dir: bool,
    #[serde(rename = "Hashes")]
    hashes: Option<HashMap<String, String>>,
}

impl From<RcloneLsJsonEntry> for FileEntry {
    fn from(entry: RcloneLsJsonEntry) -> Self {
        let (hash, hash_type) = select_hash(entry.hashes.as_ref());
        Self {
            path: entry.path,
            size: entry.size,
            modified: entry.mod_time,
            is_dir: entry.is_dir,
            hash,
            hash_type,
        }
    }
}

/// List files for a given rclone path (remote or local)
///
/// Example:
/// - Remote: "mydrive:" or "mydrive:/folder"
/// - Local: "/tmp"
pub fn list_path(rclone: &RcloneRunner, target: &str, options: ListPathOptions) -> Result<Vec<FileEntry>> {
    match list_path_inner(rclone, target, options.include_hashes) {
        Ok(entries) => Ok(entries),
        Err(err) => {
            // Best-effort fallback: if requesting hashes breaks listing, retry without.
            if options.include_hashes {
                if let Ok(entries) = list_path_inner(rclone, target, false) {
                    return Ok(entries);
                }
            }
            Err(err)
        }
    }
}

/// List files for a given rclone path, reporting progress as entries are seen.
pub fn list_path_with_progress<F>(
    rclone: &RcloneRunner,
    target: &str,
    options: ListPathOptions,
    mut on_progress: F,
) -> Result<Vec<FileEntry>>
where
    F: FnMut(usize),
{
    match list_path_with_progress_inner(rclone, target, options.include_hashes, &mut on_progress) {
        Ok(entries) => Ok(entries),
        Err(err) => {
            // Best-effort fallback: if requesting hashes breaks listing, retry without.
            if options.include_hashes {
                if let Ok(entries) = list_path_with_progress_inner(rclone, target, false, &mut on_progress) {
                    return Ok(entries);
                }
            }
            Err(err)
        }
    }
}

/// List files for a given rclone path, streaming the output to CSV while keeping at most
/// `max_in_memory` entries in memory (for TUI display).
///
/// This is intended for huge remotes where buffering the full JSON output (and/or all entries)
/// would be too expensive.
pub fn list_path_large_to_csv_with_progress<F>(
    rclone: &RcloneRunner,
    target: &str,
    options: ListPathOptions,
    csv_path: impl AsRef<Path>,
    max_in_memory: usize,
    mut on_progress: F,
) -> Result<LargeListingResult>
where
    F: FnMut(usize),
{
    let csv_path = csv_path.as_ref();
    match list_path_large_to_csv_inner(
        rclone,
        target,
        options.include_hashes,
        csv_path,
        max_in_memory,
        &mut on_progress,
    ) {
        Ok(result) => Ok(result),
        Err(err) => {
            // Best-effort fallback: if requesting hashes breaks listing, retry without.
            if options.include_hashes {
                if let Ok(result) = list_path_large_to_csv_inner(
                    rclone,
                    target,
                    false,
                    csv_path,
                    max_in_memory,
                    &mut on_progress,
                ) {
                    return Ok(result);
                }
            }
            Err(err)
        }
    }
}

fn build_lsjson_args(target: &str, include_hashes: bool) -> Vec<&str> {
    let mut args = vec!["lsjson"];
    if include_hashes {
        args.push("--hash");
    }
    args.push("--recursive");
    args.push(target);
    args
}

fn list_path_inner(rclone: &RcloneRunner, target: &str, include_hashes: bool) -> Result<Vec<FileEntry>> {
    let mut entries = Vec::new();
    let mut on_entry = |raw: RcloneLsJsonEntry| -> Result<()> {
        entries.push(FileEntry::from(raw));
        Ok(())
    };

    run_lsjson_streaming(rclone, target, include_hashes, &mut on_entry, None)?;
    Ok(entries)
}

fn list_path_with_progress_inner<F>(
    rclone: &RcloneRunner,
    target: &str,
    include_hashes: bool,
    on_progress: &mut F,
) -> Result<Vec<FileEntry>>
where
    F: FnMut(usize),
{
    let mut entries = Vec::new();
    let mut on_entry = |raw: RcloneLsJsonEntry| -> Result<()> {
        entries.push(FileEntry::from(raw));
        Ok(())
    };

    run_lsjson_streaming(
        rclone,
        target,
        include_hashes,
        &mut on_entry,
        Some(on_progress),
    )?;

    Ok(entries)
}

fn list_path_large_to_csv_inner(
    rclone: &RcloneRunner,
    target: &str,
    include_hashes: bool,
    csv_path: &Path,
    max_in_memory: usize,
    on_progress: &mut dyn FnMut(usize),
) -> Result<LargeListingResult> {
    let mut csv = crate::files::export::ListingCsvWriter::create(csv_path)?;

    let mut entries: Vec<FileEntry> = Vec::new();
    let mut on_entry = |raw: RcloneLsJsonEntry| -> Result<()> {
        let entry = FileEntry::from(raw);
        csv.write_entry(&entry)?;
        if entries.len() < max_in_memory {
            entries.push(entry);
        }
        Ok(())
    };

    let total_entries = run_lsjson_streaming(
        rclone,
        target,
        include_hashes,
        &mut on_entry,
        Some(on_progress),
    )?;

    csv.flush()?;

    Ok(LargeListingResult {
        truncated: total_entries > entries.len(),
        entries,
        total_entries,
    })
}

fn run_lsjson_streaming<'a>(
    rclone: &RcloneRunner,
    target: &str,
    include_hashes: bool,
    on_entry: &'a mut dyn FnMut(RcloneLsJsonEntry) -> Result<()>,
    on_progress: Option<&'a mut dyn FnMut(usize)>,
) -> Result<usize> {
    let args = build_lsjson_args(target, include_hashes);
    let mut child = rclone.spawn(&args)?;

    let stdout = child.stdout.take().expect("stdout piped");
    let stderr = child.stderr.take().expect("stderr piped");

    let stderr_handle = thread::spawn(move || {
        let reader = BufReader::new(stderr);
        reader.lines().map_while(Result::ok).collect::<Vec<_>>()
    });

    let stdout_reader = BufReader::new(stdout);
    let parse_result = stream_lsjson_entries_from_reader(stdout_reader, on_entry, on_progress);

    if parse_result.is_err() {
        let _ = child.kill();
    }

    let status = child.wait()?;
    let stderr_lines = stderr_handle
        .join()
        .unwrap_or_else(|_| vec!["<stderr capture panicked>".to_string()]);

    if status.code().unwrap_or(-1) != 0 {
        bail!("rclone lsjson failed: {}", stderr_lines.join("\n"));
    }

    parse_result
}

fn stream_lsjson_entries_from_reader<'a, R: Read>(
    reader: R,
    on_entry: &'a mut dyn FnMut(RcloneLsJsonEntry) -> Result<()>,
    on_progress: Option<&'a mut dyn FnMut(usize)>,
) -> Result<usize> {
    let mut json_reader = JsonPayloadReader::new(reader);
    let count = {
        let mut de = serde_json::Deserializer::from_reader(&mut json_reader);
        // Pull in the trait so we can call `deserialize_seq`.
        use serde::de::Deserializer as _;

        let visitor = LsjsonSeqVisitor {
            on_entry,
            on_progress,
            count: 0,
            last_emit: 0,
        };
        de.deserialize_seq(visitor)
            .with_context(|| "Failed to parse rclone lsjson JSON payload")?
    };

    // Drain remaining stdout bytes (e.g., noisy suffix logs) so the child can exit.
    let _ = json_reader.drain_inner_to_end();

    Ok(count)
}

struct LsjsonSeqVisitor<'a> {
    on_entry: &'a mut dyn FnMut(RcloneLsJsonEntry) -> Result<()>,
    on_progress: Option<&'a mut dyn FnMut(usize)>,
    count: usize,
    last_emit: usize,
}

impl<'de> Visitor<'de> for LsjsonSeqVisitor<'_> {
    type Value = usize;

    fn expecting(&self, formatter: &mut fmt::Formatter) -> fmt::Result {
        formatter.write_str("a JSON array of rclone lsjson entries")
    }

    fn visit_seq<A>(mut self, mut seq: A) -> std::result::Result<Self::Value, A::Error>
    where
        A: SeqAccess<'de>,
    {
        while let Some(entry) = seq.next_element::<RcloneLsJsonEntry>()? {
            (self.on_entry)(entry).map_err(de::Error::custom)?;
            self.count += 1;

            if let Some(progress) = self.on_progress.as_mut() {
                if self.count - self.last_emit >= 100 {
                    progress(self.count);
                    self.last_emit = self.count;
                }
            }
        }

        if let Some(progress) = self.on_progress.as_mut() {
            if self.count != self.last_emit {
                progress(self.count);
            }
        }

        Ok(self.count)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum JsonPayloadState {
    Seeking,
    Streaming,
    Done,
}

/// Wrap a reader and expose only the first JSON payload (array or object), ignoring any
/// prefix/suffix noise. This helps when rclone (or the environment) leaks logs to stdout.
struct JsonPayloadReader<R> {
    inner: R,
    state: JsonPayloadState,
    open: u8,
    close: u8,
    depth: i32,
    in_string: bool,
    escape: bool,
    buf: Vec<u8>,
    buf_pos: usize,
}

impl<R: Read> JsonPayloadReader<R> {
    fn new(inner: R) -> Self {
        Self {
            inner,
            state: JsonPayloadState::Seeking,
            open: b'[',
            close: b']',
            depth: 0,
            in_string: false,
            escape: false,
            buf: Vec::new(),
            buf_pos: 0,
        }
    }

    fn drain_inner_to_end(&mut self) -> io::Result<()> {
        let mut tmp = [0u8; 8192];
        while self.inner.read(&mut tmp)? != 0 {}
        Ok(())
    }

    fn push_byte(&mut self, b: u8) {
        self.buf.push(b);
    }

    fn start_json(&mut self, open: u8, close: u8, b: u8) {
        self.state = JsonPayloadState::Streaming;
        self.open = open;
        self.close = close;
        self.depth = 1;
        self.in_string = false;
        self.escape = false;
        self.push_byte(b);
    }

    fn handle_stream_byte(&mut self, b: u8) {
        self.push_byte(b);

        if self.in_string {
            if self.escape {
                self.escape = false;
                return;
            }
            match b {
                b'\\' => self.escape = true,
                b'"' => self.in_string = false,
                _ => {}
            }
            return;
        }

        match b {
            b'"' => self.in_string = true,
            b if b == self.open => self.depth += 1,
            b if b == self.close => {
                self.depth -= 1;
                if self.depth <= 0 {
                    self.state = JsonPayloadState::Done;
                }
            }
            _ => {}
        }
    }
}

impl<R: Read> Read for JsonPayloadReader<R> {
    fn read(&mut self, out: &mut [u8]) -> io::Result<usize> {
        if out.is_empty() {
            return Ok(0);
        }

        loop {
            if self.buf_pos < self.buf.len() {
                let available = self.buf.len() - self.buf_pos;
                let n = available.min(out.len());
                out[..n].copy_from_slice(&self.buf[self.buf_pos..self.buf_pos + n]);
                self.buf_pos += n;
                if self.buf_pos == self.buf.len() {
                    self.buf.clear();
                    self.buf_pos = 0;
                }
                return Ok(n);
            }

            if self.state == JsonPayloadState::Done {
                return Ok(0);
            }

            let mut tmp = [0u8; 8192];
            let read = self.inner.read(&mut tmp)?;
            if read == 0 {
                self.state = JsonPayloadState::Done;
                return Ok(0);
            }

            for &b in &tmp[..read] {
                match self.state {
                    JsonPayloadState::Seeking => match b {
                        b'[' => self.start_json(b'[', b']', b),
                        b'{' => self.start_json(b'{', b'}', b),
                        _ => {}
                    },
                    JsonPayloadState::Streaming => {
                        self.handle_stream_byte(b);
                        if self.state == JsonPayloadState::Done {
                            break;
                        }
                    }
                    JsonPayloadState::Done => break,
                }
            }
        }
    }
}

fn select_hash(hashes: Option<&HashMap<String, String>>) -> (Option<String>, Option<String>) {
    let hashes = match hashes {
        Some(h) => h,
        None => return (None, None),
    };

    let preferred = ["sha256", "sha1", "md5", "quickxorhash", "dropbox"];
    for key in preferred.iter() {
        if let Some(value) = hashes
            .iter()
            .find(|(k, _)| k.eq_ignore_ascii_case(key))
            .map(|(_, v)| v)
        {
            return (Some(value.clone()), Some(key.to_string()));
        }
    }

    // Fallback to first hash if available
    if let Some((k, v)) = hashes.iter().next() {
        return (Some(v.clone()), Some(k.clone()));
    }

    (None, None)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Cursor;

    #[test]
    fn test_parse_lsjson() {
        let data = r#"[
            {"Path":"file1.txt","Size":12,"ModTime":"2024-01-01T00:00:00Z","IsDir":false,"Hashes":{"MD5":"abc"}},
            {"Path":"folder","Size":0,"ModTime":"2024-01-01T00:00:00Z","IsDir":true}
        ]"#;

        let entries: Vec<RcloneLsJsonEntry> = serde_json::from_str(data).unwrap();
        let files: Vec<FileEntry> = entries.into_iter().map(FileEntry::from).collect();

        assert_eq!(files.len(), 2);
        assert_eq!(files[0].path, "file1.txt");
        assert_eq!(files[0].hash_type.as_deref(), Some("md5"));
        assert_eq!(files[0].hash.as_deref(), Some("abc"));
        assert!(files[1].is_dir);
    }

    #[test]
    fn test_select_hash_preferred() {
        let mut hashes = HashMap::new();
        hashes.insert("MD5".to_string(), "md5val".to_string());
        hashes.insert("SHA1".to_string(), "sha1val".to_string());

        let (hash, hash_type) = select_hash(Some(&hashes));
        assert_eq!(hash, Some("sha1val".to_string()));
        assert_eq!(hash_type, Some("sha1".to_string()));
    }

    #[test]
    fn test_stream_lsjson_entries_handles_noise_and_brackets_in_strings() {
        let data = r#"2024/01/01 00:00:00 INFO  : some log
[
  {"Path":"folder[1]/file].txt","Size":12,"ModTime":"2024-01-01T00:00:00Z","IsDir":false}
]
2024/01/01 00:00:00 INFO  : done"#;

        let mut paths: Vec<String> = Vec::new();
        let mut progress: Vec<usize> = Vec::new();

        let mut on_entry = |entry: RcloneLsJsonEntry| -> Result<()> {
            paths.push(entry.path);
            Ok(())
        };
        let mut on_progress = |count: usize| {
            progress.push(count);
        };

        let count = stream_lsjson_entries_from_reader(
            Cursor::new(data.as_bytes()),
            &mut on_entry,
            Some(&mut on_progress),
        )
        .unwrap();

        assert_eq!(count, 1);
        assert_eq!(paths, vec!["folder[1]/file].txt".to_string()]);
        assert_eq!(progress.last().copied(), Some(1));
    }
}
