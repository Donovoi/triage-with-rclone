//! File listing utilities

use anyhow::{bail, Context, Result};
use chrono::{DateTime, Utc};
use serde::de::{self, SeqAccess, Visitor};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::fmt;
use std::fs::OpenOptions;
use std::io::Write;
use std::io::{self, BufRead, BufReader, Read};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{mpsc, Arc};
use std::thread;

use crate::rclone::RcloneRunner;

#[derive(Debug, Clone, Copy)]
pub struct ListPathOptions {
    /// If true, request hashes from rclone (when the backend supports it).
    pub include_hashes: bool,
    /// If true, pass `--fast-list` to rclone (batch directory listing).
    /// Some providers (e.g. Google Drive) may return 0 results with fast-list
    /// in certain configurations, so callers can retry with this set to false.
    pub fast_list: bool,
}

impl ListPathOptions {
    pub fn with_hashes() -> Self {
        Self {
            include_hashes: true,
            fast_list: true,
        }
    }

    pub fn without_hashes() -> Self {
        Self {
            include_hashes: false,
            fast_list: true,
        }
    }

    /// Return a copy with `fast_list` disabled.
    pub fn without_fast_list(mut self) -> Self {
        self.fast_list = false;
        self
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
    /// Which remote this entry belongs to (set when listing a combine remote).
    /// `None` for single-remote sessions (backward compatible).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub remote_name: Option<String>,
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

/// PowerShell module compatibility separator (U+00B6 PILCROW SIGN), matching
/// `rcloned.psm1`'s `[char]0182`.
pub const PS_LSF_SEPARATOR: char = '\u{00B6}';
const PS_LSF_SEPARATOR_STR: &str = "\u{00B6}";

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
            remote_name: None,
        }
    }
}

/// Tag each entry with a remote name by splitting off the first path component
/// when the listing came from a combine remote.
///
/// Combine remotes return paths like `gdrive/Documents/report.pdf` where the
/// first component is the upstream name. This function splits those paths so
/// `FileEntry.remote_name = Some("gdrive")` and `FileEntry.path = "Documents/report.pdf"`.
pub fn tag_entries_with_remote(entries: &mut [FileEntry], known_remotes: &[String]) {
    for entry in entries.iter_mut() {
        if let Some((first, rest)) = entry.path.split_once('/') {
            if known_remotes.iter().any(|r| r == first) {
                entry.remote_name = Some(first.to_string());
                entry.path = rest.to_string();
            }
        } else if known_remotes.iter().any(|r| r == &entry.path) {
            // Top-level directory matching a remote name
            entry.remote_name = Some(entry.path.clone());
            entry.path = String::new();
        }
    }
}

/// List files for a given rclone path (remote or local)
///
/// Example:
/// - Remote: "mydrive:" or "mydrive:/folder"
/// - Local: "/tmp"
pub fn list_path(
    rclone: &RcloneRunner,
    target: &str,
    options: ListPathOptions,
) -> Result<Vec<FileEntry>> {
    match list_path_inner(rclone, target, options.include_hashes, options.fast_list) {
        Ok(entries) => Ok(entries),
        Err(err) => {
            tracing::warn!(error = %err, "lsjson failed, attempting fallback");
            // Fallback 1: retry without hashes
            if options.include_hashes {
                if let Ok(entries) = list_path_inner(rclone, target, false, options.fast_list) {
                    return Ok(entries);
                }
            }
            // Fallback 2: retry without fast-list (and without hashes)
            if options.fast_list {
                if let Ok(entries) = list_path_inner(rclone, target, false, false) {
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
    match list_path_with_progress_inner(rclone, target, options.include_hashes, options.fast_list, &mut on_progress) {
        Ok(entries) => Ok(entries),
        Err(err) => {
            tracing::warn!(error = %err, "lsjson failed, attempting fallback");
            // Fallback 1: retry without hashes
            if options.include_hashes {
                if let Ok(entries) =
                    list_path_with_progress_inner(rclone, target, false, options.fast_list, &mut on_progress)
                {
                    return Ok(entries);
                }
            }
            // Fallback 2: retry without fast-list (and without hashes)
            if options.fast_list {
                if let Ok(entries) =
                    list_path_with_progress_inner(rclone, target, false, false, &mut on_progress)
                {
                    return Ok(entries);
                }
            }
            Err(err)
        }
    }
}

/// Spawn a background listing task that sends progress updates through a channel.
///
/// Returns a thread handle, a progress receiver, and a cancellation flag.
/// The caller should poll `progress_rx` from the event loop and set `cancel`
/// to `true` to abort.
pub fn spawn_list_with_progress(
    rclone_exe: PathBuf,
    config_path: PathBuf,
    target: String,
    options: ListPathOptions,
) -> (
    std::thread::JoinHandle<()>,
    mpsc::Receiver<crate::ui::ListingProgress>,
    Arc<AtomicBool>,
) {
    use crate::ui::ListingProgress;

    let (tx, rx) = mpsc::channel();
    let cancel = Arc::new(AtomicBool::new(false));
    let cancel_clone = cancel.clone();

    let handle = thread::spawn(move || {
        let run = || -> Result<Vec<FileEntry>> {
            let runner = RcloneRunner::new(&rclone_exe).with_config(&config_path);
            let args_owned = build_lsjson_args_owned(&target, options.include_hashes, options.fast_list);
            let args: Vec<&str> = args_owned.iter().map(|s| s.as_str()).collect();
            tracing::info!(target = &*target, fast_list = options.fast_list, include_hashes = options.include_hashes, "Starting background rclone lsjson");
            let mut child = runner.spawn(&args)?;

            let stdout = child.stdout.take().expect("stdout piped");
            let stderr = child.stderr.take().expect("stderr piped");

            let stderr_handle = thread::spawn(move || {
                let reader = BufReader::new(stderr);
                reader.lines().map_while(Result::ok).collect::<Vec<_>>()
            });

            let tx_progress = tx.clone();
            let cancel_inner = cancel_clone.clone();
            let mut entries = Vec::new();
            let mut count: usize = 0;
            let mut last_emit: usize = 0;

            let mut on_entry = |raw: RcloneLsJsonEntry| -> Result<()> {
                entries.push(FileEntry::from(raw));
                count += 1;
                if count - last_emit >= 100 {
                    let _ = tx_progress.send(ListingProgress::Count(count));
                    last_emit = count;
                    if cancel_inner.load(Ordering::Relaxed) {
                        bail!("Listing cancelled by user");
                    }
                }
                Ok(())
            };

            let stdout_reader = BufReader::new(stdout);
            let stream_result = stream_lsjson_entries_from_reader(stdout_reader, &mut on_entry, None);

            let was_killed = stream_result.count.is_err();
            if was_killed {
                let _ = child.kill();
            }

            let status = child.wait()?;
            let stderr_lines = stderr_handle
                .join()
                .unwrap_or_else(|_| vec!["<stderr capture panicked>".to_string()]);
            let exit_code = status.code().unwrap_or(-1);
            let stderr_msg = stderr_lines.join("\n");

            if was_killed {
                if exit_code == 0 && !stream_result.found_json {
                    return Ok(Vec::new());
                }
                let parse_err = stream_result.count.unwrap_err();
                let detail = if !stderr_msg.trim().is_empty() {
                    format!("stderr: {}", stderr_msg)
                } else {
                    format!("exit code {}", exit_code)
                };
                return Err(parse_err.context(format!(
                    "rclone lsjson output could not be parsed ({})",
                    detail
                )));
            }

            if exit_code != 0 {
                if stderr_msg.trim().is_empty() {
                    bail!(
                        "rclone lsjson failed (exit code {}). Check that the remote is properly configured and the token is valid.",
                        exit_code
                    );
                } else {
                    bail!("rclone lsjson failed: {}", stderr_msg);
                }
            }

            // Attempt fallbacks on failure
            Ok(entries)
        };

        match run() {
            Ok(entries) => {
                let _ = tx.send(ListingProgress::Done(entries));
            }
            Err(e) => {
                // If cancelled, don't report as error
                if cancel_clone.load(Ordering::Relaxed) {
                    let _ = tx.send(ListingProgress::Error("Listing cancelled".to_string()));
                } else {
                    let _ = tx.send(ListingProgress::Error(format!("{:#}", e)));
                }
            }
        }
    });

    (handle, rx, cancel)
}

fn build_lsjson_args_owned(target: &str, include_hashes: bool, fast_list: bool) -> Vec<String> {
    let mut args = vec!["lsjson".to_string(), "-v".to_string()];
    if include_hashes {
        args.push("--hash".to_string());
    }
    args.push("--recursive".to_string());
    if fast_list {
        args.push("--fast-list".to_string());
    }
    args.push(target.to_string());
    args
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
        options.fast_list,
        csv_path,
        max_in_memory,
        &mut on_progress,
    ) {
        Ok(result) => Ok(result),
        Err(err) => {
            tracing::warn!(error = %err, "lsjson failed, attempting fallback");
            // Fallback 1: retry without hashes
            if options.include_hashes {
                if let Ok(result) = list_path_large_to_csv_inner(
                    rclone,
                    target,
                    false,
                    options.fast_list,
                    csv_path,
                    max_in_memory,
                    &mut on_progress,
                ) {
                    return Ok(result);
                }
            }
            // Fallback 2: retry without fast-list (and without hashes)
            if options.fast_list {
                if let Ok(result) = list_path_large_to_csv_inner(
                    rclone,
                    target,
                    false,
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

/// List files using `rclone lsf` and write the raw delimited output to `out_path`.
///
/// This mirrors the PowerShell module approach:
/// `rclone lsf <remote> --format psth -R --files-only [--fast-list] [--hash <type>] --separator <sep>`
///
/// Notes:
/// - Output is a "CSV-like" file using a non-comma delimiter (`PS_LSF_SEPARATOR`).
/// - The file has no header row (PowerShell adds headers at import time).
/// - Only files are listed (`--files-only`), not directories.
pub fn list_path_large_lsf_to_ps_csv_with_progress<F>(
    rclone: &RcloneRunner,
    target: &str,
    hash_type: Option<&str>,
    onedrive_expose_onenote: bool,
    out_path: impl AsRef<Path>,
    max_in_memory: usize,
    mut on_progress: F,
) -> Result<LargeListingResult>
where
    F: FnMut(usize),
{
    let out_path = out_path.as_ref();
    let mut out_file = OpenOptions::new()
        .create(true)
        .truncate(true)
        .write(true)
        .open(out_path)
        .with_context(|| format!("Failed to create listing output: {:?}", out_path))?;

    let mut args: Vec<&str> = vec![
        "lsf",
        target,
        "--format",
        "psth",
        "-R",
        "--files-only",
        "--separator",
        PS_LSF_SEPARATOR_STR,
    ];

    if onedrive_expose_onenote {
        args.push("--onedrive-expose-onenote-files");
    } else {
        args.push("--fast-list");
    }

    if let Some(hash_type) = hash_type {
        if !hash_type.trim().is_empty() {
            args.push("--hash");
            args.push(hash_type);
        }
    }

    let mut child = rclone.spawn(&args)?;
    let stdout = child.stdout.take().expect("stdout piped");
    let stderr = child.stderr.take().expect("stderr piped");

    let stderr_handle = thread::spawn(move || {
        let reader = BufReader::new(stderr);
        reader.lines().map_while(Result::ok).collect::<Vec<_>>()
    });

    let stdout_reader = BufReader::new(stdout);
    let mut entries: Vec<FileEntry> = Vec::new();
    let mut total_entries: usize = 0;
    let mut last_emit: usize = 0;

    for line in stdout_reader.lines() {
        let line = line.unwrap_or_default();
        if line.trim().is_empty() {
            continue;
        }

        // Preserve a PS-compatible raw listing file.
        writeln!(out_file, "{}", line)?;

        total_entries += 1;
        if total_entries - last_emit >= 100 {
            on_progress(total_entries);
            last_emit = total_entries;
            // Avoid buffering too much output in OS caches.
            let _ = out_file.flush();
        }

        if entries.len() < max_in_memory {
            if let Some(entry) = parse_lsf_ps_line(&line, hash_type) {
                entries.push(entry);
            }
        }
    }

    if total_entries != last_emit {
        on_progress(total_entries);
    }

    let status = child.wait()?;
    let stderr_lines = stderr_handle
        .join()
        .unwrap_or_else(|_| vec!["<stderr capture panicked>".to_string()]);

    if status.code().unwrap_or(-1) != 0 {
        bail!("rclone lsf failed: {}", stderr_lines.join("\n"));
    }

    Ok(LargeListingResult {
        truncated: total_entries > entries.len(),
        entries,
        total_entries,
    })
}

fn build_lsjson_args(target: &str, include_hashes: bool, fast_list: bool) -> Vec<&str> {
    let mut args = vec!["lsjson", "-v"];
    if include_hashes {
        args.push("--hash");
    }
    args.push("--recursive");
    if fast_list {
        args.push("--fast-list");
    }
    args.push(target);
    args
}

fn list_path_inner(
    rclone: &RcloneRunner,
    target: &str,
    include_hashes: bool,
    fast_list: bool,
) -> Result<Vec<FileEntry>> {
    let mut entries = Vec::new();
    let mut on_entry = |raw: RcloneLsJsonEntry| -> Result<()> {
        entries.push(FileEntry::from(raw));
        Ok(())
    };

    run_lsjson_streaming(rclone, target, include_hashes, fast_list, &mut on_entry, None)?;
    Ok(entries)
}

fn list_path_with_progress_inner<F>(
    rclone: &RcloneRunner,
    target: &str,
    include_hashes: bool,
    fast_list: bool,
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
        fast_list,
        &mut on_entry,
        Some(on_progress),
    )?;

    Ok(entries)
}

fn list_path_large_to_csv_inner(
    rclone: &RcloneRunner,
    target: &str,
    include_hashes: bool,
    fast_list: bool,
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
        fast_list,
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
    fast_list: bool,
    on_entry: &'a mut dyn FnMut(RcloneLsJsonEntry) -> Result<()>,
    on_progress: Option<&'a mut dyn FnMut(usize)>,
) -> Result<usize> {
    let args = build_lsjson_args(target, include_hashes, fast_list);
    tracing::info!(target = target, fast_list = fast_list, include_hashes = include_hashes, "Starting rclone lsjson");
    let mut child = rclone.spawn(&args)?;

    let stdout = child.stdout.take().expect("stdout piped");
    let stderr = child.stderr.take().expect("stderr piped");

    let stderr_handle = thread::spawn(move || {
        let reader = BufReader::new(stderr);
        reader.lines().map_while(Result::ok).collect::<Vec<_>>()
    });

    let stdout_reader = BufReader::new(stdout);
    let stream_result = stream_lsjson_entries_from_reader(stdout_reader, on_entry, on_progress);

    let was_killed = stream_result.count.is_err();
    if was_killed {
        let _ = child.kill();
    }

    let status = child.wait()?;
    let stderr_lines = stderr_handle
        .join()
        .unwrap_or_else(|_| vec!["<stderr capture panicked>".to_string()]);

    let exit_code = status.code().unwrap_or(-1);
    let stderr_msg = stderr_lines.join("\n");

    // Log raw stdout prefix (non-JSON bytes rclone printed before any payload).
    // This is often the actual error message on failure.
    let stdout_prefix = String::from_utf8_lossy(&stream_result.skipped_prefix);
    if !stdout_prefix.trim().is_empty() {
        tracing::warn!(
            stdout_prefix = %stdout_prefix,
            "rclone lsjson: non-JSON output before payload (possible error message)"
        );
    }

    if !stderr_msg.trim().is_empty() {
        tracing::warn!(exit_code = exit_code, stderr = %stderr_msg, "rclone lsjson stderr output");
    }

    // If we killed the child due to a parse error, report the parse error
    // with all available diagnostic context.
    if was_killed {
        // Special case: rclone exited successfully but produced no JSON at all.
        // This happens when the remote is empty or contains only inaccessible
        // entries (e.g. Google Drive dangling shortcuts). Treat as 0 results.
        if exit_code == 0 && !stream_result.found_json {
            tracing::info!(
                target = target,
                stderr = %stderr_msg,
                "rclone lsjson produced no JSON output (exit 0) — treating as empty listing"
            );
            return Ok(0);
        }

        let parse_err = stream_result.count.unwrap_err();

        // Build a detailed diagnostic message
        let mut detail = format!("exit code {}", exit_code);
        if !stderr_msg.trim().is_empty() {
            detail = format!("stderr: {}", stderr_msg);
        }
        if !stdout_prefix.trim().is_empty() {
            let prefix_truncated = if stdout_prefix.len() > 500 {
                format!("{}...", &stdout_prefix[..500])
            } else {
                stdout_prefix.to_string()
            };
            detail = format!("{} | stdout before JSON: {}", detail, prefix_truncated);
        }

        return Err(parse_err.context(format!(
            "rclone lsjson output could not be parsed ({})",
            detail
        )));
    }

    if exit_code != 0 {
        if stderr_msg.trim().is_empty() {
            bail!(
                "rclone lsjson failed (exit code {}). Check that the remote is properly configured and the token is valid.",
                exit_code
            );
        } else {
            bail!("rclone lsjson failed: {}", stderr_msg);
        }
    }

    let count = stream_result.count?;
    tracing::info!(target = target, entries = count, "rclone lsjson completed");
    Ok(count)
}

/// Outcome of streaming lsjson parsing, including diagnostic info on failure.
struct LsjsonStreamResult {
    /// Number of entries successfully parsed (0 on total failure).
    count: Result<usize>,
    /// Non-JSON bytes rclone printed to stdout before the JSON payload.
    /// Often contains the real error message when rclone fails.
    skipped_prefix: Vec<u8>,
    /// True if a JSON array/object delimiter was found in stdout.
    /// False means rclone produced no JSON at all (e.g. empty remote,
    /// dangling shortcuts only).
    found_json: bool,
}

fn stream_lsjson_entries_from_reader<'a, R: Read>(
    reader: R,
    on_entry: &'a mut dyn FnMut(RcloneLsJsonEntry) -> Result<()>,
    on_progress: Option<&'a mut dyn FnMut(usize)>,
) -> LsjsonStreamResult {
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
            .with_context(|| "Failed to parse rclone lsjson JSON payload")
    };

    let found_json = json_reader.found_json;
    let skipped_prefix = json_reader.skipped_prefix().to_vec();

    // Drain remaining stdout bytes (e.g., noisy suffix logs) so the child can exit.
    let _ = json_reader.drain_inner_to_end();

    LsjsonStreamResult {
        count,
        skipped_prefix,
        found_json,
    }
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
    /// Bytes seen before the first JSON delimiter (non-JSON prefix from rclone).
    skipped: Vec<u8>,
    /// True once we've found the opening `[` or `{` of a JSON payload.
    found_json: bool,
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
            skipped: Vec::new(),
            found_json: false,
        }
    }

    /// Return the bytes rclone printed to stdout before any JSON payload started.
    /// If rclone output an error message instead of JSON, this contains that message.
    fn skipped_prefix(&self) -> &[u8] {
        &self.skipped
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
        self.found_json = true;
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
                        _ => {
                            // Track non-JSON prefix (cap at 2 KB to avoid unbounded growth)
                            if self.skipped.len() < 2048 {
                                self.skipped.push(b);
                            }
                        }
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

fn parse_lsf_ps_line(line: &str, hash_type: Option<&str>) -> Option<FileEntry> {
    let mut parts = line.split(PS_LSF_SEPARATOR);
    let path = parts.next()?.trim().to_string();
    if path.is_empty() {
        return None;
    }

    let size = parts
        .next()
        .and_then(|s| s.trim().parse::<u64>().ok())
        .unwrap_or(0);

    let modified = parts.next().and_then(|s| parse_lsf_modtime(s.trim()));

    let hash = parts
        .next()
        .map(str::trim)
        .filter(|s| !s.is_empty() && *s != "-")
        .map(|s| s.to_string());

    let hash_type = hash
        .as_ref()
        .and(hash_type)
        .map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty());

    Some(FileEntry {
        path,
        size,
        modified,
        is_dir: false,
        hash,
        hash_type,
        remote_name: None,
    })
}

fn parse_lsf_modtime(value: &str) -> Option<DateTime<Utc>> {
    if value.is_empty() || value == "-" {
        return None;
    }

    if let Ok(dt) = DateTime::parse_from_rfc3339(value) {
        return Some(dt.with_timezone(&Utc));
    }

    // Common rclone lsf time output: "2006-01-02 15:04:05"
    if let Ok(naive) = chrono::NaiveDateTime::parse_from_str(value, "%Y-%m-%d %H:%M:%S") {
        return Some(DateTime::<Utc>::from_naive_utc_and_offset(naive, Utc));
    }

    None
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

        let result = stream_lsjson_entries_from_reader(
            Cursor::new(data.as_bytes()),
            &mut on_entry,
            Some(&mut on_progress),
        );
        let count = result.count.unwrap();

        assert_eq!(count, 1);
        assert_eq!(paths, vec!["folder[1]/file].txt".to_string()]);
        assert_eq!(progress.last().copied(), Some(1));
    }

    #[test]
    fn test_parse_lsf_ps_line_basic() {
        let sep = PS_LSF_SEPARATOR;
        let line = format!(
            "Documents/report.pdf{sep}1024{sep}2024-01-01T00:00:00Z{sep}abc",
            sep = sep
        );

        let entry = parse_lsf_ps_line(&line, Some("MD5")).unwrap();
        assert_eq!(entry.path, "Documents/report.pdf");
        assert_eq!(entry.size, 1024);
        assert_eq!(entry.hash.as_deref(), Some("abc"));
        assert_eq!(entry.hash_type.as_deref(), Some("MD5"));
        assert!(!entry.is_dir);
        assert!(entry.modified.is_some());
    }

    #[test]
    fn test_stream_lsjson_empty_stdout_returns_no_json() {
        // Simulates rclone producing no output at all (e.g. only dangling shortcuts
        // in a Google Drive). The parser should report found_json=false.
        let data = b"";
        let mut on_entry = |_: RcloneLsJsonEntry| -> Result<()> { Ok(()) };
        let result = stream_lsjson_entries_from_reader(
            Cursor::new(data.as_ref()),
            &mut on_entry,
            None,
        );
        assert!(!result.found_json, "empty stdout should not count as JSON");
        assert!(result.count.is_err(), "empty stdout should fail to parse");
    }

    #[test]
    fn test_stream_lsjson_empty_array_returns_found_json() {
        // Simulates rclone producing an empty array — valid JSON, 0 entries.
        let data = b"[]";
        let mut on_entry = |_: RcloneLsJsonEntry| -> Result<()> { Ok(()) };
        let result = stream_lsjson_entries_from_reader(
            Cursor::new(data.as_ref()),
            &mut on_entry,
            None,
        );
        assert!(result.found_json, "empty array is valid JSON");
        assert_eq!(result.count.unwrap(), 0);
    }

    #[test]
    fn test_tag_entries_with_remote_splits_paths() {
        let mut entries = vec![
            FileEntry {
                path: "gdrive/Documents/report.pdf".to_string(),
                size: 100,
                modified: None,
                is_dir: false,
                hash: None,
                hash_type: None,
                remote_name: None,
            },
            FileEntry {
                path: "onedrive/Photos/pic.jpg".to_string(),
                size: 200,
                modified: None,
                is_dir: false,
                hash: None,
                hash_type: None,
                remote_name: None,
            },
            FileEntry {
                path: "gdrive".to_string(),
                size: 0,
                modified: None,
                is_dir: true,
                hash: None,
                hash_type: None,
                remote_name: None,
            },
        ];
        let remotes = vec!["gdrive".to_string(), "onedrive".to_string()];
        tag_entries_with_remote(&mut entries, &remotes);

        assert_eq!(entries[0].remote_name.as_deref(), Some("gdrive"));
        assert_eq!(entries[0].path, "Documents/report.pdf");

        assert_eq!(entries[1].remote_name.as_deref(), Some("onedrive"));
        assert_eq!(entries[1].path, "Photos/pic.jpg");

        assert_eq!(entries[2].remote_name.as_deref(), Some("gdrive"));
        assert_eq!(entries[2].path, "");
    }

    #[test]
    fn test_tag_entries_with_remote_ignores_non_matching() {
        let mut entries = vec![FileEntry {
            path: "other/file.txt".to_string(),
            size: 50,
            modified: None,
            is_dir: false,
            hash: None,
            hash_type: None,
            remote_name: None,
        }];
        let remotes = vec!["gdrive".to_string()];
        tag_entries_with_remote(&mut entries, &remotes);

        assert!(entries[0].remote_name.is_none());
        assert_eq!(entries[0].path, "other/file.txt");
    }
}
