//! Path safety helpers.
//!
//! rclone remote paths are untrusted input. When mapping them to local filesystem paths we must:
//! - Prevent absolute-path escapes (e.g. `/etc/passwd`, `C:\Windows\...`)
//! - Prevent `..` traversal
//! - Sanitize characters that are illegal on Windows filesystems
//!
//! This module provides a best-effort mapping that keeps directory structure where possible
//! while guaranteeing the resulting path stays under a caller-provided base directory.

use sha2::{Digest, Sha256};
use std::path::{Path, PathBuf};

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SafeMappedPath {
    pub path: PathBuf,
    pub changed: bool,
}

fn hash8(input: &str) -> String {
    let mut hasher = Sha256::new();
    hasher.update(input.as_bytes());
    let full = hex::encode(hasher.finalize());
    full.chars().take(8).collect()
}

pub(crate) fn is_windows_reserved_name(name: &str) -> bool {
    // Windows device names are reserved (case-insensitive), even with extensions (e.g. CON.txt).
    // See: https://learn.microsoft.com/windows/win32/fileio/naming-a-file
    let upper = name.to_ascii_uppercase();
    matches!(
        upper.as_str(),
        "CON"
            | "PRN"
            | "AUX"
            | "NUL"
            | "COM1"
            | "COM2"
            | "COM3"
            | "COM4"
            | "COM5"
            | "COM6"
            | "COM7"
            | "COM8"
            | "COM9"
            | "LPT1"
            | "LPT2"
            | "LPT3"
            | "LPT4"
            | "LPT5"
            | "LPT6"
            | "LPT7"
            | "LPT8"
            | "LPT9"
    )
}

fn sanitize_component(raw: &str) -> (String, bool) {
    let mut changed = false;
    let mut out = String::with_capacity(raw.len());

    for c in raw.chars() {
        let invalid = matches!(c, '<' | '>' | ':' | '"' | '/' | '\\' | '|' | '?' | '*')
            || c.is_control();
        if invalid {
            out.push('_');
            changed = true;
        } else {
            out.push(c);
        }
    }

    // Windows: trailing dots/spaces are not allowed. Apply everywhere for cross-platform safety.
    let trimmed = out.trim_end_matches(['.', ' ']).to_string();
    if trimmed.len() != out.len() {
        changed = true;
    }
    out = trimmed;

    // Avoid empty path components.
    if out.is_empty() {
        return ("_".to_string(), true);
    }

    // Avoid reserved device names (check the stem, ignoring extensions).
    let stem = out.split('.').next().unwrap_or(&out);
    if is_windows_reserved_name(stem) {
        out = format!("_{}", out);
        changed = true;
    }

    // Prevent "." and ".." after sanitization.
    if out == "." || out == ".." {
        return ("_".to_string(), true);
    }

    (out, changed)
}

fn append_suffix(filename: &str, suffix: &str) -> String {
    if let Some((stem, ext)) = filename.rsplit_once('.') {
        if !stem.is_empty() && !ext.is_empty() {
            return format!("{}{}.{ext}", stem, suffix);
        }
    }
    format!("{}{}", filename, suffix)
}

/// Map an untrusted remote path into a safe local path under `base`.
///
/// This is best-effort: it preserves directory structure where possible, but will:
/// - strip leading path separators
/// - drop "." and ".." components
/// - sanitize illegal filesystem characters (especially for Windows)
/// - if any change occurred, append a stable suffix to the final component based on the original path
pub fn safe_join_under(base: &Path, remote_path: &str) -> SafeMappedPath {
    let original = remote_path.trim();
    let normalized = original.replace('\\', "/");

    let mut changed = normalized != original;
    let mut parts: Vec<String> = Vec::new();

    let stripped = normalized.trim_start_matches('/');
    if stripped.len() != normalized.len() {
        changed = true;
    }

    for raw_part in stripped.split('/') {
        if raw_part.is_empty() {
            if !parts.is_empty() {
                changed = true;
            }
            continue;
        }
        if raw_part == "." {
            changed = true;
            continue;
        }
        if raw_part == ".." {
            changed = true;
            continue;
        }

        let (sanitized, part_changed) = sanitize_component(raw_part);
        if part_changed {
            changed = true;
        }
        parts.push(sanitized);
    }

    if parts.is_empty() {
        let h = hash8(&normalized);
        let name = format!("file__triage_{}", h);
        return SafeMappedPath {
            path: base.join(name),
            changed: true,
        };
    }

    if changed {
        let h = hash8(&normalized);
        let suffix = format!("__triage_{}", h);
        if let Some(last) = parts.last_mut() {
            *last = append_suffix(last, &suffix);
        }
    }

    let mut out = base.to_path_buf();
    for part in parts {
        out.push(part);
    }

    SafeMappedPath { path: out, changed }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_safe_join_under_preserves_simple_relative() {
        let base = Path::new("/tmp/base");
        let mapped = safe_join_under(base, "a/b.txt");
        assert!(!mapped.changed);
        assert_eq!(mapped.path, PathBuf::from("/tmp/base/a/b.txt"));
    }

    #[test]
    fn test_safe_join_under_strips_absolute() {
        let base = Path::new("/tmp/base");
        let mapped = safe_join_under(base, "/etc/passwd");
        assert!(mapped.changed);
        assert!(mapped.path.starts_with(base));
        assert!(mapped.path.to_string_lossy().contains("etc"));
    }

    #[test]
    fn test_safe_join_under_drops_parent_dir() {
        let base = Path::new("/tmp/base");
        let mapped = safe_join_under(base, "../secret.txt");
        assert!(mapped.changed);
        assert!(mapped.path.starts_with(base));
        // Ensure we didn't keep ".." anywhere.
        assert!(!mapped.path.to_string_lossy().contains(".."));
    }

    #[test]
    fn test_safe_join_under_sanitizes_windows_drive_like() {
        let base = Path::new("/tmp/base");
        let mapped = safe_join_under(base, r"C:\Windows\System32\foo.txt");
        assert!(mapped.changed);
        assert!(mapped.path.starts_with(base));
        // ':' is replaced so we don't accidentally create a Windows prefix component later.
        assert!(!mapped.path.to_string_lossy().contains("C:"));
    }

    #[test]
    fn test_safe_join_under_avoids_reserved_names() {
        let base = Path::new("/tmp/base");
        let mapped = safe_join_under(base, "CON.txt");
        assert!(mapped.changed);
        assert!(mapped.path.starts_with(base));
        // Must not end with "CON.txt" exactly.
        assert!(!mapped.path.to_string_lossy().ends_with("/CON.txt"));
    }
}

