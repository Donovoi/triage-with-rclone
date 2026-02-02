//! Report generation

use anyhow::{Context, Result};
use chrono::Utc;
use std::fs;
use std::path::Path;

use super::Case;
use crate::forensics::state::StateDiff;

/// Generate a report as plain text
pub fn generate_report(
    case: &Case,
    state_diff: Option<&StateDiff>,
    change_report: Option<&str>,
    log_hash: Option<&str>,
) -> String {
    let mut report = String::new();

    report.push_str("=== rclone-triage Report ===\n\n");
    report.push_str(&format!("Session: {}\n", case.session_id()));
    report.push_str(&format!("Start Time: {}\n", case.start_time));
    report.push_str(&format!(
        "End Time: {}\n\n",
        case.end_time
            .map(|t| t.to_string())
            .unwrap_or_else(|| "<in-progress>".to_string())
    ));

    report.push_str("--- Providers ---\n");
    if case.providers.is_empty() {
        report.push_str("No providers authenticated.\n\n");
    } else {
        for p in &case.providers {
            report.push_str(&format!(
                "- {} (remote: {}) {}\n",
                p.provider,
                p.remote_name,
                p.user_info.clone().unwrap_or_default()
            ));
        }
        report.push('\n');
    }

    report.push_str("--- Downloads ---\n");
    if case.downloaded_files.is_empty() {
        report.push_str("No files downloaded.\n\n");
    } else {
        for f in &case.downloaded_files {
            report.push_str(&format!(
                "- {} ({} bytes) {:?} {:?}\n",
                f.path, f.size, f.hash_type, f.hash
            ));
        }
        report.push('\n');
    }

    if let Some(diff) = state_diff {
        report.push_str("--- System State Changes ---\n");
        report.push_str(&diff.generate_report());
        report.push('\n');
    }

    if let Some(change_report) = change_report {
        report.push_str("--- Change Tracker Report ---\n");
        report.push_str(change_report);
        report.push('\n');
    }

    if let Some(hash) = log_hash {
        report.push_str("--- Log Integrity ---\n");
        report.push_str(&format!("Final Log Hash: {}\n\n", hash));
    }

    report.push_str(&format!("Report generated at {}\n", Utc::now()));

    report
}

/// Write the report to a file
pub fn write_report(path: impl AsRef<Path>, contents: &str) -> Result<()> {
    let path = path.as_ref();
    fs::write(path, contents).with_context(|| format!("Failed to write report to {:?}", path))?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::case::Case;
    use tempfile::tempdir;

    #[test]
    fn test_generate_report() {
        let case = Case::new("my-session", std::path::PathBuf::from("/tmp")).unwrap();
        let report = generate_report(&case, None, None, Some("hash123"));
        assert!(report.contains("Report"));
        assert!(report.contains("hash123"));
    }

    #[test]
    fn test_write_report() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("report.txt");
        write_report(&path, "hello").unwrap();
        assert!(path.exists());
    }
}
