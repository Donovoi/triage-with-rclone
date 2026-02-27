//! Report generation

use anyhow::{Context, Result};
use chrono::Utc;
use sha2::{Digest, Sha256};
use std::fs;
use std::path::Path;

use super::Case;
use crate::forensics::state::StateDiff;

/// System/operator metadata collected for the forensic report header.
#[derive(Debug, Clone, Default)]
pub struct ReportMetadata {
    /// rclone-triage version (from Cargo)
    pub tool_version: String,
    /// rclone binary version string (output of `rclone version`)
    pub rclone_version: Option<String>,
    /// Operator username
    pub operator: Option<String>,
    /// Machine hostname
    pub hostname: Option<String>,
    /// OS description (e.g. "Linux 6.1.0-amd64" or "Windows 10 22H2")
    pub os_info: Option<String>,
}

impl ReportMetadata {
    /// Build metadata from the current environment.
    pub fn from_environment() -> Self {
        Self {
            tool_version: env!("CARGO_PKG_VERSION").to_string(),
            rclone_version: None, // caller should fill in after extraction
            operator: whoami_user(),
            hostname: whoami_hostname(),
            os_info: Some(os_description()),
        }
    }
}

fn whoami_user() -> Option<String> {
    #[cfg(unix)]
    {
        std::env::var("USER")
            .or_else(|_| std::env::var("LOGNAME"))
            .ok()
    }
    #[cfg(windows)]
    {
        std::env::var("USERNAME").ok()
    }
    #[cfg(not(any(unix, windows)))]
    {
        None
    }
}

fn whoami_hostname() -> Option<String> {
    #[cfg(unix)]
    {
        // gethostname via nix or fallback to /etc/hostname
        std::fs::read_to_string("/etc/hostname")
            .ok()
            .map(|s| s.trim().to_string())
            .filter(|s| !s.is_empty())
            .or_else(|| std::env::var("HOSTNAME").ok())
    }
    #[cfg(windows)]
    {
        std::env::var("COMPUTERNAME").ok()
    }
    #[cfg(not(any(unix, windows)))]
    {
        None
    }
}

fn os_description() -> String {
    let os = std::env::consts::OS;
    let arch = std::env::consts::ARCH;
    format!("{} {}", os, arch)
}

/// Generate a report as plain text
pub fn generate_report(
    case: &Case,
    state_diff: Option<&StateDiff>,
    change_report: Option<&str>,
    cleanup_report: Option<&str>,
    log_hash: Option<&str>,
) -> String {
    generate_report_with_metadata(case, state_diff, change_report, cleanup_report, log_hash, None)
}

/// Generate a report with full metadata (tool version, operator, system info).
pub fn generate_report_with_metadata(
    case: &Case,
    state_diff: Option<&StateDiff>,
    change_report: Option<&str>,
    cleanup_report: Option<&str>,
    log_hash: Option<&str>,
    metadata: Option<&ReportMetadata>,
) -> String {
    let mut report = String::new();

    report.push_str("=== rclone-triage Forensic Report ===\n\n");

    // ── Tool & Environment ──
    if let Some(meta) = metadata {
        report.push_str("--- Tool & Environment ---\n");
        report.push_str(&format!("rclone-triage version: {}\n", meta.tool_version));
        if let Some(ref rv) = meta.rclone_version {
            report.push_str(&format!("rclone version: {}\n", rv));
        }
        if let Some(ref op) = meta.operator {
            report.push_str(&format!("Operator: {}\n", op));
        }
        if let Some(ref host) = meta.hostname {
            report.push_str(&format!("Hostname: {}\n", host));
        }
        if let Some(ref os) = meta.os_info {
            report.push_str(&format!("OS: {}\n", os));
        }
        report.push('\n');
    }

    // ── Case Info ──
    report.push_str("--- Case ---\n");
    report.push_str(&format!("Case: {}\n", case.session_id()));
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
                "- {} [{}] (remote: {}) {}\n",
                p.provider_name,
                p.provider_id,
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
            let verified = match f.hash_verified {
                Some(true) => "verified",
                Some(false) => "mismatch",
                None => "unverified",
            };
            report.push_str(&format!(
                "- {} ({} bytes) {:?} {:?} ({}){}\n",
                f.path,
                f.size,
                f.hash_type,
                f.hash,
                verified,
                f.hash_error
                    .as_deref()
                    .map(|e| format!(" - {}", e))
                    .unwrap_or_default()
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

    if let Some(cleanup_report) = cleanup_report {
        report.push_str(cleanup_report);
        report.push('\n');
    }

    if let Some(hash) = log_hash {
        report.push_str("--- Log Integrity ---\n");
        report.push_str(&format!("Final Log Hash: {}\n\n", hash));
    }

    report.push_str(&format!("Report generated at {}\n", Utc::now()));

    report
}

/// Write the report to a file and append a SHA-256 self-hash for integrity.
pub fn write_report(path: impl AsRef<Path>, contents: &str) -> Result<()> {
    let path = path.as_ref();

    // Compute SHA-256 of the report body (before the hash line itself).
    let hash = {
        let mut hasher = Sha256::new();
        hasher.update(contents.as_bytes());
        hex::encode(hasher.finalize())
    };

    let with_hash = format!(
        "{}\n--- Report Integrity ---\nSHA-256: {}\n",
        contents.trim_end(),
        hash
    );

    fs::write(path, &with_hash)
        .with_context(|| format!("Failed to write report to {:?}", path))?;

    // Restrict file permissions on Unix.
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let perms = std::fs::Permissions::from_mode(0o644);
        std::fs::set_permissions(path, perms).ok();
    }

    Ok(())
}

/// Write the forensic report as an Excel (.xlsx) workbook.
pub fn write_report_xlsx(
    path: impl AsRef<Path>,
    case: &Case,
    state_diff: Option<&StateDiff>,
    metadata: Option<&ReportMetadata>,
) -> Result<()> {
    use anyhow::Context;
    use rust_xlsxwriter::Workbook;

    let path = path.as_ref();
    let path_str = path
        .to_str()
        .ok_or_else(|| anyhow::anyhow!("Invalid path: {:?}", path))?;

    let mut workbook = Workbook::new();

    // --- Summary sheet ---
    let summary = workbook
        .add_worksheet()
        .set_name("Summary")
        .context("Failed to add Summary sheet")?;
    let mut row = 0u32;
    summary.write_string(row, 0, "rclone-triage Forensic Report")?;
    row += 2;

    if let Some(meta) = metadata {
        summary.write_string(row, 0, "Tool Version")?;
        summary.write_string(row, 1, &meta.tool_version)?;
        row += 1;
        if let Some(ref rv) = meta.rclone_version {
            summary.write_string(row, 0, "rclone Version")?;
            summary.write_string(row, 1, rv)?;
            row += 1;
        }
        if let Some(ref op) = meta.operator {
            summary.write_string(row, 0, "Operator")?;
            summary.write_string(row, 1, op)?;
            row += 1;
        }
        if let Some(ref host) = meta.hostname {
            summary.write_string(row, 0, "Hostname")?;
            summary.write_string(row, 1, host)?;
            row += 1;
        }
        if let Some(ref os) = meta.os_info {
            summary.write_string(row, 0, "OS")?;
            summary.write_string(row, 1, os)?;
            row += 1;
        }
        row += 1;
    }

    summary.write_string(row, 0, "Case")?;
    summary.write_string(row, 1, case.session_id())?;
    row += 1;
    summary.write_string(row, 0, "Start Time")?;
    summary.write_string(row, 1, case.start_time.to_string())?;
    row += 1;
    summary.write_string(row, 0, "End Time")?;
    summary.write_string(
        row,
        1,
        case.end_time
            .map(|t| t.to_string())
            .unwrap_or_else(|| "<in-progress>".to_string()),
    )?;
    row += 1;
    summary.write_string(row, 0, "Providers Authenticated")?;
    summary.write_number(row, 1, case.providers.len() as f64)?;
    row += 1;
    summary.write_string(row, 0, "Files Downloaded")?;
    summary.write_number(row, 1, case.downloaded_files.len() as f64)?;

    // --- Providers sheet ---
    if !case.providers.is_empty() {
        let providers_sheet = workbook
            .add_worksheet()
            .set_name("Providers")
            .context("Failed to add Providers sheet")?;
        let headers = ["Provider", "ID", "Remote", "User Info"];
        for (col, h) in headers.iter().enumerate() {
            providers_sheet.write_string(0, col as u16, *h)?;
        }
        for (i, p) in case.providers.iter().enumerate() {
            let r = (i + 1) as u32;
            providers_sheet.write_string(r, 0, &p.provider_name)?;
            providers_sheet.write_string(r, 1, &p.provider_id)?;
            providers_sheet.write_string(r, 2, &p.remote_name)?;
            providers_sheet.write_string(r, 3, p.user_info.as_deref().unwrap_or(""))?;
        }
    }

    // --- Downloads sheet ---
    if !case.downloaded_files.is_empty() {
        let downloads_sheet = workbook
            .add_worksheet()
            .set_name("Downloads")
            .context("Failed to add Downloads sheet")?;
        let headers = ["Path", "Size", "Hash", "HashType", "Verified", "Error"];
        for (col, h) in headers.iter().enumerate() {
            downloads_sheet.write_string(0, col as u16, *h)?;
        }
        for (i, f) in case.downloaded_files.iter().enumerate() {
            let r = (i + 1) as u32;
            downloads_sheet.write_string(r, 0, &f.path)?;
            downloads_sheet.write_number(r, 1, f.size as f64)?;
            downloads_sheet.write_string(r, 2, f.hash.as_deref().unwrap_or(""))?;
            downloads_sheet.write_string(r, 3, f.hash_type.as_deref().unwrap_or(""))?;
            let verified = match f.hash_verified {
                Some(true) => "verified",
                Some(false) => "mismatch",
                None => "unverified",
            };
            downloads_sheet.write_string(r, 4, verified)?;
            downloads_sheet.write_string(r, 5, f.hash_error.as_deref().unwrap_or(""))?;
        }
    }

    // --- System Changes sheet ---
    if let Some(diff) = state_diff {
        if diff.has_changes() {
            let changes_sheet = workbook
                .add_worksheet()
                .set_name("System Changes")
                .context("Failed to add System Changes sheet")?;
            changes_sheet.write_string(0, 0, "System State Changes")?;
            let report_text = diff.generate_report();
            for (i, line) in report_text.lines().enumerate() {
                changes_sheet.write_string((i + 1) as u32, 0, line)?;
            }
        }
    }

    workbook.save(path_str).context("Failed to save XLSX report")?;
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
        let report = generate_report(&case, None, None, None, Some("hash123"));
        assert!(report.contains("Forensic Report"));
        assert!(report.contains("hash123"));
    }

    #[test]
    fn test_generate_report_with_metadata() {
        let case = Case::new("meta-session", std::path::PathBuf::from("/tmp")).unwrap();
        let meta = ReportMetadata {
            tool_version: "0.1.0".to_string(),
            rclone_version: Some("v1.68.2".to_string()),
            operator: Some("examiner1".to_string()),
            hostname: Some("forensic-ws".to_string()),
            os_info: Some("linux x86_64".to_string()),
        };
        let report = generate_report_with_metadata(
            &case, None, None, None, None, Some(&meta),
        );
        assert!(report.contains("rclone-triage version: 0.1.0"));
        assert!(report.contains("rclone version: v1.68.2"));
        assert!(report.contains("Operator: examiner1"));
        assert!(report.contains("Hostname: forensic-ws"));
        assert!(report.contains("OS: linux x86_64"));
    }

    #[test]
    fn test_write_report_with_self_hash() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("report.txt");
        write_report(&path, "hello").unwrap();
        assert!(path.exists());

        let content = std::fs::read_to_string(&path).unwrap();
        assert!(content.contains("SHA-256:"));
        assert!(content.contains("Report Integrity"));
    }

    #[test]
    fn test_write_report_xlsx() {
        let dir = tempdir().unwrap();
        let xlsx_path = dir.path().join("report.xlsx");

        let mut case = Case::new("xlsx-test", std::path::PathBuf::from("/tmp")).unwrap();
        case.add_provider(crate::case::AuthenticatedProvider {
            provider_id: "drive".to_string(),
            provider_name: "Google Drive".to_string(),
            remote_name: "gdrive".to_string(),
            user_info: Some("user@example.com".to_string()),
        });
        case.add_download(crate::case::DownloadedFile {
            path: "file.txt".to_string(),
            size: 1234,
            hash: Some("abc123".to_string()),
            hash_type: Some("sha256".to_string()),
            hash_verified: Some(true),
            hash_error: None,
        });
        case.finalize();

        let meta = ReportMetadata {
            tool_version: "0.1.0".to_string(),
            rclone_version: Some("v1.68.2".to_string()),
            operator: Some("examiner1".to_string()),
            hostname: Some("ws".to_string()),
            os_info: Some("linux x86_64".to_string()),
        };

        write_report_xlsx(&xlsx_path, &case, None, Some(&meta)).unwrap();
        assert!(xlsx_path.exists());
        assert!(std::fs::metadata(&xlsx_path).unwrap().len() > 0);
    }
}
