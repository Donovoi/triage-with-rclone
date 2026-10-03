use std::collections::{HashMap, HashSet};
use std::fs::OpenOptions;
use std::path::{Path, PathBuf};
use std::time::Duration;

use anyhow::{bail, Result};
use rclone_triage::providers::discovery::providers_from_rclone;
use rclone_triage::providers::{ProviderAuthKind, ProviderEntry};
use rclone_triage::rclone::{ParsedConfig, RcloneConfig, RcloneRunner};
use serde::Serialize;
use sha2::{Digest, Sha256};

#[derive(Debug, Clone, PartialEq, Eq)]
struct SmokeRemote {
    backend: String,
    remote_name: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
enum Status {
    NotConfigured,
    NotRequested,
    NotRun,
    Passed,
    Failed,
}

#[derive(Debug, Serialize)]
struct CoverageRow {
    backend: String,
    auth_kind: ProviderAuthKind,
    configured_remotes: usize,
    checked_remotes: usize,
    status: Status,
}

#[derive(Debug, Serialize)]
struct CoverageReport {
    schema_version: u8,
    runtime_version: String,
    scope: &'static str,
    // Access with saved credentials cannot prove a new login or refresh grant.
    fresh_login_verified: bool,
    refresh_grant_verified: bool,
    all_discovered_providers_passed: bool,
    errors: Vec<&'static str>,
    providers: Vec<CoverageRow>,
}

impl CoverageReport {
    fn new(catalog: &[ProviderEntry], version: String) -> Self {
        Self {
            schema_version: 1,
            runtime_version: version,
            scope: "existing_credentials_shallow_read_access_only",
            fresh_login_verified: false,
            refresh_grant_verified: false,
            all_discovered_providers_passed: false,
            errors: Vec::new(),
            providers: catalog
                .iter()
                .map(|entry| CoverageRow {
                    backend: entry.id.clone(),
                    auth_kind: entry.auth_kind(),
                    configured_remotes: 0,
                    checked_remotes: 0,
                    status: Status::NotConfigured,
                })
                .collect(),
        }
    }

    fn record(&mut self, backend: &str, passed: bool) {
        let row = self
            .providers
            .iter_mut()
            .find(|p| p.backend == backend)
            .unwrap();
        row.checked_remotes += 1;
        // A second successful account cannot hide a failed account.
        row.status = if !passed || row.status == Status::Failed {
            Status::Failed
        } else {
            Status::Passed
        };
    }

    fn finish(&mut self) {
        self.all_discovered_providers_passed = self.errors.is_empty()
            && !self.providers.is_empty()
            && self.providers.iter().all(|p| p.status == Status::Passed);
    }
}

fn requested_backends(raw: &str) -> Result<HashSet<String>> {
    let requested: HashSet<String> = raw
        .split(',')
        .map(|value| value.trim().to_ascii_lowercase())
        .filter(|value| !value.is_empty())
        .collect();
    if !raw.trim().is_empty() && requested.is_empty() {
        bail!("A nonempty provider filter must contain a backend or Test remote");
    }
    Ok(requested)
}

fn matches_request(remote: &SmokeRemote, entry: &ProviderEntry, requested: &str) -> bool {
    entry.matches_rclone_type(requested)
        || requested.eq_ignore_ascii_case(&remote.remote_name)
        || entry
            .known
            .is_some_and(|provider| requested == provider.short_name())
}

fn collect_smoke_remotes(
    parsed: &ParsedConfig,
    catalog: &[ProviderEntry],
) -> Result<Vec<SmokeRemote>> {
    let mut remotes = Vec::new();
    let mut names = HashMap::new();
    for remote in &parsed.remotes {
        *names
            .entry(remote.name.to_ascii_lowercase())
            .or_insert(0usize) += 1;
    }
    for remote in parsed
        .remotes
        .iter()
        .filter(|remote| remote.name.starts_with("Test"))
    {
        if names[&remote.name.to_ascii_lowercase()] != 1 {
            bail!("Duplicate or case-aliased Test remote");
        }
        let Some(provider) = catalog
            .iter()
            .find(|p| p.matches_rclone_type(&remote.remote_type))
        else {
            bail!("Test remote has an unavailable or excluded backend");
        };
        remotes.push(SmokeRemote {
            backend: provider.id.clone(),
            remote_name: remote.name.clone(),
        });
    }
    remotes.sort_by(|a, b| {
        a.backend
            .cmp(&b.backend)
            .then(a.remote_name.cmp(&b.remote_name))
    });
    Ok(remotes)
}

fn select_smoke_remotes(
    remotes: &[SmokeRemote],
    catalog: &[ProviderEntry],
    requested: &HashSet<String>,
) -> Result<Vec<SmokeRemote>> {
    let matches = |remote: &SmokeRemote, request: &str| {
        let provider = catalog.iter().find(|p| p.id == remote.backend).unwrap();
        matches_request(remote, provider, request)
    };
    if requested
        .iter()
        .any(|request| !remotes.iter().any(|r| matches(r, request)))
    {
        bail!("A requested backend or Test remote is not configured");
    }
    Ok(remotes
        .iter()
        .filter(|remote| requested.is_empty() || requested.iter().any(|r| matches(remote, r)))
        .cloned()
        .collect())
}

fn run_shallow_read(runner: &RcloneRunner, remote: &SmokeRemote) -> Result<()> {
    let target = format!("{}:", remote.remote_name);
    let output = runner.run(&[
        "lsjson",
        "--max-depth",
        "1",
        "--hash",
        "--retries",
        "1",
        "--low-level-retries",
        "1",
        "--",
        &target,
    ])?;
    if !output.success() {
        bail!("Shallow read failed");
    }
    let entries: Vec<serde_json::Value> = serde_json::from_str(&output.stdout_string())?;
    if entries.iter().any(|entry| {
        !entry.is_object()
            || entry.get("Path").and_then(|p| p.as_str()).is_none()
            || entry.get("IsDir").and_then(|p| p.as_bool()).is_none()
    }) {
        bail!("Shallow read returned invalid entries");
    }
    Ok(())
}

fn require_full_selection(
    catalog: &[ProviderEntry],
    selected: &[SmokeRemote],
    required: bool,
) -> Result<()> {
    if required
        && catalog
            .iter()
            .any(|p| !selected.iter().any(|r| r.backend == p.id))
    {
        bail!("Full provider coverage requires accounts for every discovered backend");
    }
    Ok(())
}

fn write_report(report: &CoverageReport, path: Option<&Path>) -> Result<()> {
    if let Some(path) = path {
        let file = OpenOptions::new().write(true).create_new(true).open(path)?;
        serde_json::to_writer_pretty(file, report)?;
    }
    for row in &report.providers {
        println!(
            "{}: {:?} ({} checked)",
            row.backend, row.status, row.checked_remotes
        );
    }
    println!("Fresh login and refresh grants: NOT VERIFIED by this access test.");
    Ok(())
}

fn env_flag(name: &str) -> Result<bool> {
    match std::env::var(name).as_deref() {
        Err(std::env::VarError::NotPresent) | Ok("") | Ok("false") | Ok("0") => Ok(false),
        Ok("true") | Ok("1") => Ok(true),
        _ => bail!("Invalid boolean smoke-test option"),
    }
}

fn write_inventory_report(
    report: &mut CoverageReport,
    path: Option<&Path>,
    require_all: bool,
) -> Result<()> {
    if require_all {
        report.errors.push("full_coverage_not_run");
    }
    write_report(report, path)?;
    println!("Live provider access NOT RUN: report-only mode uses no account configuration.");
    if require_all {
        bail!("Report-only mode cannot satisfy required full live coverage");
    }
    Ok(())
}

fn verify_runtime(path: &Path) -> Result<PathBuf> {
    if !path.is_absolute() || !path.is_file() {
        bail!("An absolute native runtime file path is required");
    }
    let path = path.canonicalize()?;
    let key = if cfg!(windows) {
        "RCLONE_EXE_SHA256="
    } else {
        "RCLONE_LINUX_EXE_SHA256="
    };
    let expected = include_str!("../../rclone-version.env")
        .lines()
        .find_map(|line| line.strip_prefix(key))
        .ok_or_else(|| anyhow::anyhow!("Native runtime hash is missing from the manifest"))?;
    let actual = hex::encode(Sha256::digest(std::fs::read(&path)?));
    if expected != actual {
        bail!("Native runtime hash differs from the manifest");
    }
    Ok(path)
}

#[test]
#[ignore = "requires explicit runtime and test credentials, or explicit report-only mode"]
fn test_configured_provider_remotes_smoke() {
    let binary = std::env::var("RCLONE_PROVIDER_SMOKE_RCLONE")
        .expect("Set RCLONE_PROVIDER_SMOKE_RCLONE to the verified native runtime");
    let binary = verify_runtime(Path::new(&binary))
        .unwrap_or_else(|_| panic!("Native runtime hash verification failed"));
    // Discovery is metadata-only and always uses an empty isolated config.
    let empty = tempfile::NamedTempFile::new().unwrap();
    let metadata_runner = RcloneRunner::new(&binary)
        .with_config(empty.path())
        .with_timeout(Duration::from_secs(30));
    let version = metadata_runner
        .version()
        .unwrap_or_else(|_| panic!("Cannot query runtime version"));
    assert_eq!(
        version,
        format!("rclone v{}", env!("TRIAGE_RCLONE_VERSION")),
        "Runtime differs from the pinned build"
    );
    let mut catalog = providers_from_rclone(&metadata_runner)
        .unwrap_or_else(|_| panic!("Cannot load runtime provider catalog"))
        .providers;
    catalog.sort_by(|a, b| a.id.cmp(&b.id));
    assert!(!catalog.is_empty(), "Runtime catalog is empty");
    assert!(
        catalog.iter().all(|p| !p.id.is_empty()
            && p.id
                .chars()
                .all(|ch| ch.is_ascii_lowercase() || ch.is_ascii_digit() || ch == '_')),
        "Unsafe provider identifier"
    );
    let mut report = CoverageReport::new(&catalog, version);
    let report_path =
        std::env::var_os("RCLONE_PROVIDER_SMOKE_REPORT").map(std::path::PathBuf::from);
    let require_all = env_flag("RCLONE_PROVIDER_SMOKE_REQUIRE_ALL").unwrap();
    if env_flag("RCLONE_PROVIDER_SMOKE_REPORT_ONLY").unwrap() {
        write_inventory_report(&mut report, report_path.as_deref(), require_all).unwrap();
        return;
    }
    let result = (|| -> Result<()> {
        let config_path = std::env::var("RCLONE_PROVIDER_SMOKE_CONFIG")
            .ok()
            .filter(|p| !p.trim().is_empty())
            .ok_or_else(|| anyhow::anyhow!("Explicit smoke configuration required"))?;
        let config = RcloneConfig::open_existing(Path::new(&config_path))?;
        let parsed = config.parse()?;
        let remotes = collect_smoke_remotes(&parsed, &catalog)?;
        let requested = requested_backends(
            &std::env::var("RCLONE_PROVIDER_SMOKE_BACKENDS").unwrap_or_default(),
        )?;
        for row in &mut report.providers {
            row.configured_remotes = remotes.iter().filter(|r| r.backend == row.backend).count();
            if row.configured_remotes > 0 {
                row.status = Status::NotRun;
            }
        }
        let selected = select_smoke_remotes(&remotes, &catalog, &requested)?;
        for row in &mut report.providers {
            if row.configured_remotes > 0 {
                row.status = if selected.iter().any(|r| r.backend == row.backend) {
                    Status::NotRun
                } else {
                    Status::NotRequested
                };
            }
        }
        if selected.is_empty() {
            bail!("No matching Test remotes");
        }
        require_full_selection(&catalog, &selected, require_all)?;
        let runner = RcloneRunner::new(&binary)
            .with_config(config.path())
            .with_timeout(Duration::from_secs(60));
        let available = runner.list_remotes()?;
        for remote in selected {
            let passed = available.iter().any(|name| name == &remote.remote_name)
                && run_shallow_read(&runner, &remote).is_ok();
            report.record(&remote.backend, passed);
        }
        Ok(())
    })();
    // Never publish raw provider errors, remote names, tokens or file names.
    if result.is_err() {
        report.errors.push("configuration_or_selection_failed");
    }
    if report.providers.iter().any(|p| p.status == Status::Failed) {
        report.errors.push("provider_read_failed");
    }
    report.finish();
    write_report(&report, report_path.as_deref()).expect("Cannot save coverage report");
    assert!(report.errors.is_empty(), "Provider access failed; inspect the sanitized coverage report. Raw diagnostics intentionally omitted.");
}

#[cfg(test)]
mod tests {
    use super::*;
    use rclone_triage::providers::CloudProvider;

    fn catalog() -> Vec<ProviderEntry> {
        vec![
            ProviderEntry::from_known(CloudProvider::GoogleDrive),
            ProviderEntry::from_known(CloudProvider::S3),
            ProviderEntry {
                id: "newbackend".into(),
                backend_name: "future cloud storage".into(),
                name: "New backend".into(),
                description: None,
                known: None,
                oauth_capable: false,
                auth_kind: ProviderAuthKind::Unknown,
            },
        ]
    }

    #[test]
    fn discovery_only_backend_is_covered_without_a_curated_enum_variant() {
        let parsed = ParsedConfig::parse("[TestNew]\ntype = newbackend\n[Private]\ntype = drive\n");
        let remotes = collect_smoke_remotes(&parsed, &catalog()).unwrap();
        assert_eq!(
            remotes,
            vec![SmokeRemote {
                backend: "newbackend".into(),
                remote_name: "TestNew".into()
            }]
        );
    }

    #[test]
    fn canonical_names_and_prefixes_select_the_same_discovered_backend() {
        let catalog = catalog();
        for remote_type in ["future cloud storage", "futurecloudstorage", "newbackend"] {
            let parsed = ParsedConfig::parse(&format!("[TestNew]\ntype = {remote_type}\n"));
            let remotes = collect_smoke_remotes(&parsed, &catalog).unwrap();
            assert_eq!(remotes[0].backend, "newbackend");
            for request in ["future cloud storage", "futurecloudstorage", "newbackend"] {
                assert_eq!(
                    select_smoke_remotes(&remotes, &catalog, &requested_backends(request).unwrap())
                        .unwrap()
                        .len(),
                    1
                );
            }
        }
        let oracle = ProviderEntry::from_known(CloudProvider::OracleObjectStorage);
        let parsed = ParsedConfig::parse("[TestOracle]\ntype = oracleobjectstorage\n");
        let remotes = collect_smoke_remotes(&parsed, &[oracle]).unwrap();
        assert_eq!(remotes.len(), 1);
    }

    #[test]
    fn unavailable_test_backend_is_an_error_instead_of_silent_omission() {
        let parsed =
            ParsedConfig::parse("[TestUnknown]\ntype = missing\n[TestDrive]\ntype = drive\n");
        assert!(collect_smoke_remotes(&parsed, &catalog()).is_err());
    }

    #[test]
    fn partially_satisfied_filter_fails() {
        let catalog = catalog();
        let parsed = ParsedConfig::parse("[TestDrive]\ntype = drive\n");
        let remotes = collect_smoke_remotes(&parsed, &catalog).unwrap();
        assert!(
            select_smoke_remotes(&remotes, &catalog, &requested_backends("drive,s3").unwrap())
                .is_err()
        );
        assert!(select_smoke_remotes(
            &remotes,
            &catalog,
            &requested_backends("drive,typo").unwrap()
        )
        .is_err());
        assert_eq!(
            select_smoke_remotes(
                &remotes,
                &catalog,
                &requested_backends("testdrive").unwrap()
            )
            .unwrap()
            .len(),
            1
        );
    }

    #[test]
    fn malformed_filter_cannot_expand_to_every_account() {
        assert!(requested_backends(", ,").is_err());
        assert!(requested_backends("  ").unwrap().is_empty());
        assert_eq!(requested_backends("drive,DRIVE").unwrap().len(), 1);
    }

    #[test]
    fn duplicate_and_case_aliased_test_names_are_rejected() {
        for second in ["TestDrive", "testdrive", "TESTDRIVE"] {
            let parsed = ParsedConfig::parse(&format!(
                "[TestDrive]\ntype = drive\n[{second}]\ntype = drive\n"
            ));
            assert!(collect_smoke_remotes(&parsed, &catalog()).is_err());
        }
    }

    #[test]
    fn bare_or_relative_runtime_cannot_resolve_to_a_different_path_binary() {
        assert!(verify_runtime(Path::new("rclone")).is_err());
        assert!(verify_runtime(Path::new("./rclone")).is_err());
    }

    #[test]
    fn report_only_writes_missing_inventory_but_cannot_satisfy_full_coverage() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("report.json");
        let mut report = CoverageReport::new(&catalog(), "test".into());
        assert!(write_inventory_report(&mut report, Some(&path), true).is_err());
        let saved: serde_json::Value =
            serde_json::from_slice(&std::fs::read(path).unwrap()).unwrap();
        assert_eq!(saved["all_discovered_providers_passed"], false);
        assert_eq!(
            saved["errors"],
            serde_json::json!(["full_coverage_not_run"])
        );
        assert_eq!(
            saved["providers"].as_array().unwrap().len(),
            catalog().len()
        );
        assert!(saved["providers"]
            .as_array()
            .unwrap()
            .iter()
            .all(|row| row["status"] == "not_configured"));
        let mut optional = CoverageReport::new(&catalog(), "test".into());
        assert!(write_inventory_report(&mut optional, None, false).is_ok());
    }

    #[test]
    fn full_coverage_requires_discovery_only_backends_too() {
        let catalog = catalog();
        let parsed = ParsedConfig::parse("[TestDrive]\ntype = drive\n[TestS3]\ntype = s3\n");
        let selected = collect_smoke_remotes(&parsed, &catalog).unwrap();
        assert!(require_full_selection(&catalog, &selected, false).is_ok());
        assert!(require_full_selection(&catalog, &selected, true).is_err());
        let mut complete = selected;
        complete.push(SmokeRemote {
            backend: "newbackend".into(),
            remote_name: "TestNew".into(),
        });
        assert!(require_full_selection(&catalog, &complete, true).is_ok());
    }

    #[test]
    fn reports_missing_providers_and_never_claims_fresh_login_or_refresh() {
        let mut report = CoverageReport::new(&catalog(), "test".into());
        report.record("drive", true);
        report.finish();
        assert!(!report.all_discovered_providers_passed);
        assert!(!report.fresh_login_verified);
        assert!(!report.refresh_grant_verified);
        assert_eq!(
            report
                .providers
                .iter()
                .filter(|p| p.status == Status::NotConfigured)
                .count(),
            2
        );
    }

    #[test]
    fn successful_account_does_not_hide_failure_of_same_backend() {
        let mut report = CoverageReport::new(&catalog(), "test".into());
        report.record("drive", false);
        report.record("drive", true);
        assert_eq!(report.providers[0].status, Status::Failed);
        assert_eq!(report.providers[0].checked_remotes, 2);
    }

    #[test]
    fn report_excludes_config_remote_names_tokens_and_file_names() {
        let catalog = catalog();
        let parsed = ParsedConfig::parse(
            "[TestPrivate_account@example.invalid]\ntype = drive\ntoken = secret-canary\n",
        );
        let remotes = collect_smoke_remotes(&parsed, &catalog).unwrap();
        let mut report = CoverageReport::new(&catalog, "test".into());
        report.record(&remotes[0].backend, false);
        let json = serde_json::to_string(&report).unwrap();
        for secret in ["Private_account", "example.invalid", "secret-canary"] {
            assert!(!json.contains(secret));
        }
    }

    #[test]
    fn report_refuses_to_overwrite_existing_file() {
        let file = tempfile::NamedTempFile::new().unwrap();
        std::fs::write(file.path(), b"preserve").unwrap();
        assert!(write_report(
            &CoverageReport::new(&catalog(), "test".into()),
            Some(file.path())
        )
        .is_err());
        assert_eq!(std::fs::read(file.path()).unwrap(), b"preserve");
    }
}
