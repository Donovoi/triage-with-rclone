use std::collections::HashSet;
use std::path::PathBuf;

use anyhow::{bail, Context, Result};
use rclone_triage::providers::CloudProvider;
use rclone_triage::rclone::{test_connectivity, ParsedConfig, RcloneConfig, RcloneRunner};

#[derive(Debug, Clone, PartialEq, Eq)]
struct SmokeRemote {
    provider: CloudProvider,
    remote_name: String,
}

fn smoke_rclone_binary() -> PathBuf {
    std::env::var("RCLONE_PROVIDER_SMOKE_RCLONE")
        .ok()
        .map(|value| PathBuf::from(value.trim()))
        .filter(|path| !path.as_os_str().is_empty())
        .unwrap_or_else(|| PathBuf::from("rclone"))
}

fn resolve_smoke_config_path() -> Option<PathBuf> {
    for env_name in ["RCLONE_PROVIDER_SMOKE_CONFIG", "RCLONE_CONFIG"] {
        if let Ok(path) = std::env::var(env_name) {
            let trimmed = path.trim();
            if !trimmed.is_empty() {
                let path = PathBuf::from(trimmed);
                if path.exists() {
                    return Some(path);
                }
            }
        }
    }

    dirs::config_dir().and_then(|config_dir| {
        let path = config_dir.join("rclone").join("rclone.conf");
        path.exists().then_some(path)
    })
}

fn requested_backends() -> Option<HashSet<String>> {
    let raw = std::env::var("RCLONE_PROVIDER_SMOKE_BACKENDS").ok()?;
    let requested = raw
        .split(',')
        .map(|value| value.trim().to_ascii_lowercase())
        .filter(|value| !value.is_empty())
        .collect::<HashSet<_>>();

    if requested.is_empty() {
        None
    } else {
        Some(requested)
    }
}

fn matches_requested_backends(
    provider: CloudProvider,
    remote_name: &str,
    requested: Option<&HashSet<String>>,
) -> bool {
    let Some(requested) = requested else {
        return true;
    };

    let remote_name = remote_name.to_ascii_lowercase();
    requested.contains(&remote_name)
        || requested.contains(provider.rclone_type())
        || requested.contains(provider.short_name())
}

fn collect_smoke_remotes(
    parsed: &ParsedConfig,
    requested: Option<&HashSet<String>>,
) -> Vec<SmokeRemote> {
    let mut remotes = parsed
        .remotes
        .iter()
        .filter(|remote| remote.name.starts_with("Test"))
        .filter_map(|remote| {
            let provider = remote.remote_type.parse::<CloudProvider>().ok()?;
            if !matches_requested_backends(provider, &remote.name, requested) {
                return None;
            }

            Some(SmokeRemote {
                provider,
                remote_name: remote.name.clone(),
            })
        })
        .collect::<Vec<_>>();

    remotes.sort_by(|left, right| {
        left.provider
            .display_name()
            .cmp(right.provider.display_name())
            .then_with(|| left.remote_name.cmp(&right.remote_name))
    });
    remotes
}

fn run_top_level_lsjson_smoke(
    runner: &RcloneRunner,
    remote_name: &str,
    include_hashes: bool,
) -> Result<()> {
    let mut args = vec![
        "lsjson".to_string(),
        "--max-depth".to_string(),
        "1".to_string(),
        "-v".to_string(),
    ];
    if include_hashes {
        args.push("--hash".to_string());
    }
    args.push(format!("{}:", remote_name));

    let args_ref = args.iter().map(String::as_str).collect::<Vec<_>>();
    let output = runner.run(&args_ref)?;
    if !output.success() {
        bail!(
            "top-level lsjson smoke failed for {}: {}",
            remote_name,
            output.stderr_string()
        );
    }

    let payload: serde_json::Value = serde_json::from_str(&output.stdout_string())
        .with_context(|| format!("{} did not return valid lsjson", remote_name))?;
    if !payload.is_array() {
        bail!("{} lsjson output was not a JSON array", remote_name);
    }

    Ok(())
}

#[test]
fn test_collect_smoke_remotes_only_uses_test_remotes_and_known_types() {
    let parsed = ParsedConfig::parse(
        r#"
[TestDrive]
type = drive

[DriveForensics]
type = drive

[TestMystery]
type = mystery

[TestS3]
type = s3
"#,
    );

    let remotes = collect_smoke_remotes(&parsed, None);
    assert_eq!(
        remotes,
        vec![
            SmokeRemote {
                provider: CloudProvider::GoogleDrive,
                remote_name: "TestDrive".to_string(),
            },
            SmokeRemote {
                provider: CloudProvider::S3,
                remote_name: "TestS3".to_string(),
            },
        ]
    );
}

#[test]
fn test_collect_smoke_remotes_respects_requested_backends() {
    let parsed = ParsedConfig::parse(
        r#"
[TestDrive]
type = drive

[TestS3]
type = s3

[TestSftp]
type = sftp
"#,
    );

    let requested = HashSet::from(["s3".to_string(), "testsftp".to_string()]);
    let remotes = collect_smoke_remotes(&parsed, Some(&requested));

    assert_eq!(
        remotes,
        vec![
            SmokeRemote {
                provider: CloudProvider::S3,
                remote_name: "TestS3".to_string(),
            },
            SmokeRemote {
                provider: CloudProvider::Sftp,
                remote_name: "TestSftp".to_string(),
            },
        ]
    );
}

#[test]
fn test_configured_provider_remotes_smoke() {
    let Some(config_path) = resolve_smoke_config_path() else {
        eprintln!(
            "Skipping live provider smoke test: set RCLONE_PROVIDER_SMOKE_CONFIG or create Test* remotes in your rclone config."
        );
        return;
    };

    let config = match RcloneConfig::open_existing(&config_path) {
        Ok(config) => config,
        Err(error) => {
            eprintln!(
                "Skipping live provider smoke test: failed to open config {:?}: {}",
                config_path, error
            );
            return;
        }
    };

    let runner = RcloneRunner::new(smoke_rclone_binary()).with_config(config.path());
    if let Err(error) = runner.version() {
        eprintln!(
            "Skipping live provider smoke test: rclone is unavailable or failed to start: {}",
            error
        );
        return;
    }

    let parsed = config.parse().expect("provider smoke config should parse");
    let requested = requested_backends();
    let remotes = collect_smoke_remotes(&parsed, requested.as_ref());
    if remotes.is_empty() {
        eprintln!(
            "Skipping live provider smoke test: no matching Test* remotes were found in {:?}.",
            config.path()
        );
        return;
    }

    let available_remotes = runner
        .list_remotes()
        .expect("rclone listremotes should succeed for smoke config");

    for remote in remotes {
        assert!(
            available_remotes
                .iter()
                .any(|name| name == &remote.remote_name),
            "{} should appear in rclone listremotes",
            remote.remote_name
        );

        let connectivity = test_connectivity(&runner, &remote.remote_name)
            .expect("connectivity check should run for configured smoke remote");
        assert!(
            connectivity.ok,
            "Connectivity failed for {} ({}): {}",
            remote.provider.display_name(),
            remote.remote_name,
            connectivity.error.as_deref().unwrap_or("unknown error")
        );

        run_top_level_lsjson_smoke(
            &runner,
            &remote.remote_name,
            !remote.provider.hash_types().is_empty(),
        )
        .unwrap_or_else(|error| {
            panic!(
                "Top-level lsjson smoke failed for {} ({}): {:#}",
                remote.provider.display_name(),
                remote.remote_name,
                error
            )
        });
    }
}
