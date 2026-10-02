//! Combine remote management
//!
//! Creates and manages rclone `combine` remotes that merge multiple upstream
//! remotes under a single namespace.  Each upstream appears as a named
//! top-level directory, making it easy to identify which remote a file
//! belongs to.

use anyhow::{Context, Result};

use super::config::RcloneConfig;

/// Internal name for the auto-generated combine remote.
pub const COMBINE_REMOTE_NAME: &str = "_triage_combined";

/// Build the `upstreams` value for a combine remote.
///
/// Each upstream is formatted as `name=name:` so the directory name matches
/// the rclone remote name, e.g. `gdrive=gdrive: onedrive=onedrive:`.
pub fn build_upstreams_value(remote_names: &[String]) -> String {
    remote_names
        .iter()
        .map(|name| {
            let clean = name.trim_end_matches(':');
            format!("\"{}\"", format!("{clean}={clean}:").replace('"', "\"\""))
        })
        .collect::<Vec<_>>()
        .join(" ")
}

/// Create (or overwrite) a combine remote in the given config, merging the
/// specified upstream remotes.
///
/// Returns the combine remote name (always [`COMBINE_REMOTE_NAME`]).
pub fn create_combine_remote(config: &RcloneConfig, remote_names: &[String]) -> Result<String> {
    let upstreams = build_upstreams_value(remote_names);
    let existing = config.parse()?;
    let mut name = COMBINE_REMOTE_NAME.to_string();
    let mut suffix = 1;
    while existing.remotes.iter().any(|remote| remote.name == name) {
        name = format!("{COMBINE_REMOTE_NAME}_{suffix}");
        suffix += 1;
    }

    config
        .set_remote(&name, "combine", &[("upstreams", &upstreams)])
        .with_context(|| "Failed to write combine remote to rclone config")?;

    Ok(name)
}

/// Remove the auto-generated combine remote from the config (cleanup).
pub fn remove_combine_remote(config: &RcloneConfig) -> Result<()> {
    config
        .remove_remote(COMBINE_REMOTE_NAME)
        .with_context(|| "Failed to remove combine remote from rclone config")
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::tempdir;

    #[test]
    fn test_build_upstreams_value() {
        let names = vec!["gdrive".to_string(), "onedrive".to_string()];
        assert_eq!(
            build_upstreams_value(&names),
            "\"gdrive=gdrive:\" \"onedrive=onedrive:\""
        );
    }

    #[test]
    fn test_build_upstreams_value_single() {
        let names = vec!["dropbox".to_string()];
        assert_eq!(build_upstreams_value(&names), "\"dropbox=dropbox:\"");
    }

    #[test]
    fn quoted_space_names_and_existing_remote_are_preserved() {
        assert_eq!(
            build_upstreams_value(&["My Drive".into()]),
            "\"My Drive=My Drive:\""
        );
        let temp = tempdir().unwrap();
        let path = temp.path().join("rclone.conf");
        std::fs::write(
            &path,
            "[_triage_combined]\ntype = alias\nremote = original:\n\n[My Drive]\ntype = local\n",
        )
        .unwrap();
        let config = RcloneConfig::open_existing(&path).unwrap();
        let name = create_combine_remote(&config, &["My Drive".into()]).unwrap();
        assert_eq!(name, "_triage_combined_1");
        let text = std::fs::read_to_string(&path).unwrap();
        assert!(text.contains("remote = original:"));
    }

    #[test]
    fn test_build_upstreams_strips_colon() {
        let names = vec!["gdrive:".to_string()];
        assert_eq!(build_upstreams_value(&names), "\"gdrive=gdrive:\"");
    }

    #[test]
    fn test_create_and_remove_combine_remote() {
        let dir = tempdir().unwrap();
        let config_path = dir.path().join("rclone.conf");
        std::fs::write(
            &config_path,
            "[gdrive]\ntype = drive\n\n[onedrive]\ntype = onedrive\n",
        )
        .unwrap();
        let config = RcloneConfig::open_existing(&config_path).unwrap();

        let name = create_combine_remote(&config, &["gdrive".to_string(), "onedrive".to_string()])
            .unwrap();
        assert_eq!(name, COMBINE_REMOTE_NAME);

        let content = std::fs::read_to_string(&config_path).unwrap();
        assert!(content.contains("[_triage_combined]"));
        assert!(content.contains("type = combine"));
        assert!(content.contains("upstreams = \"gdrive=gdrive:\" \"onedrive=onedrive:\""));

        remove_combine_remote(&config).unwrap();
        let content = std::fs::read_to_string(&config_path).unwrap();
        assert!(!content.contains("[_triage_combined]"));
    }
}
