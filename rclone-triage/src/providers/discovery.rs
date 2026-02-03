//! Provider discovery from rclone
//!
//! Uses `rclone config providers --json` output to determine which backends
//! are available, then filters to supported CloudProvider variants.

use anyhow::{Context, Result};
use serde::Deserialize;
use std::collections::HashSet;

use crate::providers::CloudProvider;
use crate::rclone::RcloneRunner;

#[derive(Debug, Deserialize)]
struct RcloneProvider {
    #[serde(rename = "Name")]
    name: Option<String>,
    #[serde(rename = "Prefix")]
    prefix: Option<String>,
}

/// Parse rclone providers JSON and return supported providers.
pub fn supported_providers_from_rclone_json(json: &str) -> Result<Vec<CloudProvider>> {
    let providers: Vec<RcloneProvider> =
        serde_json::from_str(json).context("Failed to parse rclone providers JSON")?;

    let prefixes: HashSet<String> = providers
        .into_iter()
        .filter_map(|p| p.prefix.or(p.name))
        .map(|s| s.trim().to_lowercase())
        .collect();

    let supported = CloudProvider::all()
        .iter()
        .copied()
        .filter(|p| prefixes.contains(p.rclone_type()))
        .collect::<Vec<_>>();

    Ok(supported)
}

/// Ask rclone for providers and return the supported subset.
pub fn supported_providers_from_rclone(runner: &RcloneRunner) -> Result<Vec<CloudProvider>> {
    let output = runner.run(&["config", "providers", "--json"])?;
    if !output.success() {
        anyhow::bail!("rclone config providers failed: {}", output.stderr_string());
    }
    supported_providers_from_rclone_json(&output.stdout_string())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_supported_providers_from_rclone_json() {
        let json = r#"
        [
          {"Name":"Google Drive","Prefix":"drive"},
          {"Name":"Microsoft OneDrive","Prefix":"onedrive"},
          {"Name":"Dropbox","Prefix":"dropbox"},
          {"Name":"Box","Prefix":"box"},
          {"Name":"iCloud Drive","Prefix":"iclouddrive"},
          {"Name":"pCloud","Prefix":"pcloud"}
        ]
        "#;

        let supported = supported_providers_from_rclone_json(json).unwrap();
        assert!(supported.contains(&CloudProvider::GoogleDrive));
        assert!(supported.contains(&CloudProvider::OneDrive));
        assert!(supported.contains(&CloudProvider::Dropbox));
        assert!(supported.contains(&CloudProvider::Box));
        assert!(supported.contains(&CloudProvider::ICloud));
        // pcloud is not supported yet
        assert_eq!(supported.len(), 5);
    }
}
