//! Provider discovery from rclone
//!
//! Uses `rclone config providers --json` output to determine which backends
//! are available, returning both known and unknown providers.

use anyhow::{Context, Result};
use serde::Deserialize;
use std::collections::HashSet;
use std::str::FromStr;

use crate::providers::{CloudProvider, ProviderEntry};
use crate::rclone::RcloneRunner;

#[derive(Debug, Deserialize)]
struct RcloneProvider {
    #[serde(rename = "Name")]
    name: Option<String>,
    #[serde(rename = "Prefix")]
    prefix: Option<String>,
}

/// Parse rclone providers JSON and return provider entries.
pub fn providers_from_rclone_json(json: &str) -> Result<Vec<ProviderEntry>> {
    let providers: Vec<RcloneProvider> =
        serde_json::from_str(json).context("Failed to parse rclone providers JSON")?;

    let mut entries = Vec::new();
    let mut seen = HashSet::new();

    for provider in providers {
        let prefix = provider
            .prefix
            .map(|s| s.trim().to_lowercase())
            .filter(|s| !s.is_empty());
        let name = provider
            .name
            .map(|s| s.trim().to_string())
            .filter(|s| !s.is_empty());

        let id = match prefix {
            Some(p) => p,
            None => name
                .as_ref()
                .map(|n| n.to_lowercase())
                .unwrap_or_else(|| "unknown".to_string()),
        };

        if !seen.insert(id.clone()) {
            continue;
        }

        let known = CloudProvider::from_str(&id).ok();
        let display = if let Some(name) = name.clone() {
            name
        } else if let Some(p) = known {
            p.display_name().to_string()
        } else {
            id.clone()
        };

        entries.push(ProviderEntry {
            id,
            name: display,
            known,
        });
    }

    Ok(entries)
}

/// Ask rclone for providers and return the full list.
pub fn providers_from_rclone(runner: &RcloneRunner) -> Result<Vec<ProviderEntry>> {
    let output = runner.run(&["config", "providers", "--json"])?;
    if !output.success() {
        anyhow::bail!("rclone config providers failed: {}", output.stderr_string());
    }
    providers_from_rclone_json(&output.stdout_string())
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
          {"Name":"pCloud","Prefix":"pcloud"},
          {"Name":"Google Photos","Prefix":"gphotos"}
        ]
        "#;

        let entries = providers_from_rclone_json(json).unwrap();
        assert!(entries.iter().any(|p| p.id == "drive"));
        assert!(entries.iter().any(|p| p.id == "onedrive"));
        assert!(entries.iter().any(|p| p.id == "dropbox"));
        assert!(entries.iter().any(|p| p.id == "box"));
        assert!(entries.iter().any(|p| p.id == "iclouddrive"));
        assert!(entries.iter().any(|p| p.id == "pcloud"));
        assert!(entries.iter().any(|p| p.id == "gphotos"));
    }
}
