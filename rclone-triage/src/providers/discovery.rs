//! Provider discovery from rclone
//!
//! Uses `rclone config providers --json` output to determine which backends
//! are available, returning both known and unknown providers.

use anyhow::{bail, Context, Result};
use regex::RegexSet;
use serde::Deserialize;
use std::collections::HashSet;
use std::str::FromStr;

use crate::providers::{CloudProvider, ProviderAuthKind, ProviderEntry};
use crate::rclone::RcloneRunner;

#[derive(Debug, Deserialize)]
struct RcloneProvider {
    #[serde(rename = "Name")]
    name: Option<String>,
    #[serde(rename = "Description")]
    description: Option<String>,
    #[serde(rename = "Prefix")]
    prefix: Option<String>,
    #[serde(rename = "Options")]
    options: Option<Vec<serde_json::Value>>,
}

#[derive(Debug, Clone, Default)]
pub struct ProviderDiscoveryStats {
    pub total: usize,
    pub oauth_capable: usize,
    pub non_oauth: usize,
    pub excluded_bad: usize,
    pub excluded_no_prefix: usize,
    pub excluded_duplicates: usize,
}

impl ProviderDiscoveryStats {
    pub fn excluded_total(&self) -> usize {
        self.excluded_bad + self.excluded_no_prefix + self.excluded_duplicates
    }
}

#[derive(Debug, Clone)]
pub struct ProviderDiscoveryResult {
    pub providers: Vec<ProviderEntry>,
    pub stats: ProviderDiscoveryStats,
}

pub(crate) const BAD_PROVIDER_PREFIXES: &[&str] = &[
    "alias", "crypt", "cache", "chunker", "combine", "compress", "ftp", "hasher", "http",
    "local", "memory", "sftp", "smb", "union", "webdav",
];

const OAUTH_PATTERNS: &[&str] = &[
    r"client[_-]?id",
    r"client[_-]?secret",
    r"auth[_-]?url",
    r"token[_-]?url",
    r"oauth",
    r"refresh[_-]?token",
    r"authorization",
    r"app[_-]?id",
    r"consumer[_-]?key",
    r"consumer[_-]?secret",
];

const KEY_PATTERNS: &[&str] = &[
    r"access[_-]?key",
    r"secret[_-]?key",
    r"access[_-]?key[_-]?id",
    r"secret[_-]?access[_-]?key",
    r"api[_-]?key",
    r"private[_-]?key",
    r"service[_-]?account",
    r"account[_-]?key",
];

const USERPASS_PATTERNS: &[&str] = &[
    r"username",
    r"password",
    r"\bpass\b",
    r"passphrase",
];

pub(crate) fn is_bad_provider(prefix: &str, name: Option<&str>) -> bool {
    let prefix = prefix.trim().to_lowercase();
    if BAD_PROVIDER_PREFIXES.contains(&prefix.as_str()) {
        return true;
    }
    let name = name.unwrap_or("").trim().to_lowercase();
    BAD_PROVIDER_PREFIXES.contains(&name.as_str())
}

fn collect_strings(value: &serde_json::Value, output: &mut Vec<String>) {
    match value {
        serde_json::Value::Null => {}
        serde_json::Value::Bool(b) => output.push(b.to_string()),
        serde_json::Value::Number(n) => output.push(n.to_string()),
        serde_json::Value::String(s) => output.push(s.clone()),
        serde_json::Value::Array(items) => {
            for item in items {
                collect_strings(item, output);
            }
        }
        serde_json::Value::Object(map) => {
            for (key, value) in map {
                output.push(key.clone());
                collect_strings(value, output);
            }
        }
    }
}

fn detect_auth_kind(options: Option<&Vec<serde_json::Value>>) -> ProviderAuthKind {
    let Some(options) = options else {
        return ProviderAuthKind::Unknown;
    };

    let oauth_patterns = match RegexSet::new(OAUTH_PATTERNS) {
        Ok(set) => set,
        Err(_) => return ProviderAuthKind::Unknown,
    };
    let key_patterns = match RegexSet::new(KEY_PATTERNS) {
        Ok(set) => set,
        Err(_) => return ProviderAuthKind::Unknown,
    };
    let userpass_patterns = match RegexSet::new(USERPASS_PATTERNS) {
        Ok(set) => set,
        Err(_) => return ProviderAuthKind::Unknown,
    };

    let mut tokens = Vec::new();
    for option in options {
        collect_strings(option, &mut tokens);
    }

    let tokens = tokens
        .into_iter()
        .map(|token| token.to_lowercase())
        .collect::<Vec<_>>();

    if tokens.iter().any(|token| oauth_patterns.is_match(token)) {
        return ProviderAuthKind::OAuth;
    }
    if tokens.iter().any(|token| key_patterns.is_match(token)) {
        return ProviderAuthKind::KeyBased;
    }
    if tokens.iter().any(|token| userpass_patterns.is_match(token)) {
        return ProviderAuthKind::UserPass;
    }

    ProviderAuthKind::Unknown
}

/// Parse rclone providers JSON and return provider entries with discovery stats.
pub fn providers_from_rclone_json(json: &str) -> Result<ProviderDiscoveryResult> {
    let providers: Vec<RcloneProvider> =
        serde_json::from_str(json).context("Failed to parse rclone providers JSON")?;

    let mut entries = Vec::new();
    let mut seen = HashSet::new();
    let mut stats = ProviderDiscoveryStats {
        total: providers.len(),
        ..Default::default()
    };

    for provider in providers {
        let prefix = provider
            .prefix
            .map(|s| s.trim().to_lowercase())
            .filter(|s| !s.is_empty());
        let name = provider
            .name
            .map(|s| s.trim().to_string())
            .filter(|s| !s.is_empty());
        let description = provider
            .description
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
            stats.excluded_duplicates += 1;
            continue;
        }

        if id == "unknown" {
            stats.excluded_no_prefix += 1;
            continue;
        }

        if is_bad_provider(&id, name.as_deref()) {
            stats.excluded_bad += 1;
            continue;
        }

        let auth_kind = detect_auth_kind(provider.options.as_ref());
        let oauth_capable = auth_kind == ProviderAuthKind::OAuth;
        if oauth_capable {
            stats.oauth_capable += 1;
        } else {
            stats.non_oauth += 1;
        }

        let known = CloudProvider::from_str(&id).ok();
        let display = if let Some(desc) = description.clone() {
            desc
        } else if let Some(name) = name.clone() {
            name
        } else if let Some(p) = known {
            p.display_name().to_string()
        } else {
            id.clone()
        };

        let description = description.filter(|desc| desc.trim() != display);

        entries.push(ProviderEntry {
            id,
            name: display,
            description,
            known,
            oauth_capable,
            auth_kind,
        });
    }

    Ok(ProviderDiscoveryResult {
        providers: entries,
        stats,
    })
}

/// Ask rclone for providers and return the full list.
pub fn providers_from_rclone(runner: &RcloneRunner) -> Result<ProviderDiscoveryResult> {
    let output = runner.run(&["config", "providers"])?;
    if !output.success() {
        bail!(
            "rclone config providers failed: {}",
            output.stderr_string()
        );
    }

    let stdout = output.stdout_string();
    providers_from_rclone_json(&stdout)
        .with_context(|| "rclone config providers did not return JSON output")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_supported_providers_from_rclone_json() {
        let json = r#"
        [
          {"Name":"Google Drive","Prefix":"drive","Options":[{"Name":"client_id"}]},
          {"Name":"Microsoft OneDrive","Prefix":"onedrive","Options":[{"Name":"client-id"}]},
          {"Name":"Dropbox","Prefix":"dropbox","Options":[{"Name":"auth_url"}]},
          {"Name":"Box","Prefix":"box","Options":[{"Name":"token_url"}]},
          {"Name":"iCloud Drive","Prefix":"iclouddrive","Options":[{"Name":"username"}]},
          {"Name":"pCloud","Prefix":"pcloud","Options":[{"Name":"client_secret"}]},
          {"Name":"Google Photos","Prefix":"gphotos","Options":[{"Name":"oauth"}]}
        ]
        "#;

        let result = providers_from_rclone_json(json).unwrap();
        let entries = result.providers;
        assert!(entries.iter().any(|p| p.id == "drive"));
        assert!(entries.iter().any(|p| p.id == "onedrive"));
        assert!(entries.iter().any(|p| p.id == "dropbox"));
        assert!(entries.iter().any(|p| p.id == "box"));
        assert!(entries.iter().any(|p| p.id == "iclouddrive"));
        assert!(entries.iter().any(|p| p.id == "pcloud"));
        assert!(entries.iter().any(|p| p.id == "gphotos"));
        assert_eq!(result.stats.total, 7);
        assert_eq!(result.stats.oauth_capable, 6);
        assert_eq!(result.stats.non_oauth, 1);
    }

    #[test]
    fn test_providers_from_rclone_json_filters_bad_and_non_oauth() {
        let json = r#"
        [
          {"Name":"Google Drive","Prefix":"drive","Options":[{"Name":"client_id"}]},
          {"Name":"Local","Prefix":"local","Options":[{"Name":"root"}]},
          {"Name":"Amazon S3","Prefix":"s3","Options":[{"Name":"access_key_id"}]},
          {"Name":"FTP","Prefix":"ftp","Options":[{"Name":"host"}]},
          {"Name":"Mystery","Prefix":"mystery","Options":[{"Name":"something"}]}
        ]
        "#;

        let result = providers_from_rclone_json(json).unwrap();
        let entries = result.providers;
        assert!(entries.iter().any(|p| p.id == "drive"));
        assert!(entries.iter().any(|p| p.id == "s3"));
        assert!(!entries.iter().any(|p| p.id == "local"));
        assert!(!entries.iter().any(|p| p.id == "ftp"));
        assert!(entries.iter().any(|p| p.id == "mystery"));
        assert_eq!(result.stats.total, 5);
        assert_eq!(result.stats.excluded_bad, 2);
        assert_eq!(result.stats.non_oauth, 2);
    }
}
