//! Provider option schemas from rclone.
//!
//! Uses `rclone config providers` JSON output to build a best-effort schema for
//! manual backend configuration (non-OAuth providers, or when investigators want
//! to configure a backend from scratch).

use anyhow::{bail, Context, Result};
use serde::Deserialize;

use crate::rclone::RcloneRunner;

#[derive(Debug, Clone, Deserialize)]
pub struct ProviderOptionExample {
    #[serde(rename = "Value")]
    pub value: serde_json::Value,
    #[serde(rename = "Help")]
    pub help: Option<String>,
}

#[derive(Debug, Clone, Deserialize)]
pub struct ProviderOptionSchema {
    #[serde(rename = "Name")]
    pub name: String,
    #[serde(rename = "Help")]
    pub help: Option<String>,
    #[serde(rename = "Default")]
    pub default: Option<serde_json::Value>,
    #[serde(rename = "Required", default)]
    pub required: bool,
    #[serde(rename = "IsPassword", default)]
    pub is_password: bool,
    /// Hide level from rclone (0 = show, higher values are "advanced"/hidden).
    #[serde(rename = "Hide", default)]
    pub hide: i64,
    #[serde(rename = "Examples", default)]
    pub examples: Vec<ProviderOptionExample>,
}

impl ProviderOptionSchema {
    pub fn help_text(&self) -> &str {
        self.help.as_deref().unwrap_or("")
    }

    pub fn default_string(&self) -> Option<String> {
        json_value_to_string_opt(self.default.as_ref())
    }

    pub fn examples_as_strings(&self) -> Vec<(String, Option<String>)> {
        self.examples
            .iter()
            .filter_map(|ex| {
                let value = json_value_to_string_opt(Some(&ex.value))?;
                Some((value, ex.help.clone()))
            })
            .collect()
    }
}

#[derive(Debug, Clone, Deserialize)]
pub struct ProviderSchema {
    #[serde(rename = "Name")]
    pub name: Option<String>,
    #[serde(rename = "Description")]
    pub description: Option<String>,
    #[serde(rename = "Prefix")]
    pub prefix: Option<String>,
    #[serde(rename = "Options", default)]
    pub options: Vec<ProviderOptionSchema>,
}

fn json_value_to_string_opt(value: Option<&serde_json::Value>) -> Option<String> {
    let value = value?;
    match value {
        serde_json::Value::Null => None,
        serde_json::Value::String(s) => {
            let trimmed = s.trim();
            if trimmed.is_empty() {
                None
            } else {
                Some(trimmed.to_string())
            }
        }
        other => {
            let text = other.to_string();
            if text == "null" || text.trim().is_empty() {
                None
            } else {
                Some(text)
            }
        }
    }
}

/// Parse rclone provider schemas from JSON (used by tests).
pub fn providers_from_rclone_json(json: &str) -> Result<Vec<ProviderSchema>> {
    serde_json::from_str(json).context("Failed to parse rclone providers JSON")
}

/// Find a schema by canonical backend name, option prefix, or FileName alias.
pub fn provider_schema_from_rclone_json(
    json: &str,
    backend: &str,
) -> Result<Option<ProviderSchema>> {
    let wanted = backend.trim();
    if wanted.is_empty() {
        bail!("Provider name or prefix cannot be empty");
    }

    let providers = providers_from_rclone_json(json)?;
    Ok(providers.into_iter().find(|p| {
        super::backend_matches(
            p.name.as_deref().unwrap_or("").trim(),
            p.prefix.as_deref().unwrap_or("").trim(),
            wanted,
        )
    }))
}

/// Ask rclone for provider schemas and match a backend name or prefix.
pub fn provider_schema_from_rclone(
    runner: &RcloneRunner,
    backend: &str,
) -> Result<Option<ProviderSchema>> {
    let output = runner.run(&["config", "providers"])?;
    if !output.success() {
        bail!("rclone config providers failed: {}", output.stderr_string());
    }

    provider_schema_from_rclone_json(&output.stdout_string(), backend)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn schema_lookup_accepts_backend_name_prefix_and_filename_but_not_display_label() {
        let json = r#"[{"Name":"future storage","Prefix":"fsx",
            "Description":"Friendly product label","Options":[{"Name":"api_key","Required":true}]}]"#;
        for identifier in ["future storage", "fsx", "futurestorage"] {
            let schema = provider_schema_from_rclone_json(json, identifier)
                .unwrap()
                .unwrap();
            assert_eq!(schema.name.as_deref(), Some("future storage"));
            assert_eq!(schema.options[0].name, "api_key");
            assert!(schema.options[0].required);
        }
        assert!(
            provider_schema_from_rclone_json(json, "Friendly product label")
                .unwrap()
                .is_none()
        );
    }

    #[test]
    fn test_provider_schema_parse_and_extract() {
        let json = r#"
[
  {
    "Name": "WebDAV",
    "Description": "WebDAV",
    "Prefix": "webdav",
    "Options": [
      {
        "Name": "url",
        "Help": "URL of the WebDAV endpoint.",
        "Default": "",
        "Required": true,
        "IsPassword": false,
        "Hide": 0,
        "Examples": [{"Value": "https://example.com/remote.php/dav/files/user/", "Help": "Nextcloud"}]
      },
      {
        "Name": "pass",
        "Help": "Password.",
        "Default": null,
        "Required": false,
        "IsPassword": true,
        "Hide": 0,
        "Examples": []
      }
    ]
  }
]
"#;

        let schema = provider_schema_from_rclone_json(json, "webdav")
            .unwrap()
            .expect("schema should exist");
        assert_eq!(schema.prefix.as_deref(), Some("webdav"));
        assert_eq!(schema.options.len(), 2);

        let url = schema.options.iter().find(|o| o.name == "url").unwrap();
        assert!(url.required);
        assert!(!url.is_password);
        assert_eq!(url.default_string(), None);
        let examples = url.examples_as_strings();
        assert_eq!(examples.len(), 1);
        assert_eq!(
            examples[0].0,
            "https://example.com/remote.php/dav/files/user/"
        );

        let pass = schema.options.iter().find(|o| o.name == "pass").unwrap();
        assert!(!pass.required);
        assert!(pass.is_password);
    }
}
