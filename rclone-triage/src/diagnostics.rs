//! Conservative redaction for support bundles. Unknown settings are private by default.

const REDACTED: &str = "<REDACTED>";

/// Environment secrets must be removed before diagnostic staging files are created.
pub fn redact_environment_value(name: &str, value: &str) -> String {
    match name.to_ascii_uppercase().as_str() {
        "PATH" | "HOME" | "USER" | "SHELL" | "LANG" | "TERM" => value.to_owned(),
        _ => REDACTED.to_owned(),
    }
}

fn public_setting(name: &str) -> bool {
    matches!(
        name.trim().to_ascii_lowercase().as_str(),
        "type"
            | "scope"
            | "region"
            | "provider"
            | "version"
            | "os"
            | "arch"
            | "chunk_size"
            | "upload_cutoff"
            | "drive_type"
            | "team_drive"
    )
}

fn redact_json(value: &mut serde_json::Value) {
    match value {
        serde_json::Value::Object(fields) => {
            for (key, value) in fields {
                if value.is_object() || value.is_array() {
                    redact_json(value);
                } else if !public_setting(key) {
                    *value = serde_json::Value::String(REDACTED.to_owned());
                }
            }
        }
        serde_json::Value::Array(values) => {
            for value in values {
                if value.is_object() || value.is_array() {
                    redact_json(value);
                } else {
                    *value = serde_json::Value::String(REDACTED.to_owned());
                }
            }
        }
        _ => *value = serde_json::Value::String(REDACTED.to_owned()),
    }
}

/// Redact structured configuration and recognizable sensitive diagnostic lines.
/// This is intentionally conservative; it is not a guarantee that arbitrary prose
/// contains no private data. Support bundles still require user review before sharing.
pub fn redact_text(content: &str) -> String {
    if let Ok(mut value) = serde_json::from_str::<serde_json::Value>(content) {
        redact_json(&mut value);
        return serde_json::to_string_pretty(&value).unwrap_or_else(|_| REDACTED.to_owned());
    }
    content
        .lines()
        .map(|line| {
            if let Ok(mut value) = serde_json::from_str::<serde_json::Value>(line) {
                redact_json(&mut value);
                return serde_json::to_string(&value).unwrap_or_else(|_| REDACTED.to_owned());
            }
            let trimmed = line.trim();
            if trimmed.starts_with('[') && trimmed.ends_with(']') {
                return line.to_owned();
            }
            if let Some((name, value)) = line.split_once('=') {
                return format!(
                    "{}= {}",
                    name.trim_end(),
                    if public_setting(name) {
                        value.trim()
                    } else {
                        REDACTED
                    }
                );
            }
            let lower = line.to_ascii_lowercase();
            if [
                "token",
                "secret",
                "password",
                "credential",
                "authorization",
                "bearer ",
                "cookie",
                "private_key",
                "access_key",
                "code=",
                "state=",
            ]
            .iter()
            .any(|needle| lower.contains(needle))
            {
                REDACTED.to_owned()
            } else {
                line.to_owned()
            }
        })
        .collect::<Vec<_>>()
        .join("\n")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn secrets_never_enter_diagnostic_output() {
        for key in [
            "RCLONE_CONFIG_PASS",
            "RCLONE_CONFIG_REMOTE_TOKEN",
            "RCLONE_S3_SECRET_ACCESS_KEY",
            "NEW_PROVIDER_SECRET",
        ] {
            assert_eq!(redact_environment_value(key, "canary-secret"), REDACTED);
        }
        let input = "[remote]\ntype = s3\nsecret_access_key = canary-secret\nunknown_backend_option = canary-secret\nAuthorization: Bearer canary-secret\n";
        let redacted = redact_text(input);
        assert!(!redacted.contains("canary-secret"));
        assert!(redacted.contains("type= s3"));
        assert!(redacted.contains("[remote]"));
    }

    #[test]
    fn json_credentials_and_unrecognized_values_are_redacted() {
        let output = redact_text(
            r#"{"client_secret":"canary-secret","provider":{"type":"drive","new_credential":"canary-secret"},"credentials":["canary-secret"]}"#,
        );
        assert!(!output.contains("canary-secret"));
        assert!(output.contains("drive"));
        let lines = "{\"message\":\"canary-secret\"}\n{\"new_backend_field\":\"canary-secret\"}";
        assert!(!redact_text(lines).contains("canary-secret"));
    }
}
