use anyhow::{bail, Result};
use ratatui::Terminal;

use crate::ui::prompt::prompt_text_in_tui;
use crate::ui::render::render_state;
use crate::ui::App;

fn should_obscure_option_key(key: &str) -> bool {
    let key = key.trim().to_ascii_lowercase();
    matches!(key.as_str(), "pass" | "password")
        || key.ends_with("_pass")
        || key.ends_with("_password")
}

fn obscure_with_rclone(rclone: &crate::rclone::RcloneRunner, value: &str) -> Result<String> {
    let output = rclone.run(&["obscure", value])?;
    if !output.success() {
        bail!("rclone obscure failed: {}", output.stderr_string());
    }
    output
        .stdout
        .iter()
        .find_map(|line| {
            let trimmed = line.trim();
            if trimmed.is_empty() {
                None
            } else {
                Some(trimmed.to_string())
            }
        })
        .ok_or_else(|| anyhow::anyhow!("rclone obscure returned no output"))
}

fn format_option_value_hint(
    key: &str,
    schema: Option<&crate::providers::schema::ProviderOptionSchema>,
) -> String {
    let mut lines = Vec::new();
    lines.push(format!("Enter value for '{}'.", key));

    if let Some(schema) = schema {
        let help = schema.help_text().trim();
        if !help.is_empty() {
            lines.push(String::new());
            lines.push(help.to_string());
        }

        if let Some(default) = schema.default_string() {
            lines.push(String::new());
            lines.push(format!("Default: {}", default));
        }

        let examples = schema.examples_as_strings();
        if !examples.is_empty() {
            lines.push(String::new());
            lines.push("Examples:".to_string());
            for (idx, (value, help)) in examples.into_iter().take(4).enumerate() {
                let suffix = help
                    .as_deref()
                    .map(|h| format!(" ({})", h))
                    .unwrap_or_default();
                lines.push(format!("{}. {}{}", idx + 1, value, suffix));
            }
        }
    }

    lines.push(String::new());
    lines.push(
        "Password fields will be obscured for rclone. Prefix with 'raw:' to use the value as-is."
            .to_string(),
    );
    lines.push(String::new());
    lines.push("Enter submit | Esc cancel".to_string());

    lines.join("\n")
}

fn format_option_key_hint(known_keys_preview: Option<&str>) -> String {
    let mut lines = Vec::new();
    lines.push("Enter an option key (blank to finish).".to_string());
    lines.push(String::new());
    lines.push("Example: access_key_id".to_string());

    if let Some(preview) = known_keys_preview {
        if !preview.trim().is_empty() {
            lines.push(String::new());
            lines.push(format!("Known keys: {}", preview));
        }
    }

    lines.push(String::new());
    lines.push("Enter submit | Esc cancel".to_string());
    lines.join("\n")
}

fn write_manual_remote(
    config: &crate::rclone::RcloneConfig,
    provider: &crate::providers::ProviderEntry,
    remote_name: &str,
    options: &[(&str, &str)],
) -> Result<()> {
    config.set_remote(remote_name, provider.backend_name(), options)
}

/// Configure a backend that doesn't use OAuth by prompting for config options.
///
/// This is best-effort. It writes a remote section to the case's rclone config and then
/// attempts connectivity + listing so the investigator can see files quickly.
pub(crate) fn perform_manual_config_flow<
    B: ratatui::backend::Backend<Error: std::error::Error + Send + Sync + 'static>,
>(
    app: &mut App,
    terminal: &mut Terminal<B>,
) -> Result<()> {
    let Some(provider) = app.provider.chosen.clone() else {
        app.auth_status = "No provider selected.".to_string();
        return Ok(());
    };

    app.auth_status = format!(
        "Manual backend configuration\n\nProvider: {}\nBackend: {}\n\nTip: You can copy an existing rclone config into the case directory, or refer to rclone docs for this backend.\n\nPassword fields (pass/password) will be obscured for rclone. Prefix the value with 'raw:' to skip obscuring.",
        provider.display_name(),
        provider.backend_name(),
    );
    terminal.draw(|f| render_state(f, app))?;

    let binary = match crate::embedded::ExtractedBinary::extract() {
        Ok(binary) => binary,
        Err(e) => {
            app.auth_status = format!("Manual config failed (extract): {}", e);
            app.log_error(format!("Manual config failed (extract): {}", e));
            return Ok(());
        }
    };
    app.cleanup_track_file(binary.path());
    if let Some(dir) = binary.temp_dir() {
        app.cleanup_track_dir(dir);
    }

    let rclone = crate::rclone::RcloneRunner::new(binary.path());

    let config_dir = app
        .config_dir()
        .unwrap_or_else(|| std::path::PathBuf::from("."));
    app.track_env_var(
        "RCLONE_CONFIG",
        "Set RCLONE_CONFIG for manual backend config",
    );
    let config = match crate::rclone::RcloneConfig::for_case(&config_dir) {
        Ok(config) => config,
        Err(e) => {
            app.auth_status = format!("Manual config failed (config): {}", e);
            app.log_error(format!("Manual config failed (config): {}", e));
            return Ok(());
        }
    };
    app.cleanup_track_env_value("RCLONE_CONFIG", config.original_env());
    app.track_file(config.path(), "Created/updated rclone config file");

    let default_remote = match config.next_available_remote_name(provider.short_name()) {
        Ok(name) => name,
        Err(e) => {
            app.auth_status = format!("Manual config failed (remote name): {}", e);
            app.log_error(format!("Manual config failed (remote name): {}", e));
            return Ok(());
        }
    };

    let Some(remote_name_input) = prompt_text_in_tui(
        app,
        terminal,
        "Remote Name",
        &format!(
            "Enter remote name.\n\nDefault: {}\n\nEnter submit | Esc cancel",
            default_remote
        ),
    )?
    else {
        app.auth_status = "Manual configuration cancelled.".to_string();
        app.state = crate::ui::AppState::ProviderSelect;
        return Ok(());
    };

    let remote_name = if remote_name_input.trim().is_empty() {
        default_remote
    } else {
        remote_name_input.trim().to_string()
    };

    let mut options: Vec<(String, String)> = Vec::new();

    let schema = match crate::providers::schema::provider_schema_from_rclone(
        &rclone,
        provider.backend_name(),
    ) {
        Ok(schema) => schema,
        Err(e) => {
            app.log_info(format!(
                "Provider option schema unavailable for {}: {}",
                provider.short_name(),
                e
            ));
            None
        }
    };

    let known_keys_preview = schema.as_ref().map(|schema| {
        let mut keys = schema
            .options
            .iter()
            .filter(|o| o.required || o.hide <= 0)
            .map(|o| o.name.clone())
            .collect::<Vec<_>>();
        keys.sort_by_key(|a| a.to_ascii_lowercase());
        let max = 12usize;
        let mut preview = keys.into_iter().take(max).collect::<Vec<_>>().join(", ");
        if schema.options.len() > max {
            preview.push_str(", ...");
        }
        preview
    });

    // Prompt required options from schema first (best-effort "plug and play" for non-OAuth backends).
    if let Some(schema) = schema.as_ref() {
        let required = schema
            .options
            .iter()
            .filter(|o| o.required)
            .collect::<Vec<_>>();

        if required.is_empty() {
            app.log_info(format!(
                "Provider {} has no required options; falling back to free-form option entry.",
                provider.short_name()
            ));
        } else {
            for opt in required {
                loop {
                    let default = opt.default_string();
                    let blank_behavior = match default.as_deref() {
                        Some(d) if !d.is_empty() => format!("Blank uses default: {}", d),
                        _ => "Blank is not allowed for required options.".to_string(),
                    };

                    let hint = format!(
                        "Required option: {}\n\n{}\n\n{}\n\nEnter submit | Esc cancel",
                        opt.name,
                        opt.help_text(),
                        blank_behavior
                    );

                    let Some(mut value) =
                        prompt_text_in_tui(app, terminal, "Required Option", &hint)?
                    else {
                        app.auth_status = "Manual configuration cancelled.".to_string();
                        app.state = crate::ui::AppState::ProviderSelect;
                        return Ok(());
                    };

                    if value.trim().is_empty() {
                        if let Some(d) = default.as_deref() {
                            if !d.is_empty() {
                                value = d.to_string();
                            }
                        }
                    }

                    if value.trim().is_empty() {
                        // Required with no default; ask again.
                        continue;
                    }

                    let needs_obscure = opt.is_password || should_obscure_option_key(&opt.name);
                    if needs_obscure {
                        let raw_prefix = "raw:";
                        if value.to_ascii_lowercase().starts_with(raw_prefix) {
                            value = value[raw_prefix.len()..].trim().to_string();
                        } else {
                            match obscure_with_rclone(&rclone, &value) {
                                Ok(obscured) => value = obscured,
                                Err(e) => {
                                    app.auth_status = format!(
                                        "Manual config failed (obscure {}): {}",
                                        opt.name, e
                                    );
                                    app.log_error(format!(
                                        "Manual config failed (obscure {}): {}",
                                        opt.name, e
                                    ));
                                    return Ok(());
                                }
                            }
                        }
                    }

                    options.push((opt.name.clone(), value));
                    break;
                }
            }
        }
    }

    loop {
        let Some(key) = prompt_text_in_tui(
            app,
            terminal,
            "Backend Option Key",
            &format_option_key_hint(known_keys_preview.as_deref()),
        )?
        else {
            app.auth_status = "Manual configuration cancelled.".to_string();
            app.state = crate::ui::AppState::ProviderSelect;
            return Ok(());
        };
        let key = key.trim().to_string();
        if key.is_empty() {
            break;
        }

        let schema_opt = schema
            .as_ref()
            .and_then(|s| s.options.iter().find(|o| o.name.eq_ignore_ascii_case(&key)));

        let Some(mut value) = prompt_text_in_tui(
            app,
            terminal,
            "Backend Option Value",
            &format_option_value_hint(&key, schema_opt),
        )?
        else {
            app.auth_status = "Manual configuration cancelled.".to_string();
            app.state = crate::ui::AppState::ProviderSelect;
            return Ok(());
        };

        let needs_obscure =
            schema_opt.map(|o| o.is_password).unwrap_or(false) || should_obscure_option_key(&key);
        if needs_obscure {
            let raw_prefix = "raw:";
            if value.to_ascii_lowercase().starts_with(raw_prefix) {
                value = value[raw_prefix.len()..].trim().to_string();
            } else {
                match obscure_with_rclone(&rclone, &value) {
                    Ok(obscured) => value = obscured,
                    Err(e) => {
                        app.auth_status = format!("Manual config failed (obscure {}): {}", key, e);
                        app.log_error(format!("Manual config failed (obscure {}): {}", key, e));
                        return Ok(());
                    }
                }
            }
        }

        if let Some(existing) = options.iter_mut().find(|(k, _)| k == &key) {
            existing.1 = value;
        } else {
            options.push((key, value));
        }
    }

    let options_ref: Vec<(&str, &str)> = options
        .iter()
        .map(|(k, v)| (k.as_str(), v.as_str()))
        .collect();

    if let Err(e) = write_manual_remote(&config, &provider, &remote_name, &options_ref) {
        app.auth_status = format!("Manual config failed (write remote): {}", e);
        app.log_error(format!("Manual config failed (write remote): {}", e));
        return Ok(());
    }
    if !config.has_remote(&remote_name)? {
        app.auth_status = format!("Remote {} was not created.", remote_name);
        app.log_error(format!("Remote {} was not created.", remote_name));
        return Ok(());
    }

    app.remote.chosen = Some(remote_name.clone());

    // Track configured provider in case (best-effort: no user info).
    if let Some(ref mut case) = app.forensics.case {
        case.add_provider(crate::case::AuthenticatedProvider {
            provider_id: provider.id.clone(),
            provider_name: provider.display_name().to_string(),
            remote_name: remote_name.clone(),
            user_info: None,
        });
    }

    let runner = crate::rclone::RcloneRunner::new(binary.path())
        .with_config(config.path())
        .with_cancel_flag(app.shutdown.clone());

    app.auth_status = "Testing connectivity...".to_string();
    terminal.draw(|f| render_state(f, app))?;

    // Retry connectivity up to 3 times with exponential backoff.
    let max_retries: u32 = 3;
    let mut connectivity = crate::rclone::test_connectivity(&runner, &remote_name)?;
    let mut attempt: u32 = 1;
    while !connectivity.ok && attempt <= max_retries && !runner.is_cancelled() {
        let delay = crate::rclone::retry_delay(attempt - 1);
        let msg = format!(
            "Connectivity check failed (attempt {}/{}), retrying in {}s...",
            attempt,
            max_retries + 1,
            delay.as_secs()
        );
        app.log_info(&msg);
        app.auth_status = msg;
        terminal.draw(|f| render_state(f, app))?;
        std::thread::sleep(delay);
        connectivity = crate::rclone::test_connectivity(&runner, &remote_name)?;
        attempt += 1;
    }

    if connectivity.ok {
        app.log_info(format!(
            "Connectivity OK ({} ms)",
            connectivity.duration.as_millis()
        ));
    } else {
        let err_msg = connectivity
            .error
            .unwrap_or_else(|| "Unknown error".to_string());
        app.log_error(format!(
            "Connectivity failed after {} attempts: {}",
            attempt, err_msg
        ));
        app.auth_status = format!(
            "Connectivity failed after {} attempts: {}",
            attempt, err_msg
        );
    }

    if runner.is_cancelled() {
        return Ok(());
    }
    crate::ui::flows::list::perform_list_flow(app, terminal)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn manual_configuration_persists_canonical_type_and_finds_imported_aliases() {
        let discovered = crate::providers::discovery::providers_from_rclone_json(
            r#"[{"Name":"future storage","Prefix":"fsx","Description":"Friendly label"},
                 {"Name":"oracleobjectstorage","Prefix":"oos","Description":"Oracle Object Storage"}]"#,
        ).unwrap();
        for provider in discovered.providers {
            let scratch = tempfile::tempdir().unwrap();
            let config =
                crate::rclone::RcloneConfig::new(scratch.path().join("synthetic.conf")).unwrap();
            write_manual_remote(
                &config,
                &provider,
                "TestCanonical",
                &[("synthetic_option", "unchanged")],
            )
            .unwrap();
            let parsed = config.parse().unwrap();
            let remote = parsed.get_remote("TestCanonical").unwrap();
            assert_eq!(remote.remote_type, provider.backend_name());
            assert_ne!(remote.remote_type, provider.short_name());
            config
                .set_remote("TestPrefix", provider.short_name(), &[])
                .unwrap();
            config
                .set_remote(
                    "TestFileName",
                    &provider.backend_name().replace(' ', ""),
                    &[],
                )
                .unwrap();
            config
                .set_remote("TestWrongLabel", provider.display_name(), &[])
                .unwrap();
            let names =
                crate::ui::flows::remotes::resolve_provider_remotes(&config, &provider).unwrap();
            assert_eq!(names, ["TestCanonical", "TestPrefix", "TestFileName"]);
        }
    }
}
