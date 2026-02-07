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

/// Configure a backend that doesn't use OAuth by prompting for config options.
///
/// This is best-effort. It writes a remote section to the case's rclone config and then
/// attempts connectivity + listing so the investigator can see files quickly.
pub(crate) fn perform_manual_config_flow<B: ratatui::backend::Backend>(
    app: &mut App,
    terminal: &mut Terminal<B>,
) -> Result<()> {
    let Some(provider) = app.chosen_provider.clone() else {
        app.auth_status = "No provider selected.".to_string();
        return Ok(());
    };

    app.auth_status = format!(
        "Manual backend configuration\n\nProvider: {}\nBackend: {}\n\nTip: You can copy an existing rclone config into the case directory, or refer to rclone docs for this backend.\n\nPassword fields (pass/password) will be obscured for rclone. Prefix the value with 'raw:' to skip obscuring.",
        provider.display_name(),
        provider.short_name(),
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
    app.track_env_var("RCLONE_CONFIG", "Set RCLONE_CONFIG for manual backend config");
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

    loop {
        let Some(key) = prompt_text_in_tui(
            app,
            terminal,
            "Backend Option Key",
            "Enter an option key (blank to finish).\n\nExample: access_key_id\n\nEnter submit | Esc cancel",
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

        let Some(mut value) = prompt_text_in_tui(
            app,
            terminal,
            "Backend Option Value",
            &format!(
                "Enter value for '{}'.\n\nPassword fields (pass/password) will be obscured.\nPrefix with 'raw:' to use the value as-is.\n\nEnter submit | Esc cancel",
                key
            ),
        )?
        else {
            app.auth_status = "Manual configuration cancelled.".to_string();
            app.state = crate::ui::AppState::ProviderSelect;
            return Ok(());
        };

        if should_obscure_option_key(&key) {
            let raw_prefix = "raw:";
            if value.to_ascii_lowercase().starts_with(raw_prefix) {
                value = value[raw_prefix.len()..].trim().to_string();
            } else {
                match obscure_with_rclone(&rclone, &value) {
                    Ok(obscured) => value = obscured,
                    Err(e) => {
                        app.auth_status =
                            format!("Manual config failed (obscure {}): {}", key, e);
                        app.log_error(format!(
                            "Manual config failed (obscure {}): {}",
                            key, e
                        ));
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

    if let Err(e) = config.set_remote(&remote_name, provider.short_name(), &options_ref) {
        app.auth_status = format!("Manual config failed (write remote): {}", e);
        app.log_error(format!("Manual config failed (write remote): {}", e));
        return Ok(());
    }
    if !config.has_remote(&remote_name)? {
        app.auth_status = format!("Remote {} was not created.", remote_name);
        app.log_error(format!("Remote {} was not created.", remote_name));
        return Ok(());
    }

    app.chosen_remote = Some(remote_name.clone());

    // Track configured provider in case (best-effort: no user info).
    if let Some(ref mut case) = app.case {
        case.add_provider(crate::case::AuthenticatedProvider {
            provider_id: provider.id.clone(),
            provider_name: provider.display_name().to_string(),
            remote_name: remote_name.clone(),
            user_info: None,
        });
    }

    let runner = crate::rclone::RcloneRunner::new(binary.path()).with_config(config.path());

    app.auth_status = "Testing connectivity...".to_string();
    terminal.draw(|f| render_state(f, app))?;

    let connectivity = crate::rclone::test_connectivity(&runner, &remote_name)?;
    if connectivity.ok {
        app.log_info(format!(
            "Connectivity OK ({} ms)",
            connectivity.duration.as_millis()
        ));
    } else {
        app.log_error(format!(
            "Connectivity failed: {}",
            connectivity
                .error
                .unwrap_or_else(|| "Unknown error".to_string())
        ));
    }

    app.auth_status = "Listing files...".to_string();
    terminal.draw(|f| render_state(f, app))?;

    let large_listing = std::env::var("RCLONE_TRIAGE_LARGE_LISTING")
        .map(|v| v != "0")
        .unwrap_or(false);
    let large_in_memory: usize = std::env::var("RCLONE_TRIAGE_LARGE_LISTING_IN_MEMORY")
        .ok()
        .and_then(|v| v.parse().ok())
        .unwrap_or(50_000);

    let include_hashes = provider
        .known
        .map(|known| !known.hash_types().is_empty())
        .unwrap_or_else(|| match crate::providers::features::provider_supports_hashes(&provider) {
            Ok(Some(true)) => true,
            Ok(Some(false)) | Ok(None) => false,
            Err(e) => {
                app.log_info(format!(
                    "Skipping remote hashes (hash support lookup failed): {}",
                    e
                ));
                false
            }
        });

    let list_options = if include_hashes {
        crate::files::listing::ListPathOptions::with_hashes()
    } else {
        crate::files::listing::ListPathOptions::without_hashes()
    };

    if large_listing {
        if app.directories.is_none() {
            app.log_info("Large listing requested, but case directories are unavailable; falling back to in-memory listing.");
        }
        if let Some(ref dirs) = app.directories {
            let csv_path = dirs
                .listings
                .join(format!("{}_files.csv", provider.short_name()));

            let listing_result = crate::files::listing::list_path_large_to_csv_with_progress(
                &runner,
                &format!("{}:", remote_name),
                list_options,
                &csv_path,
                large_in_memory,
                |count| {
                    app.auth_status = format!("Listing files... ({} found)", count);
                    let _ = terminal.draw(|f| render_state(f, app));
                },
            );

            match listing_result {
                Ok(result) => {
                    app.log_info(format!("Exported listing to {:?}", csv_path));
                    app.track_file(&csv_path, "Exported file listing CSV");

                    app.file_entries_full = result.entries.clone();
                    app.file_entries = result.entries.iter().map(|e| e.path.clone()).collect();
                    app.files_to_download.clear();
                    app.file_selected = 0;

                    let shown = app.file_entries.len();
                    if result.truncated {
                        app.auth_status = format!(
                            "Found {} files (showing first {}). CSV: {:?}",
                            result.total_entries, shown, csv_path
                        );
                    } else {
                        app.auth_status = format!("Found {} files", result.total_entries);
                    }
                    app.advance(); // Move to FileList
                }
                Err(e) => {
                    app.log_error(format!("Listing failed: {}", e));
                    app.auth_status = format!("Listing failed: {}", e);
                }
            }

            return Ok(());
        }
    }

    let listing_result = crate::files::listing::list_path_with_progress(
        &runner,
        &format!("{}:", remote_name),
        list_options,
        |count| {
            app.auth_status = format!("Listing files... ({} found)", count);
            let _ = terminal.draw(|f| render_state(f, app));
        },
    );

    match listing_result {
        Ok(entries) => {
            // Export file listing to CSV/XLSX (best-effort).
            if let Some(ref dirs) = app.directories {
                let csv_path = dirs
                    .listings
                    .join(format!("{}_files.csv", provider.short_name()));
                if let Err(e) = crate::files::export::export_listing(&entries, &csv_path) {
                    app.log_error(format!("CSV export failed: {}", e));
                } else {
                    app.log_info(format!("Exported listing to {:?}", csv_path));
                    app.track_file(&csv_path, "Exported file listing CSV");
                }

                let xlsx_path = dirs
                    .listings
                    .join(format!("{}_files.xlsx", provider.short_name()));
                if let Err(e) = crate::files::export::export_listing_xlsx(&entries, &xlsx_path) {
                    app.log_error(format!("Excel export failed: {}", e));
                } else {
                    app.log_info(format!("Exported listing to {:?}", xlsx_path));
                    app.track_file(&xlsx_path, "Exported file listing Excel");
                }
            }

            app.file_entries_full = entries.clone();
            app.file_entries = entries.iter().map(|e| e.path.clone()).collect();
            app.files_to_download.clear();
            app.file_selected = 0;

            app.auth_status = format!("Found {} files", app.file_entries.len());
            app.advance(); // Move to FileList
        }
        Err(e) => {
            app.log_error(format!("Listing failed: {}", e));
            app.auth_status = format!("Listing failed: {}", e);
        }
    }

    Ok(())
}
