use anyhow::Result;
use ratatui::Terminal;

use crate::ui::render::render_state;
use crate::ui::App;

pub(crate) fn perform_list_flow<B: ratatui::backend::Backend>(
    app: &mut App,
    terminal: &mut Terminal<B>,
) -> Result<()> {
    let Some(provider) = app.chosen_provider.clone() else {
        app.provider_status = "No provider selected.".to_string();
        return Ok(());
    };

    app.provider_status = format!("Preparing listing for {}...", provider.display_name());
    terminal.draw(|f| render_state(f, app))?;

    let binary = crate::embedded::ExtractedBinary::extract()?;
    app.cleanup_track_file(binary.path());
    if let Some(dir) = binary.temp_dir() {
        app.cleanup_track_dir(dir);
    }

    let config_dir = app
        .config_dir()
        .unwrap_or_else(|| std::path::PathBuf::from("."));
    app.track_env_var("RCLONE_CONFIG", "Set RCLONE_CONFIG for listing");
    let config = match crate::rclone::RcloneConfig::for_case(&config_dir) {
        Ok(config) => config,
        Err(e) => {
            app.provider_status = format!("Listing failed (config): {}", e);
            app.log_error(format!("Listing failed (config): {}", e));
            return Ok(());
        }
    };
    app.cleanup_track_env_value("RCLONE_CONFIG", config.original_env());

    let remotes = match crate::ui::flows::remotes::resolve_provider_remotes(&config, &provider) {
        Ok(remotes) => remotes,
        Err(e) => {
            app.provider_status = format!("Listing failed (parse config): {}", e);
            app.log_error(format!("Listing failed (parse config): {}", e));
            return Ok(());
        }
    };

    if remotes.is_empty() {
        app.provider_status = format!(
            "No authenticated remotes found for {}. Copy a config to {:?} and retry.",
            provider.display_name(),
            config.path()
        );
        app.log_error(format!(
            "No authenticated remotes found for {}",
            provider.display_name()
        ));
        return Ok(());
    }

    let remote_name = match crate::ui::flows::remotes::choose_remote_or_prompt(app, &provider, remotes)?
    {
        Some(remote_name) => remote_name,
        None => return Ok(()),
    };
    app.chosen_remote = Some(remote_name.clone());
    app.files_to_download.clear();
    app.file_entries.clear();
    app.file_entries_full.clear();
    app.file_selected = 0;

    let runner = crate::rclone::RcloneRunner::new(binary.path()).with_config(config.path());

    app.provider_status = format!("Listing {}...", remote_name);
    terminal.draw(|f| render_state(f, app))?;

    let include_hashes = provider
        .known
        .map(|known| !known.hash_types().is_empty())
        .unwrap_or_else(|| {
            match crate::providers::features::provider_supports_hashes(&provider) {
                Ok(Some(true)) => true,
                Ok(Some(false)) | Ok(None) => false,
                Err(e) => {
                    app.log_info(format!(
                        "Skipping remote hashes (hash support lookup failed): {}",
                        e
                    ));
                    false
                }
            }
        });

    let listing_result = crate::files::listing::list_path_with_progress(
        &runner,
        &format!("{}:", remote_name),
        if include_hashes {
            crate::files::listing::ListPathOptions::with_hashes()
        } else {
            crate::files::listing::ListPathOptions::without_hashes()
        },
        |count| {
            app.provider_status = format!("Listing {}... ({} found)", remote_name, count);
            let _ = terminal.draw(|f| render_state(f, app));
        },
    );

    match listing_result {
        Ok(entries) => {
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
            app.log_info(format!(
                "Listed {} files from {}",
                app.file_entries.len(),
                provider.display_name()
            ));
            app.provider_status = format!("Found {} files", app.file_entries.len());
            app.state = crate::ui::AppState::FileList;
        }
        Err(e) => {
            app.provider_status = format!("Listing failed: {}", e);
            app.log_error(format!("Listing failed: {}", e));
        }
    }

    Ok(())
}

