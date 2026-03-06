use anyhow::Result;
use ratatui::Terminal;

use crate::ui::render::render_state;
use crate::ui::App;

pub(crate) fn perform_list_flow<B: ratatui::backend::Backend>(
    app: &mut App,
    terminal: &mut Terminal<B>,
) -> Result<()> {
    let Some(provider) = app.provider.chosen.clone() else {
        app.provider.status = "No provider selected.".to_string();
        return Ok(());
    };

    app.provider.status = format!("Preparing listing for {}...", provider.display_name());
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
            app.provider.status = format!("Listing failed (config): {}", e);
            app.log_error(format!("Listing failed (config): {}", e));
            return Ok(());
        }
    };
    app.cleanup_track_env_value("RCLONE_CONFIG", config.original_env());

    let remotes = match crate::ui::flows::remotes::resolve_provider_remotes(&config, &provider) {
        Ok(remotes) => remotes,
        Err(e) => {
            app.provider.status = format!("Listing failed (parse config): {}", e);
            app.log_error(format!("Listing failed (parse config): {}", e));
            return Ok(());
        }
    };

    if remotes.is_empty() {
        app.provider.status = format!(
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

    let remote_name =
        match crate::ui::flows::remotes::choose_remote_or_prompt(app, &provider, remotes)? {
            Some(remote_name) => remote_name,
            None => return Ok(()),
        };
    app.remote.chosen = Some(remote_name.clone());
    app.files.to_download.clear();
    app.files.entries.clear();
    app.files.entries_full.clear();
    app.files.selected = 0;

    app.provider.status = format!("Listing {}...", remote_name);
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
        .unwrap_or_else(
            || match crate::providers::features::provider_supports_hashes(&provider) {
                Ok(Some(true)) => true,
                Ok(Some(false)) | Ok(None) => false,
                Err(e) => {
                    app.log_info(format!(
                        "Skipping remote hashes (hash support lookup failed): {}",
                        e
                    ));
                    false
                }
            },
        );

    let list_options = if include_hashes {
        crate::files::listing::ListPathOptions::with_hashes()
    } else {
        crate::files::listing::ListPathOptions::without_hashes()
    };

    if large_listing {
        if app.forensics.directories.is_none() {
            app.log_info("Large listing requested, but case directories are unavailable; falling back to in-memory listing.");
        }
        if let Some(ref dirs) = app.forensics.directories {
            let runner = crate::rclone::RcloneRunner::new(binary.path()).with_config(config.path());
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
                    app.provider.status = format!("Listing {}... ({} found)", remote_name, count);
                    let _ = terminal.draw(|f| render_state(f, app));
                },
            );

            match listing_result {
                Ok(result) => {
                    app.log_info(format!("Exported listing to {:?}", csv_path));
                    app.track_file(&csv_path, "Exported file listing CSV");

                    app.files.entries_full = result.entries.clone();
                    app.files.entries = result.entries.iter().map(|e| e.path.clone()).collect();

                    let shown = app.files.entries.len();
                    if result.truncated {
                        app.provider.status = format!(
                            "Found {} files (showing first {}). CSV: {:?}",
                            result.total_entries, shown, csv_path
                        );
                    } else {
                        app.provider.status = format!("Found {} files", result.total_entries);
                    }
                    app.state = crate::ui::AppState::FileList;
                }
                Err(e) => {
                    app.provider.status = format!("Listing failed: {}", e);
                    app.log_error(format!("Listing failed: {}", e));
                }
            }

            return Ok(());
        }
    }

    // Spawn listing in background thread so the TUI stays responsive
    let target = format!("{}:", remote_name);
    let remote_type = provider
        .known
        .map(|k| format!("{:?}", k).to_lowercase())
        .unwrap_or_else(|| provider.short_name().to_string());
    app.log_info(format!("Starting background listing of {}", target));

    let (handle, progress_rx, cancel) = crate::files::listing::spawn_list_with_progress(
        binary.path().to_path_buf(),
        config.path().to_path_buf(),
        target,
        list_options,
    );

    app.listing_task = Some(crate::ui::ListingTask {
        handle,
        progress_rx,
        cancel,
        started: std::time::Instant::now(),
        count: 0,
        context: crate::ui::ListingContext {
            remote_name,
            remote_type,
            combine_remotes: Vec::new(),
            include_hashes,
            config_path: config.path().to_path_buf(),
        },
    });

    app.state = crate::ui::AppState::Listing;
    terminal.draw(|f| render_state(f, app))?;

    Ok(())
}

/// Perform a list flow from an existing config file (config browser path).
/// Unlike perform_list_flow, this does not require a provider selection—
/// it loads all remotes from the config and lets the user pick one or more.
///
/// When multiple remotes are selected, a combine remote is created so all
/// files appear under one listing with per-remote subdirectories.
pub(crate) fn perform_list_flow_from_config<B: ratatui::backend::Backend>(
    app: &mut App,
    terminal: &mut Terminal<B>,
    config_path: &std::path::Path,
) -> Result<()> {
    // Clear any previous listing error when user retries
    app.config_browser.last_error = None;
    app.provider.status = format!("Loading config: {}...", config_path.display());
    terminal.draw(|f| render_state(f, app))?;

    let binary = crate::embedded::ExtractedBinary::extract()?;
    app.cleanup_track_file(binary.path());
    if let Some(dir) = binary.temp_dir() {
        app.cleanup_track_dir(dir);
    }

    app.track_env_var(
        "RCLONE_CONFIG",
        "Set RCLONE_CONFIG for config-based listing",
    );
    let config = match crate::rclone::RcloneConfig::open_existing(config_path) {
        Ok(config) => config,
        Err(e) => {
            app.config_browser.status = format!("Failed to open config: {}", e);
            app.log_error(format!("Failed to open config: {}", e));
            app.state = crate::ui::AppState::ConfigBrowser;
            return Ok(());
        }
    };
    app.cleanup_track_env_value("RCLONE_CONFIG", config.original_env());

    let remotes = match crate::ui::flows::remotes::resolve_all_remotes(&config) {
        Ok(remotes) => remotes,
        Err(e) => {
            app.config_browser.status = format!("Failed to parse config: {}", e);
            app.log_error(format!("Failed to parse config: {}", e));
            app.state = crate::ui::AppState::ConfigBrowser;
            return Ok(());
        }
    };

    if remotes.is_empty() {
        app.config_browser.status = format!(
            "No remotes found in {}. Choose a different config file.",
            config_path.display()
        );
        app.log_error(format!("No remotes found in {}", config_path.display()));
        app.state = crate::ui::AppState::ConfigBrowser;
        return Ok(());
    }

    // Check if multi-select was already confirmed (resume after RemoteSelect screen)
    let (remote_name, remote_type, combine_remotes) = if !app.remote.chosen_multiple.is_empty() {
        // Multi-select confirmed — strip " (type)" suffixes to get raw names
        let raw_names: Vec<String> = app
            .remote
            .chosen_multiple
            .iter()
            .map(|s| s.split(" (").next().unwrap_or(s).to_string())
            .collect();

        if raw_names.len() == 1 {
            let rtype = remotes
                .iter()
                .find(|(n, _)| *n == raw_names[0])
                .map(|(_, t)| t.clone())
                .unwrap_or_default();
            app.remote.chosen = Some(raw_names[0].clone());
            (raw_names[0].clone(), rtype, Vec::new())
        } else {
            // Create combine remote
            let combine_name = crate::rclone::combine::create_combine_remote(&config, &raw_names)?;
            app.combine_remote_created = true;
            app.remote.chosen = Some(combine_name.clone());
            app.log_info(format!(
                "Created combine remote '{}' with upstreams: {}",
                combine_name,
                raw_names.join(", ")
            ));
            (combine_name, "combine".to_string(), raw_names)
        }
    } else if let Some(chosen) = app.remote.chosen.clone() {
        // Single-select already confirmed (auto-select or resuming)
        let rtype = remotes
            .iter()
            .find(|(n, _)| *n == chosen)
            .map(|(_, t)| t.clone())
            .unwrap_or_default();
        (chosen, rtype, Vec::new())
    } else {
        // First call — route to remote selection
        match crate::ui::flows::remotes::choose_remote_from_all(app, remotes)? {
            Some((name, rtype)) => {
                app.remote.chosen = Some(name.clone());
                (name, rtype, Vec::new())
            }
            None => return Ok(()), // Gone to RemoteSelect screen
        }
    };

    app.files.to_download.clear();
    app.files.entries.clear();
    app.files.entries_full.clear();
    app.files.selected = 0;

    let include_hashes = if combine_remotes.is_empty() {
        crate::providers::features::type_supports_hashes(&remote_type)
    } else {
        false // combine remotes aggregate different hash types; skip for consistency
    };

    let list_options = if include_hashes {
        crate::files::listing::ListPathOptions::with_hashes()
    } else {
        crate::files::listing::ListPathOptions::without_hashes()
    };

    let target = format!("{}:", remote_name);
    app.provider.status = format!("Listing {}...", remote_name);
    app.log_info(format!("Starting background listing of {}", target));

    // Spawn listing in background thread so the TUI stays responsive
    let (handle, progress_rx, cancel) = crate::files::listing::spawn_list_with_progress(
        binary.path().to_path_buf(),
        config.path().to_path_buf(),
        target,
        list_options,
    );

    app.listing_task = Some(crate::ui::ListingTask {
        handle,
        progress_rx,
        cancel,
        started: std::time::Instant::now(),
        count: 0,
        context: crate::ui::ListingContext {
            remote_name,
            remote_type,
            combine_remotes,
            include_hashes,
            config_path: config_path.to_path_buf(),
        },
    });

    app.state = crate::ui::AppState::Listing;
    terminal.draw(|f| render_state(f, app))?;

    Ok(())
}

/// Finalize a completed background listing: export CSV/XLSX, populate file entries, transition
/// to FileList. Called from the event loop when `ListingProgress::Done` is received.
pub(crate) fn finalize_listing(app: &mut App, mut entries: Vec<crate::files::FileEntry>) {
    let task = match app.listing_task.take() {
        Some(t) => t,
        None => return,
    };
    let ctx = task.context;

    // Tag entries with remote names when using a combine remote
    if !ctx.combine_remotes.is_empty() {
        crate::files::listing::tag_entries_with_remote(&mut entries, &ctx.combine_remotes);
    }

    let export_label = if ctx.combine_remotes.is_empty() {
        ctx.remote_type.clone()
    } else {
        ctx.combine_remotes.join("+")
    };

    if let Some(ref dirs) = app.forensics.directories {
        let csv_path = dirs.listings.join(format!("{}_files.csv", export_label));
        if let Err(e) = crate::files::export::export_listing(&entries, &csv_path) {
            app.log_error(format!("CSV export failed: {}", e));
        } else {
            app.log_info(format!("Exported listing to {:?}", csv_path));
            app.track_file(&csv_path, "Exported file listing CSV");
        }

        let xlsx_path = dirs.listings.join(format!("{}_files.xlsx", export_label));
        if let Err(e) = crate::files::export::export_listing_xlsx(&entries, &xlsx_path) {
            app.log_error(format!("Excel export failed: {}", e));
        } else {
            app.log_info(format!("Exported listing to {:?}", xlsx_path));
            app.track_file(&xlsx_path, "Exported file listing Excel");
        }
    }

    app.files.entries_full = entries.clone();
    app.files.entries = entries
        .iter()
        .map(|e| {
            if let Some(ref rn) = e.remote_name {
                if e.path.is_empty() {
                    format!("[{}]", rn)
                } else {
                    format!("[{}] {}", rn, e.path)
                }
            } else {
                e.path.clone()
            }
        })
        .collect();
    app.log_info(format!(
        "Listed {} files from {}",
        app.files.entries.len(),
        if ctx.combine_remotes.is_empty() {
            format!("{} ({})", ctx.remote_name, ctx.remote_type)
        } else {
            format!("combined: {}", ctx.combine_remotes.join(", "))
        }
    ));
    app.provider.status = format!("Found {} files", app.files.entries.len());
    app.state = crate::ui::AppState::FileList;
}
