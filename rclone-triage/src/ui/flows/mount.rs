use anyhow::Result;
use ratatui::Terminal;

use crate::ui::render::render_state;
use crate::ui::App;

pub(crate) fn perform_mount_flow<B: ratatui::backend::Backend>(
    app: &mut App,
    terminal: &mut Terminal<B>,
) -> Result<()> {
    let Some(provider) = app.provider.chosen.clone() else {
        app.provider.status = "No provider selected.".to_string();
        return Ok(());
    };

    if app.mounted_remote.is_some() {
        app.provider.status = "Remote already mounted.".to_string();
        return Ok(());
    }

    app.provider.status = format!("Preparing mount for {}...", provider.display_name());
    terminal.draw(|f| render_state(f, app))?;

    let binary = crate::embedded::ExtractedBinary::extract()?;
    app.cleanup_track_file(binary.path());
    if let Some(dir) = binary.temp_dir() {
        app.cleanup_track_dir(dir);
    }

    let config_dir = app
        .config_dir()
        .unwrap_or_else(|| std::path::PathBuf::from("."));
    app.track_env_var("RCLONE_CONFIG", "Set RCLONE_CONFIG for mount");
    let config = match crate::rclone::RcloneConfig::for_case(&config_dir) {
        Ok(config) => config,
        Err(e) => {
            app.provider.status = format!("Mount failed (config): {}", e);
            app.log_error(format!("Mount failed (config): {}", e));
            return Ok(());
        }
    };
    app.cleanup_track_env_value("RCLONE_CONFIG", config.original_env());

    let remotes = match crate::ui::flows::remotes::resolve_provider_remotes(&config, &provider) {
        Ok(remotes) => remotes,
        Err(e) => {
            app.provider.status = format!("Mount failed (parse config): {}", e);
            app.log_error(format!("Mount failed (parse config): {}", e));
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

    let remote_name = match crate::ui::flows::remotes::choose_remote_or_prompt(app, &provider, remotes)?
    {
        Some(remote_name) => remote_name,
        None => return Ok(()),
    };

    // --- Phase 1: Run file listing BEFORE mounting ---
    // This avoids API contention between the mount process and lsjson.
    let runner = crate::rclone::RcloneRunner::new(binary.path()).with_config(config.path());
    let include_hashes = provider
        .known
        .map(|known| !known.hash_types().is_empty())
        .unwrap_or(false);
    let list_options = if include_hashes {
        crate::files::listing::ListPathOptions::with_hashes()
    } else {
        crate::files::listing::ListPathOptions::without_hashes()
    };
    let target = format!("{}:", remote_name);
    let short = provider.short_name().to_string();
    let max_in_memory: usize = std::env::var("RCLONE_TRIAGE_LARGE_LISTING_IN_MEMORY")
        .ok()
        .and_then(|v| v.parse().ok())
        .unwrap_or(50_000);

    app.remote.chosen = Some(remote_name.clone());
    app.files.entries.clear();
    app.files.entries_full.clear();
    app.files.to_download.clear();
    app.files.selected = 0;

    app.provider.status = "Listing files... (0 found)".to_string();
    terminal.draw(|f| render_state(f, app))?;

    if let Some(ref dirs) = app.forensics.directories {
        let csv_path = dirs.listings.join(format!("{}_files.csv", short));
        let listing_result = crate::files::listing::list_path_large_to_csv_with_progress(
            &runner,
            &target,
            list_options,
            &csv_path,
            max_in_memory,
            |count| {
                app.provider.status = format!("Listing files... ({} found)", count);
                let _ = terminal.draw(|f| render_state(f, app));
            },
        );
        match listing_result {
            Ok(result) => {
                if result.total_entries == 0 && list_options.fast_list {
                    tracing::warn!("Listing returned 0 entries with --fast-list, retrying without");
                    app.provider.status = "Retrying listing without fast-list...".to_string();
                    let _ = terminal.draw(|f| render_state(f, app));

                    let retry_options = list_options.without_fast_list();
                    let retry_result = crate::files::listing::list_path_large_to_csv_with_progress(
                        &runner,
                        &target,
                        retry_options,
                        &csv_path,
                        max_in_memory,
                        |count| {
                            app.provider.status = format!("Listing files... ({} found)", count);
                            let _ = terminal.draw(|f| render_state(f, app));
                        },
                    );
                    match retry_result {
                        Ok(retry) => {
                            populate_mount_listing(app, &retry, &csv_path);
                        }
                        Err(e) => {
                            app.log_error(format!("File listing retry failed: {}", e));
                            app.provider.status = format!("Listing failed: {}", e);
                        }
                    }
                } else {
                    populate_mount_listing(app, &result, &csv_path);
                }
            }
            Err(e) => {
                app.log_error(format!("File listing failed: {}", e));
                app.provider.status = format!("Listing failed: {}", e);
            }
        }
    } else {
        let listing_result = crate::files::listing::list_path_with_progress(
            &runner,
            &target,
            list_options,
            |count| {
                app.provider.status = format!("Listing files... ({} found)", count);
                let _ = terminal.draw(|f| render_state(f, app));
            },
        );
        match listing_result {
            Ok(entries) => {
                if entries.is_empty() && list_options.fast_list {
                    tracing::warn!("Listing returned 0 entries with --fast-list, retrying without");
                    app.provider.status = "Retrying listing without fast-list...".to_string();
                    let _ = terminal.draw(|f| render_state(f, app));

                    let retry_options = list_options.without_fast_list();
                    match crate::files::listing::list_path_with_progress(
                        &runner,
                        &target,
                        retry_options,
                        |count| {
                            app.provider.status = format!("Listing files... ({} found)", count);
                            let _ = terminal.draw(|f| render_state(f, app));
                        },
                    ) {
                        Ok(retry_entries) => {
                            app.files.entries_full = retry_entries.clone();
                            app.files.entries = retry_entries.iter().map(|e| e.path.clone()).collect();
                            app.provider.status = format!("Found {} files", app.files.entries.len());
                        }
                        Err(e) => {
                            app.log_error(format!("File listing retry failed: {}", e));
                            app.provider.status = format!("Listing failed: {}", e);
                        }
                    }
                } else {
                    app.files.entries_full = entries.clone();
                    app.files.entries = entries.iter().map(|e| e.path.clone()).collect();
                    app.provider.status = format!("Found {} files", app.files.entries.len());
                }
            }
            Err(e) => {
                app.log_error(format!("File listing failed: {}", e));
                app.provider.status = format!("Listing failed: {}", e);
            }
        }
    }

    // --- Phase 2: Mount the remote for file explorer access ---
    let mut manager = match crate::rclone::MountManager::new(binary.path()) {
        Ok(manager) => manager.with_config(config.path()),
        Err(e) => {
            app.provider.status = format!("Found {} files. Mount failed: {}", app.files.entries.len(), e);
            app.log_error(format!("Mount failed: {}", e));
            app.state = crate::ui::AppState::FileList;
            return Ok(());
        }
    };

    // Check for FUSE/WinFSP and auto-install if missing
    match manager.check_fuse_available() {
        Ok(true) => {}
        Ok(false) => {
            app.provider.status = format!(
                "Found {} files. Mounting...",
                app.files.entries.len()
            );
            terminal.draw(|f| render_state(f, app))?;
            app.log_info("FUSE/WinFSP not detected — attempting auto-install");

            match manager.install_fuse() {
                Ok(true) => {
                    app.log_info("FUSE/WinFSP installed successfully");
                }
                Ok(false) | Err(_) => {
                    app.log_error("FUSE/WinFSP auto-install failed");
                    app.provider.status = format!(
                        "Found {} files. Mount skipped (FUSE/WinFSP not available).",
                        app.files.entries.len()
                    );
                    app.state = crate::ui::AppState::FileList;
                    return Ok(());
                }
            }
        }
        Err(e) => {
            app.provider.status = format!("FUSE check failed: {}. Attempting mount anyway.", e);
            app.log_info(format!("FUSE check failed: {}", e));
        }
    }

    // Keep mount points and caches inside the case directory to reduce system footprint.
    if let Some(ref dirs) = app.forensics.directories {
        let mount_base = dirs.base.join("mounts");
        let cache_dir = dirs.base.join("cache").join("rclone");

        if let Err(e) = std::fs::create_dir_all(&mount_base) {
            app.provider.status = format!("Mount failed (mount dir): {}", e);
            app.log_error(format!(
                "Mount failed (mount dir {:?}): {}",
                mount_base, e
            ));
            app.state = crate::ui::AppState::FileList;
            return Ok(());
        }
        app.track_file(&mount_base, "Created mount base directory inside case");

        if let Err(e) = std::fs::create_dir_all(&cache_dir) {
            app.provider.status = format!("Mount failed (cache dir): {}", e);
            app.log_error(format!(
                "Mount failed (cache dir {:?}): {}",
                cache_dir, e
            ));
            app.state = crate::ui::AppState::FileList;
            return Ok(());
        }
        app.track_file(&cache_dir, "Created rclone cache directory inside case");

        manager = manager.with_mount_base(&mount_base).with_cache_dir(&cache_dir);
    }

    app.provider.status = format!(
        "Found {} files. Mounting {}...",
        app.files.entries.len(),
        remote_name
    );
    terminal.draw(|f| render_state(f, app))?;

    match manager.mount_and_explore(&remote_name, None) {
        Ok(mounted) => {
            let mount_path = mounted.mount_point().to_path_buf();
            app.mounted_remote = Some(mounted);
            app.log_info(format!("Mounted {} at {:?}", remote_name, mount_path));
            if app.files.entries.is_empty() {
                app.provider.status = format!(
                    "Mounted at {:?}. Listing returned 0 files — check logs.",
                    mount_path
                );
            } else {
                app.provider.status = format!(
                    "Mounted at {:?}. {} files listed.",
                    mount_path,
                    app.files.entries.len()
                );
            }
        }
        Err(e) => {
            app.provider.status = format!(
                "Found {} files. Mount failed: {}",
                app.files.entries.len(),
                e
            );
            app.log_error(format!("Mount failed: {}", e));
        }
    }

    app.state = crate::ui::AppState::FileList;
    Ok(())
}

/// Populate app state from a large listing result, including CSV export tracking.
fn populate_mount_listing(
    app: &mut App,
    result: &crate::files::listing::LargeListingResult,
    csv_path: &std::path::Path,
) {
    app.log_info(format!("Exported listing to {:?}", csv_path));
    app.track_file(csv_path, "Exported file listing CSV");
    app.files.entries_full = result.entries.clone();
    app.files.entries = result.entries.iter().map(|e| e.path.clone()).collect();
    let shown = app.files.entries.len();
    if result.truncated {
        app.provider.status = format!(
            "Found {} files (showing first {}). CSV: {:?}",
            result.total_entries, shown, csv_path
        );
    } else {
        app.provider.status = format!("Found {} files.", result.total_entries);
    }
}