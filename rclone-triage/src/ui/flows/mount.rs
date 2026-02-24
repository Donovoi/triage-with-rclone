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

    let mut manager = match crate::rclone::MountManager::new(binary.path()) {
        Ok(manager) => manager.with_config(config.path()),
        Err(e) => {
            app.provider.status = format!("Mount failed: {}", e);
            app.log_error(format!("Mount failed: {}", e));
            return Ok(());
        }
    };

    // Check for FUSE/WinFSP and auto-install if missing
    match manager.check_fuse_available() {
        Ok(true) => {}
        Ok(false) => {
            app.provider.status = "FUSE/WinFSP not found. Installing automatically...".to_string();
            app.log_info("FUSE/WinFSP not detected — attempting auto-install");
            terminal.draw(|f| render_state(f, app))?;

            match manager.install_fuse() {
                Ok(true) => {
                    app.provider.status = "FUSE/WinFSP installed successfully.".to_string();
                    app.log_info("FUSE/WinFSP installed successfully");
                    terminal.draw(|f| render_state(f, app))?;
                }
                Ok(false) | Err(_) => {
                    app.provider.status = "FUSE/WinFSP auto-install failed. Install manually and retry:\n\
                        Windows: winget install WinFsp.WinFsp\n\
                        Linux: sudo apt install fuse3\n\
                        macOS: brew install --cask macfuse"
                        .to_string();
                    app.log_error("FUSE/WinFSP auto-install failed");
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
            return Ok(());
        }
        app.track_file(&mount_base, "Created mount base directory inside case");

        if let Err(e) = std::fs::create_dir_all(&cache_dir) {
            app.provider.status = format!("Mount failed (cache dir): {}", e);
            app.log_error(format!(
                "Mount failed (cache dir {:?}): {}",
                cache_dir, e
            ));
            return Ok(());
        }
        app.track_file(&cache_dir, "Created rclone cache directory inside case");

        manager = manager.with_mount_base(&mount_base).with_cache_dir(&cache_dir);
    }

    match manager.mount_and_explore(&remote_name, None) {
        Ok(mounted) => {
            let mount_path = mounted.mount_point().to_path_buf();
            app.mounted_remote = Some(mounted);
            app.remote.chosen = Some(remote_name.clone());
            app.files.entries.clear();
            app.files.entries_full.clear();
            app.files.to_download.clear();
            app.files.selected = 0;
            app.provider.status = format!("Mounted at {:?} — listing files...", mount_path);
            terminal.draw(|f| render_state(f, app))?;

            // Run a file listing so the TUI file list is populated.
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

            if let Some(ref dirs) = app.forensics.directories {
                let csv_path = dirs.listings.join(format!("{}_files.csv", short));
                let listing_result = crate::files::listing::list_path_large_to_csv_with_progress(
                    &runner,
                    &target,
                    list_options,
                    &csv_path,
                    max_in_memory,
                    |count| {
                        app.provider.status = format!("Mounted at {:?} — listing files... ({} found)", mount_path, count);
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
                                "Mounted at {:?}. Found {} files (showing first {}). CSV: {:?}",
                                mount_path, result.total_entries, shown, csv_path
                            );
                        } else {
                            app.provider.status = format!(
                                "Mounted at {:?}. Found {} files.",
                                mount_path, result.total_entries
                            );
                        }
                    }
                    Err(e) => {
                        app.log_error(format!("File listing after mount failed: {}", e));
                        app.provider.status = format!(
                            "Mounted at {:?}. Listing failed: {}",
                            mount_path, e
                        );
                    }
                }
            } else {
                let listing_result = crate::files::listing::list_path_with_progress(
                    &runner,
                    &target,
                    list_options,
                    |count| {
                        app.provider.status = format!("Mounted at {:?} — listing files... ({} found)", mount_path, count);
                        let _ = terminal.draw(|f| render_state(f, app));
                    },
                );
                match listing_result {
                    Ok(entries) => {
                        app.files.entries_full = entries.clone();
                        app.files.entries = entries.iter().map(|e| e.path.clone()).collect();
                        app.provider.status = format!("Mounted at {:?}. Found {} files.", mount_path, app.files.entries.len());
                    }
                    Err(e) => {
                        app.log_error(format!("File listing after mount failed: {}", e));
                        app.provider.status = format!(
                            "Mounted at {:?}. Listing failed: {}",
                            mount_path, e
                        );
                    }
                }
            }

            app.state = crate::ui::AppState::FileList;
        }
        Err(e) => {
            app.provider.status = format!("Mount failed: {}", e);
            app.log_error(format!("Mount failed: {}", e));
        }
    }

    Ok(())
}

