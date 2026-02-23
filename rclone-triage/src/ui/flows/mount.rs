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
            app.remote.chosen = Some(remote_name);
            app.files.entries.clear();
            app.files.entries_full.clear();
            app.files.to_download.clear();
            app.files.selected = 0;
            app.provider.status = format!("Mounted remote at {:?}", mount_path);
            app.state = crate::ui::AppState::FileList;
        }
        Err(e) => {
            app.provider.status = format!("Mount failed: {}", e);
            app.log_error(format!("Mount failed: {}", e));
        }
    }

    Ok(())
}

