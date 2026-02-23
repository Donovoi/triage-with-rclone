use anyhow::Result;
use ratatui::Terminal;

use crate::ui::render::render_state;
use crate::ui::App;

/// Perform the download flow.
pub(crate) fn perform_download_flow<B: ratatui::backend::Backend>(
    app: &mut App,
    terminal: &mut Terminal<B>,
) -> Result<()> {
    use crate::files::download::{DownloadPhase, DownloadQueue, DownloadRequest};

    app.unmount_remote();
    app.download.failures.clear();

    let total_files = app.files.to_download.len();
    app.download.status = format!("Downloading {} files...", total_files);
    app.download.progress = (0, total_files);
    app.download.current_bytes = None;
    app.download.done_bytes = 0;
    let total_bytes: u64 = app
        .files.to_download
        .iter()
        .filter_map(|file| app.get_file_entry(file).map(|e| e.size))
        .sum();
    app.download.total_bytes = if total_bytes > 0 {
        Some(total_bytes)
    } else {
        None
    };
    terminal.draw(|f| render_state(f, app))?;

    let binary = crate::embedded::ExtractedBinary::extract()?;
    app.cleanup_track_file(binary.path());
    if let Some(dir) = binary.temp_dir() {
        app.cleanup_track_dir(dir);
    }

    // Use case config directory if available
    let config_dir = app
        .config_dir()
        .unwrap_or_else(|| std::path::PathBuf::from("."));
    // Track env var change before config sets it
    app.track_env_var("RCLONE_CONFIG", "Set RCLONE_CONFIG for case config");
    let config = crate::rclone::RcloneConfig::for_case(&config_dir)?;
    app.cleanup_track_env_value("RCLONE_CONFIG", config.original_env());
    let runner = crate::rclone::RcloneRunner::new(binary.path()).with_config(config.path());

    if let Some(provider) = app.provider.chosen.clone() {
        let remote_name = app
            .remote.chosen
            .as_deref()
            .unwrap_or(provider.short_name());

        // Use case downloads directory if available
        let dest_dir = app
            .downloads_dir()
            .unwrap_or_else(|| std::path::PathBuf::from("./downloads"));
        std::fs::create_dir_all(&dest_dir)?;

        let total = app.files.to_download.len();
        app.log_info(format!(
            "Starting download of {} files to {:?}",
            total, dest_dir
        ));

        // Build download queue with hash verification
        let mut queue = DownloadQueue::new();
        queue.set_verify_hashes(true);

        for file in &app.files.to_download {
            let source = format!("{}:{}", remote_name, file);
            let mapped = crate::utils::safe_join_under(&dest_dir, file);
            let dest = mapped.path;
            if mapped.changed {
                app.log_info(format!(
                    "Sanitized download destination for '{}' -> {:?}",
                    file, dest
                ));
            }

            // Ensure parent directory exists
            if let Some(parent) = dest.parent() {
                std::fs::create_dir_all(parent)?;
            }

            // Get expected hash from file listing (if available)
            let (expected_hash, hash_type, expected_size) = app
                .get_file_entry(file)
                .map(|e| (e.hash.clone(), e.hash_type.clone(), Some(e.size)))
                .unwrap_or((None, None, None));

            let request = DownloadRequest::new_copyto(&source, dest.to_string_lossy())
                .with_hash(expected_hash, hash_type)
                .with_size(expected_size);
            queue.add(request);
        }

        // Execute downloads with progress callback
        let files_clone = app.files.to_download.clone();
        let mut completed_bytes: u64 = 0;
        let results = queue.download_all_with_progress(&runner, |progress| {
            match progress.phase {
                DownloadPhase::Starting | DownloadPhase::InProgress | DownloadPhase::Failed => {
                    app.download.progress = (progress.current, progress.total);
                }
                DownloadPhase::Completed => {
                    app.download.progress = (progress.current + 1, progress.total);
                }
            }

            match progress.phase {
                DownloadPhase::InProgress => {
                    if let (Some(done), Some(total)) = (progress.bytes_done, progress.bytes_total) {
                        app.download.current_bytes = Some((done, total));
                        if let Some(overall_total) = app.download.total_bytes {
                            let done_total = completed_bytes.saturating_add(done);
                            app.download.done_bytes = done_total.min(overall_total);
                        }
                    }
                }
                DownloadPhase::Completed => {
                    if let Some(total) = progress.bytes_total.or(progress.bytes_done) {
                        completed_bytes = completed_bytes.saturating_add(total);
                        if let Some(overall_total) = app.download.total_bytes {
                            app.download.done_bytes = completed_bytes.min(overall_total);
                        } else {
                            app.download.done_bytes = completed_bytes;
                        }
                    }
                    app.download.current_bytes = progress.bytes_total.map(|t| (t, t));
                }
                DownloadPhase::Starting | DownloadPhase::Failed => {
                    app.download.current_bytes = None;
                }
            }

            app.download.status = progress.status.clone();
            let _ = terminal.draw(|f| render_state(f, app));
        });

        // Process results
        let mut success_count = 0;
        let mut hash_verified_count = 0;
        let mut hash_mismatch_count = 0;

        for (i, result) in results.iter().enumerate() {
            let file = &files_clone[i];
            app.download.progress = (i + 1, total);
            app.download.status = format!("Processing {}/{}: {}", i + 1, total, file);

            if result.success {
                success_count += 1;
                let size = result.size.unwrap_or(0);

                // Log hash verification status
                match result.hash_verified {
                    Some(true) => {
                        hash_verified_count += 1;
                        app.log_info(format!(
                            "Downloaded: {} ({} bytes) - hash verified ✓",
                            file, size
                        ));
                    }
                    Some(false) => {
                        hash_mismatch_count += 1;
                        app.log_error(format!(
                            "Downloaded: {} ({} bytes) - HASH MISMATCH! Expected: {:?}, Got: {:?}",
                            file,
                            size,
                            app.get_file_entry(file).and_then(|e| e.hash.clone()),
                            result.hash
                        ));
                    }
                    None => {
                        if app
                            .get_file_entry(file)
                            .and_then(|e| e.hash.clone())
                            .is_some()
                        {
                            app.log_info(format!(
                                "Downloaded: {} ({} bytes) - hash verification skipped: {}",
                                file,
                                size,
                                result.hash_error.as_deref().unwrap_or("unknown reason")
                            ));
                        } else {
                            app.log_info(format!(
                                "Downloaded: {} ({} bytes) - provider did not supply a hash",
                                file, size
                            ));
                        }
                    }
                }

                // Track downloaded file
                let dest = crate::utils::safe_join_under(&dest_dir, file).path;
                app.track_file(&dest, format!("Downloaded file: {}", file));

                // Track downloaded file in case
                if let Some(ref mut case) = app.forensics.case {
                    case.add_download(crate::case::DownloadedFile {
                        path: file.clone(),
                        size,
                        hash: result.hash.clone(),
                        hash_type: result.hash_type.clone(),
                        hash_verified: result.hash_verified,
                        hash_error: result.hash_error.clone(),
                    });
                }
            } else {
                let err_msg = result.error.as_deref().unwrap_or("Unknown error");
                app.download.failures.push(file.clone());
                app.log_error(format!("Download failed for {}: {}", file, err_msg));
            }
        }

        // Finalize the case
        if let Some(ref mut case) = app.forensics.case {
            case.finalize();
        }

        let failed_count = app.download.failures.len();

        // Summary
        app.log_info(format!(
            "Download complete: {}/{} files successful",
            success_count, total
        ));
        if hash_verified_count > 0 {
            app.log_info(format!("Hash verified: {} files", hash_verified_count));
        }
        if hash_mismatch_count > 0 {
            app.log_error(format!(
                "Hash mismatch detected: {} files (possible tampering!)",
                hash_mismatch_count
            ));
        }
        if failed_count > 0 {
            app.log_error(format!(
                "Failed downloads: {} files (see log for details)",
                failed_count
            ));
        }

        app.download.status = format!(
            "Downloaded {}/{} files ({} verified, {} failed)",
            success_count, total, hash_verified_count, failed_count
        );

        // Generate and write the forensic report
        if let (Some(ref case), Some(ref dirs)) = (&app.forensics.case, &app.forensics.directories) {
            let log_hash = app.forensics.logger.as_ref().and_then(|l| l.final_hash().ok());

            // Capture final state and compute diff
            let state_diff = app.capture_final_state();

            // Get change tracker report as string
            let change_report = app
                .forensics.change_tracker
                .lock()
                .ok()
                .map(|tracker| tracker.generate_report());

            // Attempt cleanup and capture any unrevertable changes
            let cleanup_report = app.forensics.cleanup.as_ref().and_then(|cleanup| {
                if let Ok(mut cleanup) = cleanup.lock() {
                    let _ = cleanup.execute();
                    cleanup.cleanup_report()
                } else {
                    None
                }
            });

            let report_content = crate::case::report::generate_report_with_metadata(
                case,
                state_diff.as_ref(),
                change_report.as_deref(),
                cleanup_report.as_deref(),
                log_hash.as_deref(),
                Some(&crate::case::report::ReportMetadata::from_environment()),
            );

            if let Err(e) = crate::case::report::write_report(&dirs.report, &report_content) {
                app.log_error(format!("Failed to write report: {}", e));
            } else {
                app.log_info(format!("Report written to {:?}", dirs.report));
            }

            // Also generate XLSX report
            let xlsx_report_path = dirs.base.join("forensic_report.xlsx");
            if let Err(e) = crate::case::report::write_report_xlsx(
                &xlsx_report_path,
                case,
                state_diff.as_ref(),
                Some(&crate::case::report::ReportMetadata::from_environment()),
            ) {
                app.log_error(format!("Failed to write XLSX report: {}", e));
            } else {
                app.log_info(format!("XLSX report written to {:?}", xlsx_report_path));
            }
        }

        // Generate report lines for TUI display
        let dest_display = app
            .downloads_dir()
            .map(|p| p.display().to_string())
            .unwrap_or_else(|| "./downloads/".to_string());

        app.download.report_lines = vec!["=== rclone-triage Report ===".to_string(), String::new()];

        // Add case metadata if available
        if let Some(ref case) = app.forensics.case {
            app.download.report_lines
                .push(format!("Case: {}", case.session_id()));
            app.download.report_lines.push(format!(
                "Started: {}",
                case.start_time.format("%Y-%m-%d %H:%M:%S UTC")
            ));
            if let Some(end) = case.end_time {
                app.download.report_lines
                    .push(format!("Ended: {}", end.format("%Y-%m-%d %H:%M:%S UTC")));
            }
            app.download.report_lines.push(String::new());
        }

        app.download.report_lines
            .push(format!("Provider: {}", provider.display_name()));
        app.download.report_lines.push(format!("Files requested: {}", total));
        app.download.report_lines
            .push(format!("Files downloaded: {}", success_count));
        if failed_count > 0 {
            app.download.report_lines
                .push(format!("Failed downloads: {}", failed_count));
        }
        app.download.report_lines
            .push(format!("Destination: {}", dest_display));
        app.download.report_lines.push(String::new());
        app.download.report_lines.push("Downloaded files:".to_string());

        // Use case downloaded_files if available for sizes
        if let Some(ref case) = app.forensics.case {
            for file in &case.downloaded_files {
                app.download.report_lines
                    .push(format!("  - {} ({} bytes)", file.path, file.size));
            }
        } else {
            for file in &app.files.to_download {
                app.download.report_lines.push(format!("  - {}", file));
            }
        }

        app.download.report_lines.push(String::new());
        if failed_count > 0 {
            app.download.report_lines
                .push("Press 'r' to retry failed downloads or 'q' to exit.".to_string());
        } else {
            app.download.report_lines.push("Press 'q' to exit.".to_string());
        }

        app.advance(); // Move to Complete
    }

    Ok(())
}
