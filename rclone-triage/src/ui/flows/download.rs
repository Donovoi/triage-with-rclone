use anyhow::{Context, Result};
use crossterm::event::{self, Event, KeyCode, KeyEventKind, KeyModifiers};
use ratatui::Terminal;
use std::collections::HashMap;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{mpsc, Arc};
use std::thread::JoinHandle;
use std::time::Duration;

use crate::files::download::{DownloadPhase, DownloadProgress, DownloadQueue, DownloadResult};
use crate::files::planner::{plan_downloads, write_acquisition_manifest, AcquisitionPlan};
use crate::files::DownloadQueueEntry;
use crate::ui::render::render_state;
use crate::ui::{App, AppState};

/// Always reap workers, including on terminal errors and early returns.
struct DownloadJob {
    cancel: Arc<AtomicBool>,
    handle: Option<JoinHandle<Vec<DownloadResult>>>,
}

impl Drop for DownloadJob {
    fn drop(&mut self) {
        self.cancel.store(true, Ordering::Relaxed);
        if let Some(handle) = self.handle.take() {
            let _ = handle.join();
        }
    }
}

fn prepare_plan(app: &App) -> Result<AcquisitionPlan> {
    let source = app
        .acquisition
        .as_ref()
        .context("No acquisition source. List the remote again.")?;
    let config = crate::rclone::RcloneConfig::open_existing(&source.config_path)?;
    let known = config
        .parse()?
        .remotes
        .into_iter()
        .map(|r| r.name)
        .collect::<Vec<_>>();
    let entries = app
        .files
        .to_download
        .iter()
        .map(|display| {
            let entry = app.get_file_entry(display).with_context(|| {
                format!("Selected file is absent from the inventory: {display}")
            })?;
            Ok(DownloadQueueEntry {
                path: entry.path.clone(),
                size: entry.size,
                hash: entry.hash.clone(),
                hash_type: entry.hash_type.clone(),
                is_dir: entry.is_dir,
                remote_name: entry.remote_name.clone(),
            })
        })
        .collect::<Result<Vec<_>>>()?;
    let root = app
        .downloads_dir()
        .context("Case output is not initialized")?;
    plan_downloads(&entries, &source.default_remote, &known, &root)
}

pub(crate) fn perform_download_flow<
    B: ratatui::backend::Backend<Error: std::error::Error + Send + Sync + 'static>,
>(
    app: &mut App,
    terminal: &mut Terminal<B>,
) -> Result<()> {
    let result = (|| {
        app.unmount_remote();
        let source = app
            .acquisition
            .as_ref()
            .context("No acquisition source. List the remote again.")?
            .clone();
        let plan = prepare_plan(app)?;
        let binary = crate::embedded::ExtractedBinary::extract()?;
        let runner = crate::rclone::RcloneRunner::new(binary.path())
            .with_config(&source.config_path)
            .with_cancel_flag(app.shutdown.clone());
        execute_plan(app, terminal, plan, runner, Some(binary), true)
    })();
    if let Err(error) = result {
        app.download.status = format!("Acquisition failed: {error:#}");
        app.provider.status = app.download.status.clone();
        app.auth_status.clear();
        app.log_error(&app.download.status);
        app.state = AppState::FileList;
        terminal.draw(|frame| render_state(frame, app))?;
    }
    Ok(())
}

/// Runner injection permits complete offline tests without extracting rclone.
fn execute_plan<B: ratatui::backend::Backend<Error: std::error::Error + Send + Sync + 'static>>(
    app: &mut App,
    terminal: &mut Terminal<B>,
    plan: AcquisitionPlan,
    runner: crate::rclone::RcloneRunner,
    binary: Option<crate::embedded::ExtractedBinary>,
    poll_input: bool,
) -> Result<()> {
    let source = app
        .acquisition
        .as_ref()
        .context("No acquisition source")?
        .clone();
    let dirs = app
        .forensics
        .directories
        .as_ref()
        .context("No case directory")?
        .clone();
    if plan.files.is_empty() {
        anyhow::bail!("No files selected. Directories are not acquired recursively.");
    }
    let manifest_path = dirs.base.join("acquisition-manifest.json");
    // A retry must not erase the earlier plan, failures or completed-file evidence.
    if manifest_path.exists() {
        use std::io::Write;
        let mut archive = tempfile::Builder::new()
            .prefix("acquisition-prior-")
            .suffix(".json")
            .tempfile_in(&dirs.base)?;
        archive.write_all(&std::fs::read(&manifest_path)?)?;
        archive.as_file().sync_all()?;
        archive.keep().map_err(|error| error.error)?;
    }
    write_acquisition_manifest(&plan, &source.config_path, &[], &manifest_path)?;
    let mut queue = DownloadQueue::new();
    queue.set_verify_hashes(true);
    for file in &plan.files {
        if let Some(parent) = std::path::Path::new(&file.request.destination).parent() {
            std::fs::create_dir_all(parent)?;
        }
        queue.add(file.request.clone());
    }
    let displays = app
        .files
        .entries
        .iter()
        .enumerate()
        .filter_map(|(index, display)| {
            app.files.entries_full.get(index).map(|entry| {
                (
                    (
                        entry
                            .remote_name
                            .clone()
                            .unwrap_or_else(|| source.default_remote.clone()),
                        entry.path.clone(),
                    ),
                    display.clone(),
                )
            })
        })
        .collect::<HashMap<_, _>>();
    app.download.failures.clear();
    app.download.progress = (0, plan.files.len());
    app.download.current_bytes = None;
    app.download.done_bytes = 0;
    app.download.total_bytes = plan.files.iter().try_fold(0u64, |total, file| {
        file.request
            .expected_size
            .and_then(|size| total.checked_add(size))
    });
    app.download.status = format!("Acquiring {} files from {}", plan.files.len(), source.label);
    app.log_info(&app.download.status);
    app.state = AppState::Downloading;
    let initial_render = terminal
        .draw(|frame| render_state(frame, app))
        .map(|_| ())
        .map_err(anyhow::Error::from);

    // Even a disconnected terminal before the worker starts must finalize the
    // pending plan. A pre-cancelled queue records each request without spawning
    // rclone, then follows the same durable manifest/report path as later errors.
    let cancel = Arc::new(AtomicBool::new(initial_render.is_err()));
    let worker_cancel = cancel.clone();
    let (sender, receiver) = mpsc::sync_channel(64);
    let handle = std::thread::spawn(move || {
        let _binary_owner = binary;
        queue.download_all_with_progress_cancel(&runner, worker_cancel, |progress| {
            // Progress is replaceable; child output must not wait on terminal speed.
            let _ = sender.try_send(progress.clone());
        })
    });
    let mut job = DownloadJob {
        cancel,
        handle: Some(handle),
    };
    let mut bytes = vec![0u64; plan.files.len()];
    let mut completed = vec![false; plan.files.len()];
    let interaction_result: Result<()> = (|| {
        initial_render?;
        loop {
            while let Ok(progress) = receiver.try_recv() {
                apply_progress(app, &progress, &mut bytes, &mut completed);
            }
            if app.shutdown.load(Ordering::Relaxed) {
                job.cancel.store(true, Ordering::Relaxed);
            }
            if job
                .handle
                .as_ref()
                .is_some_and(|handle| handle.is_finished())
            {
                break;
            }
            if poll_input {
                if event::poll(Duration::from_millis(50))? {
                    if let Event::Key(key) = event::read()? {
                        if key.kind == KeyEventKind::Press
                            && (matches!(key.code, KeyCode::Esc | KeyCode::Char('q'))
                                || (key.code == KeyCode::Char('c')
                                    && key.modifiers.contains(KeyModifiers::CONTROL)))
                        {
                            job.cancel.store(true, Ordering::Relaxed);
                            app.download.status =
                                "Cancelling; waiting for child processes to stop...".into();
                            if key.code == KeyCode::Char('c') {
                                app.shutdown.store(true, Ordering::Relaxed);
                            }
                        }
                    }
                }
            } else if let Ok(progress) = receiver.recv_timeout(Duration::from_millis(25)) {
                apply_progress(app, &progress, &mut bytes, &mut completed);
            }
            terminal.draw(|frame| render_state(frame, app))?;
        }
        Ok(())
    })();
    if interaction_result.is_err() {
        job.cancel.store(true, Ordering::Relaxed);
    }
    let results = job
        .handle
        .take()
        .context("Download worker missing")?
        .join()
        .map_err(|_| anyhow::anyhow!("Download worker panicked"))?;
    write_acquisition_manifest(&plan, &source.config_path, &results, &manifest_path)?;
    let mut verified = 0usize;
    let mut successful = 0usize;
    for (file, result) in plan.files.iter().zip(&results) {
        let display = displays
            .get(&(file.remote_name.clone(), file.path.clone()))
            .cloned()
            .unwrap_or_else(|| format!("[{}] {}", file.remote_name, file.path));
        if result.success {
            successful += 1;
            if result.hash_verified == Some(true) {
                verified += 1;
            }
        } else {
            app.download.failures.push(display);
        }
        app.log_info(format!(
            "Acquisition {:?}: {} -> {} ({} bytes; {:?})",
            result.integrity,
            result.source,
            result.destination,
            result.size.unwrap_or(0),
            result.error
        ));
        // Mismatch bytes remain evidence, with their explicit verification status.
        if result.size.is_some() && std::path::Path::new(&result.destination).is_file() {
            app.track_file(
                &result.destination,
                format!("Acquired {}:{}", file.remote_name, file.path),
            );
            if let Some(case) = &mut app.forensics.case {
                case.add_download(crate::case::DownloadedFile {
                    path: file.path.clone(),
                    size: result.size.unwrap_or(0),
                    hash: result.hash.clone(),
                    hash_type: result.hash_type.clone(),
                    hash_verified: result.hash_verified,
                    hash_error: result.hash_error.clone(),
                    remote_name: Some(file.remote_name.clone()),
                });
            }
        }
    }
    if let Some(case) = &mut app.forensics.case {
        case.finalize();
    }
    let failures = app.download.failures.len();
    app.download.progress = (results.len(), plan.files.len());
    app.download.status = format!(
        "Acquired {}/{} files ({} source hashes verified, {} failed or cancelled)",
        successful,
        plan.files.len(),
        verified,
        failures
    );
    app.log_info(&app.download.status);
    app.log_info(format!(
        "Acquisition manifest written to {:?}",
        manifest_path
    ));
    write_reports(app)?;
    app.download.report_lines = vec![
        "=== Acquisition complete ===".into(),
        app.download.status.clone(),
        format!("Source: {}", source.label),
        format!("Destination: {}", dirs.downloads.display()),
        format!("Manifest: {}", manifest_path.display()),
        format!("Report: {}", dirs.report.display()),
        if failures > 0 {
            "Press r to retry failed files, or q to exit.".into()
        } else {
            "Press q to exit.".into()
        },
    ];
    app.state = AppState::Complete;
    // Terminal failure must not discard completed, partial or cancelled outcomes.
    interaction_result?;
    terminal.draw(|frame| render_state(frame, app))?;
    Ok(())
}

fn apply_progress(
    app: &mut App,
    progress: &DownloadProgress,
    bytes: &mut [u64],
    completed: &mut [bool],
) {
    if let Some(value) = bytes.get_mut(progress.current) {
        *value = progress.bytes_done.unwrap_or(*value);
    }
    if let Some(value) = completed.get_mut(progress.current) {
        *value |= matches!(
            progress.phase,
            DownloadPhase::Completed | DownloadPhase::Failed
        );
    }
    app.download.progress = (
        completed.iter().filter(|done| **done).count(),
        completed.len(),
    );
    app.download.done_bytes = bytes.iter().copied().fold(0u64, u64::saturating_add);
    app.download.current_bytes = progress.bytes_done.zip(progress.bytes_total);
    app.download.status = progress.status.clone();
}

fn write_reports(app: &App) -> Result<()> {
    let case = app.forensics.case.as_ref().context("No case initialized")?;
    let dirs = app
        .forensics
        .directories
        .as_ref()
        .context("No case directory")?;
    let state_diff = app.capture_final_state();
    let change_report = app
        .forensics
        .change_tracker
        .lock()
        .ok()
        .map(|tracker| tracker.generate_report());
    // A documented checkpoint: successful report writes do not append later log records.
    let checkpoint = app
        .forensics
        .logger
        .as_ref()
        .map(|logger| logger.checkpoint())
        .transpose()?;
    if let Some(checkpoint) = &checkpoint {
        std::fs::write(
            dirs.base.join("log-checkpoint.json"),
            serde_json::to_vec_pretty(checkpoint)?,
        )?;
    }
    let log_hash = checkpoint
        .as_ref()
        .map(|checkpoint| checkpoint.hash.as_str());
    let metadata = crate::case::report::ReportMetadata::from_environment();
    let report = crate::case::report::generate_report_with_metadata(
        case,
        state_diff.as_ref(),
        change_report.as_deref(),
        None,
        log_hash,
        Some(&metadata),
    );
    crate::case::report::write_report(&dirs.report, &report)?;
    crate::case::report::write_report_xlsx(
        dirs.base.join("forensic_report.xlsx"),
        case,
        state_diff.as_ref(),
        Some(&metadata),
    )?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ui::AcquisitionSource;

    fn local_fixture() -> (tempfile::TempDir, App, std::path::PathBuf) {
        let temp = tempfile::tempdir().unwrap();
        let first = temp.path().join("source-a");
        let second = temp.path().join("source-b");
        std::fs::create_dir_all(&first).unwrap();
        std::fs::create_dir_all(&second).unwrap();
        std::fs::write(first.join("same.txt"), b"alpha").unwrap();
        std::fs::write(second.join("same.txt"), b"beta").unwrap();
        let source_config = temp.path().join("original.conf");
        std::fs::write(&source_config, format!("[accountA]\ntype = alias\nremote = {}\n[accountB]\ntype = alias\nremote = {}\n[_triage_combined]\ntype = local\n", first.display(), second.display())).unwrap();
        let original_bytes = std::fs::read(&source_config).unwrap();
        let mut app = App::with_case_settings("named-case".into(), temp.path().join("cases"));
        app.init_case(app.case_output_dir.clone()).unwrap();
        let snapshot = crate::ui::flows::list::working_config(&mut app, &source_config).unwrap();
        let config = crate::rclone::RcloneConfig::open_existing(&snapshot).unwrap();
        let remotes = vec!["accountA".into(), "accountB".into()];
        let generated = crate::rclone::combine::create_combine_remote(&config, &remotes).unwrap();
        assert_ne!(generated, "_triage_combined");
        assert_eq!(std::fs::read(&source_config).unwrap(), original_bytes);
        app.generated_combines
            .push((snapshot.clone(), generated.clone()));
        app.acquisition = Some(AcquisitionSource {
            config_path: snapshot,
            default_remote: generated,
            label: "two accounts".into(),
        });
        (temp, app, source_config)
    }

    fn injected_runner(
        temp: &std::path::Path,
        config: &std::path::Path,
    ) -> (
        crate::rclone::RcloneRunner,
        Option<crate::embedded::ExtractedBinary>,
    ) {
        #[cfg(windows)]
        {
            let _ = temp;
            let binary = crate::embedded::ExtractedBinary::extract().unwrap();
            (
                crate::rclone::RcloneRunner::new(binary.path()).with_config(config),
                Some(binary),
            )
        }
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let path = temp.join("fake-rclone");
            std::fs::write(&path, r#"#!/bin/sh
set -eu
if [ "${1-}" = "--config" ]; then shift 2; fi
case "$1" in
  lsjson)
    if [ "${2-}" = "--stat" ]; then
      printf '{"IsDir":false}'
    else
      printf '[{"Path":"accountA/same.txt","Size":5,"IsDir":false},{"Path":"accountB/same.txt","Size":4,"IsDir":false},{"Path":"accountA","Size":0,"IsDir":true}]'
    fi ;;
  rc)
    [ "${2-}" = "--loopback" ] && [ "${3-}" = "operations/copyfile" ] || {
      printf 'unsupported RC operation\n' >&2; exit 7;
    }
    shift 3
    src_fs= src_remote= dst_fs= dst_remote=
    for argument do
      case "$argument" in
        srcFs=*) src_fs=${argument#srcFs=} ;;
        srcRemote=*) src_remote=${argument#srcRemote=} ;;
        dstFs=*) dst_fs=${argument#dstFs=} ;;
        dstRemote=*) dst_remote=${argument#dstRemote=} ;;
      esac
    done
    [ "$src_remote" = 'same.txt' ] && [ "$dst_remote" = 'payload' ] && [ -d "$dst_fs" ] || {
      printf 'invalid object or staging destination\n' >&2; exit 7;
    }
    case "$src_fs" in
      accountA:) printf alpha > "$dst_fs/$dst_remote" ;;
      accountB:) printf beta > "$dst_fs/$dst_remote" ;;
      *) printf 'unknown source filesystem\n' >&2; exit 7 ;;
    esac
    printf '{}\n' ;;
  *) printf 'unexpected rclone operation\n' >&2; exit 8 ;;
esac
"#).unwrap();
            std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o700)).unwrap();
            (
                crate::rclone::RcloneRunner::new(path).with_config(config),
                None,
            )
        }
    }

    #[test]
    fn external_config_listing_selection_acquisition_preserves_source_and_checkpoint() {
        let (temp, mut app, source_config) = local_fixture();
        let original = std::fs::read(&source_config).unwrap();
        let source = app.acquisition.clone().unwrap();
        let (runner, binary) = injected_runner(temp.path(), &source.config_path);
        let entries = crate::files::list_path(
            &runner,
            &format!("{}:", source.default_remote),
            crate::files::ListPathOptions::without_hashes(),
        )
        .unwrap();
        let (_, receiver) = mpsc::channel();
        app.listing_task = Some(crate::ui::ListingTask {
            handle: std::thread::spawn(|| {}),
            progress_rx: receiver,
            cancel: Arc::new(AtomicBool::new(false)),
            started: std::time::Instant::now(),
            count: 0,
            context: crate::ui::ListingContext {
                remote_name: source.default_remote,
                remote_type: "combine".into(),
                combine_remotes: vec!["accountA".into(), "accountB".into()],
                include_hashes: false,
                config_path: source.config_path,
                listing_csv: None,
            },
        });
        crate::ui::flows::list::finalize_listing(&mut app, entries);
        assert!(app.provider.chosen.is_none());
        app.select_all_files();
        assert_eq!(app.files.to_download.len(), 2);
        let plan = prepare_plan(&app).unwrap();
        let destinations = plan
            .files
            .iter()
            .map(|file| file.request.destination.clone())
            .collect::<Vec<_>>();
        let mut terminal = Terminal::new(ratatui::backend::TestBackend::new(100, 30)).unwrap();
        execute_plan(&mut app, &mut terminal, plan, runner, binary, false).unwrap();
        assert_eq!(app.state, AppState::Complete);
        let dirs = app.forensics.directories.as_ref().unwrap();
        let manifest: serde_json::Value = serde_json::from_slice(
            &std::fs::read(dirs.base.join("acquisition-manifest.json")).unwrap(),
        )
        .unwrap();
        assert!(
            app.download.failures.is_empty(),
            "Failed files: {:?}; outcomes: {}",
            app.download.failures,
            manifest["results"]
        );
        assert_eq!(std::fs::read(&destinations[0]).unwrap(), b"alpha");
        assert_eq!(std::fs::read(&destinations[1]).unwrap(), b"beta");
        assert_eq!(std::fs::read(&source_config).unwrap(), original);
        assert_eq!(dirs.base, temp.path().join("cases").join("named-case"));
        assert_eq!(manifest["results"].as_array().unwrap().len(), 2);
        assert!(manifest["results"][0]["local_sha256"].is_string());
        let checkpoint: crate::forensics::logger::LogCheckpoint =
            serde_json::from_slice(&std::fs::read(dirs.base.join("log-checkpoint.json")).unwrap())
                .unwrap();
        assert!(crate::forensics::logger::ForensicLogger::verify_checkpoint(
            &dirs.logs.join("rclone-triage.log"),
            &checkpoint
        )
        .unwrap());
        drop(app);
        assert_eq!(std::fs::read(source_config).unwrap(), original);
    }

    #[test]
    fn cancelled_acquisition_retains_manifest_and_retry_selection() {
        let (_temp, mut app, _) = local_fixture();
        app.files.entries = vec!["same.txt".into()];
        app.files.entries_full = vec![crate::files::FileEntry {
            path: "same.txt".into(),
            size: Some(5),
            modified: None,
            is_dir: false,
            hash: None,
            hash_type: None,
            remote_name: Some("accountA".into()),
        }];
        app.rebuild_file_index();
        app.state = AppState::FileList;
        app.select_all_files();
        app.shutdown.store(true, Ordering::Relaxed);
        let runner = crate::rclone::RcloneRunner::new("must-not-be-executed")
            .with_cancel_flag(app.shutdown.clone());
        let plan = prepare_plan(&app).unwrap();
        let mut terminal = Terminal::new(ratatui::backend::TestBackend::new(100, 30)).unwrap();
        execute_plan(&mut app, &mut terminal, plan, runner, None, false).unwrap();
        assert_eq!(app.download.failures, vec!["same.txt"]);
        assert_eq!(app.state, AppState::Complete);
        let dirs = app.forensics.directories.as_ref().unwrap();
        let manifest: serde_json::Value = serde_json::from_slice(
            &std::fs::read(dirs.base.join("acquisition-manifest.json")).unwrap(),
        )
        .unwrap();
        assert_eq!(manifest["results"][0]["integrity"], "Cancelled");
    }

    #[test]
    fn terminal_failure_still_persists_every_acquisition_outcome() {
        struct FailingOutput {
            flushes: usize,
        }
        impl std::io::Write for FailingOutput {
            fn write(&mut self, bytes: &[u8]) -> std::io::Result<usize> {
                Ok(bytes.len())
            }
            fn flush(&mut self) -> std::io::Result<()> {
                self.flushes += 1;
                if self.flushes > 1 {
                    Err(std::io::Error::other("terminal disconnected"))
                } else {
                    Ok(())
                }
            }
        }
        let (temp, mut app, _) = local_fixture();
        app.files.entries = vec!["same.txt".into()];
        app.files.entries_full = vec![crate::files::FileEntry {
            path: "same.txt".into(),
            size: Some(5),
            modified: None,
            is_dir: false,
            hash: None,
            hash_type: None,
            remote_name: Some("accountA".into()),
        }];
        app.rebuild_file_index();
        app.state = AppState::FileList;
        app.select_all_files();
        let plan = prepare_plan(&app).unwrap();
        let source = app.acquisition.as_ref().unwrap();
        let (runner, binary) = injected_runner(temp.path(), &source.config_path);
        let backend = ratatui::backend::CrosstermBackend::new(FailingOutput { flushes: 0 });
        let mut terminal = Terminal::with_options(
            backend,
            ratatui::TerminalOptions {
                viewport: ratatui::Viewport::Fixed(ratatui::layout::Rect::new(0, 0, 100, 30)),
            },
        )
        .unwrap();
        let error = execute_plan(&mut app, &mut terminal, plan, runner, binary, false).unwrap_err();
        assert!(error.to_string().contains("terminal disconnected"));
        let dirs = app.forensics.directories.as_ref().unwrap();
        let manifest: serde_json::Value = serde_json::from_slice(
            &std::fs::read(dirs.base.join("acquisition-manifest.json")).unwrap(),
        )
        .unwrap();
        assert_eq!(manifest["results"].as_array().unwrap().len(), 1);
        assert!(dirs.base.join("log-checkpoint.json").is_file());
    }

    #[test]
    fn external_config_plan_keeps_remote_identity_without_provider_selection() {
        let temp = tempfile::tempdir().unwrap();
        let config = temp.path().join("external.conf");
        std::fs::write(
            &config,
            "[accountA]\ntype = local\n[accountB]\ntype = local\n",
        )
        .unwrap();
        let mut app = App::with_case_settings("case".into(), temp.path().into());
        app.init_case(temp.path().into()).unwrap();
        app.acquisition = Some(AcquisitionSource {
            config_path: config,
            default_remote: "accountA".into(),
            label: "accounts".into(),
        });
        for remote in ["accountA", "accountB"] {
            app.files.entries.push(format!("[{remote}] same.txt"));
            app.files.entries_full.push(crate::files::FileEntry {
                path: "same.txt".into(),
                size: None,
                modified: None,
                is_dir: false,
                hash: None,
                hash_type: None,
                remote_name: Some(remote.into()),
            });
        }
        app.rebuild_file_index();
        app.state = AppState::FileList;
        app.select_all_files();
        let plan = prepare_plan(&app).unwrap();
        assert!(app.provider.chosen.is_none());
        assert_eq!(plan.files.len(), 2);
        assert_eq!(plan.files[0].request.source, "accountA:same.txt");
        assert_eq!(plan.files[1].request.source, "accountB:same.txt");
        assert_ne!(
            plan.files[0].request.destination,
            plan.files[1].request.destination
        );
        assert_eq!(plan.files[0].request.expected_size, None);
    }
}
