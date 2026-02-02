//! rclone-triage: Cloud Triage Tool
//!
//! A single-file Windows executable that embeds rclone and provides
//! a TUI interface for cloud data acquisition.

mod case;
mod cleanup;
mod embedded;
mod files;
mod forensics;
mod providers;
mod rclone;
mod ui;

use crate::case::Case;
use crate::files::list_path;
use crate::forensics::state::SystemStateSnapshot;
use crate::providers::{auth::authenticate_with_rclone, CloudProvider};
use crate::rclone::{RcloneConfig, RcloneRunner};
use crate::ui::App as TuiApp;
use anyhow::Result;
use clap::Parser;
use cleanup::Cleanup;

fn main() -> Result<()> {
    println!("rclone-triage v{}", env!("CARGO_PKG_VERSION"));

    let args = Cli::parse();
    let mut app_guard = AppGuard::new();

    // Capture initial system state before any operations
    let initial_state = SystemStateSnapshot::capture("Initial state before session").ok();

    // Ctrl+C handler for graceful shutdown
    {
        let mut cleanup = app_guard.cleanup.clone_for_signal();
        let _ = ctrlc::set_handler(move || {
            let _ = cleanup.execute();
            std::process::exit(130);
        });
    }

    // Verify embedded binary
    embedded::verify_embedded_binary()?;

    // Extract embedded rclone
    let binary = embedded::ExtractedBinary::extract()?;
    app_guard.cleanup.track_file(binary.path());

    // Initialize session
    let case = Case::new(&args.name, args.output_dir.clone())?;
    println!("Session initialized: {}", case.session_id());

    // Optional TUI loop
    if args.tui {
        let mut app = TuiApp::new();
        crate::ui::runner::run_loop(&mut app)?;
        return Ok(());
    }

    // Minimal auth + listing wiring (CLI-driven)
    if let Some(provider) = args.provider {
        println!("Authenticating {}...", provider);
        let config = RcloneConfig::for_case(&case.output_dir)?;
        let runner = RcloneRunner::new(binary.path()).with_config(config.path());

        let remote_name = provider.short_name();
        let _auth = authenticate_with_rclone(provider, &runner, &config, remote_name)?;

        let listing = list_path(&runner, &format!("{}:", remote_name))?;
        println!("Listed {} entries", listing.len());
    }

    // Capture final state and report if verbose
    if let Some(initial) = initial_state {
        if let Ok(final_state) = SystemStateSnapshot::capture("Final state after session") {
            let diff = initial.diff(&final_state);
            if diff.has_changes() {
                println!("\nSystem state changes detected:");
                println!("{}", diff.generate_report());
            }
        }
    }

    Ok(())
}

/// Ensures cleanup is run on drop
struct AppGuard {
    cleanup: Cleanup,
}

impl AppGuard {
    fn new() -> Self {
        Self {
            cleanup: Cleanup::new(),
        }
    }
}

impl Drop for AppGuard {
    fn drop(&mut self) {
        let _ = self.cleanup.execute();
    }
}

/// CLI arguments
#[derive(Parser, Debug)]
#[command(author, version, about = "Cloud triage tool")]
struct Cli {
    /// Session name (folder name for output). Defaults to triage-YYYYMMDD-HHMMSS
    #[arg(long, short, default_value = "")]
    name: String,
    /// Output directory
    #[arg(long, short = 'o', default_value = ".")]
    output_dir: std::path::PathBuf,

    /// Cloud provider to authenticate (e.g., gdrive, onedrive, dropbox)
    #[arg(long)]
    provider: Option<CloudProvider>,

    /// Launch interactive TUI
    #[arg(long, default_value_t = false)]
    tui: bool,
}
