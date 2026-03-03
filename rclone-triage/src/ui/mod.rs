//! TUI application state machine
//!
//! Defines the core application state and transitions used by the UI.

use crate::case::directory::CaseDirectories;
use crate::case::Case;
use crate::cleanup::Cleanup;
use crate::forensics::changes::ChangeTracker;
use crate::forensics::logger::ForensicLogger;
use crate::forensics::state::SystemStateSnapshot;
use crate::providers::browser::Browser;
use crate::providers::{CloudProvider, ProviderEntry};
use crate::rclone::MountedRemote;
use anyhow::{Context, Result};
use chrono::{DateTime, Local};
use std::path::PathBuf;
use std::sync::atomic::AtomicBool;
use std::sync::{mpsc, Arc, Mutex};
use std::thread::JoinHandle;
use std::time::Instant;

pub mod flows;
pub mod layout;
pub mod prompt;
pub mod render;
pub mod runner;
pub mod screens;
pub mod widgets;

/// Application states for the TUI flow
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AppState {
    MainMenu,
    AdditionalOptions,
    OneDriveMenu,
    ProviderSelect,
    ConfigBrowser,
    Listing,
    RemoteSelect,
    MobileAuthFlow,
    BrowserSelect,
    Authenticating,
    PostAuthChoice,
    Mounted,
    FileList,
    Downloading,
    OAuthCredentials,
    Complete,
}

impl AppState {
    /// Get the next logical state in the flow
    pub fn next(self) -> Self {
        match self {
            AppState::MainMenu => AppState::ProviderSelect,
            AppState::AdditionalOptions => AppState::AdditionalOptions,
            AppState::OneDriveMenu => AppState::OneDriveMenu,
            AppState::ProviderSelect => AppState::BrowserSelect,
            AppState::ConfigBrowser => AppState::Listing,
            AppState::Listing => AppState::FileList,
            AppState::RemoteSelect => AppState::RemoteSelect,
            AppState::MobileAuthFlow => AppState::Authenticating,
            AppState::BrowserSelect => AppState::Authenticating,
            AppState::Authenticating => AppState::PostAuthChoice,
            AppState::PostAuthChoice => AppState::FileList,
            AppState::Mounted => AppState::Complete,
            AppState::FileList => AppState::Downloading,
            AppState::Downloading => AppState::Complete,
            AppState::OAuthCredentials => AppState::OAuthCredentials,
            AppState::Complete => AppState::Complete,
        }
    }

    /// Get the previous logical state in the flow
    pub fn previous(self) -> Self {
        match self {
            AppState::MainMenu => AppState::MainMenu,
            AppState::AdditionalOptions => AppState::MainMenu,
            AppState::OneDriveMenu => AppState::AdditionalOptions,
            AppState::ProviderSelect => AppState::MainMenu,
            AppState::ConfigBrowser => AppState::MainMenu,
            AppState::Listing => AppState::ConfigBrowser,
            AppState::RemoteSelect => AppState::ProviderSelect,
            AppState::MobileAuthFlow => AppState::ProviderSelect,
            AppState::BrowserSelect => AppState::ProviderSelect,
            AppState::Authenticating => AppState::BrowserSelect,
            AppState::PostAuthChoice => AppState::Authenticating,
            AppState::Mounted => AppState::PostAuthChoice,
            AppState::FileList => AppState::PostAuthChoice,
            AppState::Downloading => AppState::FileList,
            AppState::OAuthCredentials => AppState::AdditionalOptions,
            AppState::Complete => AppState::Downloading,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MobileAuthFlow {
    Redirect,
    RedirectWithAccessPoint,
    DeviceCode,
}

/// What to do after successful authentication.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PostAuthAction {
    /// List all files recursively to CSV, then show in TUI.
    ListToCsv,
    /// Mount the remote as a drive and open file explorer.
    MountAndBrowse,
    /// Skip listing entirely and go to the file list (empty).
    SkipToFileList,
    /// Go back to provider select to authenticate another remote.
    AddAnotherProvider,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MenuAction {
    Authenticate,
    RetrieveList,
    DownloadFromCsv,
    MountProvider,
    SmartAuth,
    MobileAuth,
    AdditionalOptions,
    UpdateTools,
    ConfigureOAuth,
    ShowOAuthCredentials,
    ExportBrowserSessions,
    ExportDomainCookies,
    StartWebGui,
    OneDriveMenu,
    OpenOneDriveVault,
    BackToAdditionalOptions,
    BackToMainMenu,
    BackToProviders,
    MobileAuthRedirect,
    MobileAuthRedirectWithAp,
    MobileAuthDeviceCode,
    Exit,
}

#[derive(Debug, Clone)]
pub struct MenuItem {
    pub label: &'static str,
    pub description: &'static str,
    pub action: MenuAction,
}

/// Move a list cursor up with wrapping.
fn list_navigate_up(selected: &mut usize, len: usize) {
    if len == 0 {
        return;
    }
    *selected = if *selected == 0 { len - 1 } else { *selected - 1 };
}

/// Move a list cursor down with wrapping.
fn list_navigate_down(selected: &mut usize, len: usize) {
    if len == 0 {
        return;
    }
    *selected = (*selected + 1) % len;
}

/// Provider selection state
pub struct ProviderSelection {
    /// Available providers
    pub entries: Vec<ProviderEntry>,
    /// Currently highlighted index
    pub selected: usize,
    /// Status message for this screen
    pub status: String,
    /// Multi-select checkboxes
    pub checked: Vec<bool>,
    /// Show help overlay
    pub show_help: bool,
    /// Timestamp of last refresh
    pub last_updated: Option<DateTime<Local>>,
    /// Last refresh error
    pub last_error: Option<String>,
    /// Confirmed provider choice
    pub chosen: Option<ProviderEntry>,
}

/// Browser selection state
pub struct BrowserSelection {
    /// Detected browsers
    pub entries: Vec<Browser>,
    /// Currently highlighted index (0 = system default)
    pub selected: usize,
    /// Multi-select checkboxes
    pub checked: Vec<bool>,
    /// Confirmed browser choice (None = system default)
    pub chosen: Option<Browser>,
}

/// Remote selection state
pub struct RemoteSelection {
    /// Available remote names
    pub options: Vec<String>,
    /// Currently highlighted index
    pub selected: usize,
    /// Multi-select checkboxes (for combining multiple remotes)
    pub checked: Vec<bool>,
    /// Confirmed remote choice (single-select mode)
    pub chosen: Option<String>,
    /// Confirmed multi-select choices (combine mode)
    pub chosen_multiple: Vec<String>,
}

/// File listing and selection state
pub struct FileSelection {
    /// File paths for display
    pub entries: Vec<String>,
    /// Full file entries with hash info
    pub entries_full: Vec<crate::files::FileEntry>,
    /// Currently highlighted index
    pub selected: usize,
    /// Paths marked for download
    pub to_download: Vec<String>,
}

/// Download progress state
pub struct DownloadProgress {
    /// Status message
    pub status: String,
    /// (current_file, total_files)
    pub progress: (usize, usize),
    /// Current file bytes (done, total)
    pub current_bytes: Option<(u64, u64)>,
    /// Total bytes across all selected files
    pub total_bytes: Option<u64>,
    /// Bytes completed so far
    pub done_bytes: u64,
    /// Paths that failed
    pub failures: Vec<String>,
    /// Final report lines
    pub report_lines: Vec<String>,
}

/// Progress update sent from a background listing thread.
pub enum ListingProgress {
    /// Number of entries found so far.
    Count(usize),
    /// Listing finished successfully with entries.
    Done(Vec<crate::files::FileEntry>),
    /// Listing failed.
    Error(String),
}

/// Context needed to finalize listing results (export, state transition).
pub struct ListingContext {
    /// The remote name being listed.
    pub remote_name: String,
    /// The remote type (e.g. "drive", "onedrive").
    pub remote_type: String,
    /// Raw remote names when using a combine remote.
    pub combine_remotes: Vec<String>,
    /// Whether hashes were requested.
    pub include_hashes: bool,
    /// Path to the config file used.
    pub config_path: PathBuf,
}

/// A background listing task with cancellation support.
pub struct ListingTask {
    /// Thread handle for the listing worker.
    pub handle: JoinHandle<()>,
    /// Receives progress updates from the worker.
    pub progress_rx: mpsc::Receiver<ListingProgress>,
    /// Flag to signal cancellation; checked by the worker.
    pub cancel: Arc<AtomicBool>,
    /// When the listing started.
    pub started: Instant,
    /// Number of entries found so far (for display).
    pub count: usize,
    /// Context needed to finalize the listing.
    pub context: ListingContext,
}

/// An entry in the config file browser
#[derive(Debug, Clone)]
pub struct ConfigBrowserEntry {
    pub name: String,
    pub path: PathBuf,
    pub is_dir: bool,
    pub size: Option<u64>,
}

/// State for the config file browser screen
pub struct ConfigBrowserState {
    /// Current directory being browsed
    pub current_dir: PathBuf,
    /// Directory entries (dirs first, then files)
    pub entries: Vec<ConfigBrowserEntry>,
    /// Currently highlighted index
    pub selected: usize,
    /// Status/error messages
    pub status: String,
    /// Preview of remotes in the selected config file
    pub preview: Vec<String>,
    /// Path of the selected config file (set on Enter)
    pub selected_config: Option<PathBuf>,
    /// Listing error with user-friendly explanation and next steps
    pub last_error: Option<String>,
}

impl Default for ConfigBrowserState {
    fn default() -> Self {
        Self::new()
    }
}

impl ConfigBrowserState {
    pub fn new() -> Self {
        // Try common config locations in order
        let start_dir = dirs_path_or_cwd();
        let mut state = Self {
            current_dir: start_dir.clone(),
            entries: Vec::new(),
            selected: 0,
            status: String::new(),
            preview: Vec::new(),
            selected_config: None,
            last_error: None,
        };
        state.load_entries(&start_dir);
        state
    }

    pub fn from_dir(dir: PathBuf) -> Self {
        let mut state = Self {
            current_dir: dir.clone(),
            entries: Vec::new(),
            selected: 0,
            status: String::new(),
            preview: Vec::new(),
            selected_config: None,
            last_error: None,
        };
        state.load_entries(&dir);
        state
    }

    pub fn load_entries(&mut self, dir: &std::path::Path) {
        self.entries.clear();
        self.selected = 0;
        self.preview.clear();

        let read_dir = match std::fs::read_dir(dir) {
            Ok(rd) => rd,
            Err(e) => {
                self.status = format!("Cannot read directory: {}", e);
                return;
            }
        };

        let mut dirs = Vec::new();
        let mut files = Vec::new();

        for entry in read_dir.flatten() {
            let path = entry.path();
            let name = entry.file_name().to_string_lossy().to_string();
            // Skip hidden files
            if name.starts_with('.') {
                continue;
            }
            let metadata = entry.metadata().ok();
            let is_dir = metadata.as_ref().is_some_and(|m| m.is_dir());
            let size = metadata.as_ref().and_then(|m| if m.is_file() { Some(m.len()) } else { None });
            let entry = ConfigBrowserEntry {
                name,
                path,
                is_dir,
                size,
            };
            if is_dir {
                dirs.push(entry);
            } else {
                files.push(entry);
            }
        }

        dirs.sort_by(|a, b| a.name.to_lowercase().cmp(&b.name.to_lowercase()));
        files.sort_by(|a, b| a.name.to_lowercase().cmp(&b.name.to_lowercase()));

        // Always prepend . and .. navigation entries so the user sees
        // where they are—even in empty directories.
        let parent_path = dir.parent().unwrap_or(dir).to_path_buf();
        self.entries.push(ConfigBrowserEntry {
            name: ".".to_string(),
            path: dir.to_path_buf(),
            is_dir: true,
            size: None,
        });
        self.entries.push(ConfigBrowserEntry {
            name: "..".to_string(),
            path: parent_path,
            is_dir: true,
            size: None,
        });

        self.entries.extend(dirs);
        self.entries.extend(files);
        self.current_dir = dir.to_path_buf();
        let real_count = self.entries.len().saturating_sub(2);
        self.status = format!("{} items", real_count);
    }

    pub fn navigate_up(&mut self) {
        list_navigate_up(&mut self.selected, self.entries.len());
        self.update_preview();
    }

    pub fn navigate_down(&mut self) {
        list_navigate_down(&mut self.selected, self.entries.len());
        self.update_preview();
    }

    pub fn enter_selected(&mut self) -> Option<PathBuf> {
        let entry = self.entries.get(self.selected)?.clone();
        if entry.name == "." {
            // Refresh current directory
            let cur = self.current_dir.clone();
            self.load_entries(&cur);
            return None;
        }
        if entry.name == ".." {
            self.go_parent();
            return None;
        }
        if entry.is_dir {
            self.load_entries(&entry.path);
            None
        } else {
            // Return the selected file path
            self.selected_config = Some(entry.path.clone());
            Some(entry.path)
        }
    }

    pub fn go_parent(&mut self) {
        if let Some(parent) = self.current_dir.parent() {
            let parent = parent.to_path_buf();
            self.load_entries(&parent);
        }
    }

    pub fn update_preview(&mut self) {
        self.preview.clear();
        if let Some(entry) = self.entries.get(self.selected) {
            if !entry.is_dir {
                // Try to parse as rclone config to show remotes
                if let Ok(content) = std::fs::read_to_string(&entry.path) {
                    let parsed = crate::rclone::config::ParsedConfig::parse(&content);
                    if !parsed.remotes.is_empty() {
                        self.preview.push(format!("Remotes ({})", parsed.remotes.len()));
                        for remote in &parsed.remotes {
                            self.preview
                                .push(format!("  {} ({})", remote.name, remote.remote_type));
                        }
                    } else {
                        self.preview.push("No remotes found in file".to_string());
                    }
                }
            }
        }
    }
}

fn dirs_path_or_cwd() -> PathBuf {
    // Try ~/.config/rclone/ first
    if let Some(config_dir) = dirs::config_dir() {
        let rclone_dir = config_dir.join("rclone");
        if rclone_dir.is_dir() {
            return rclone_dir;
        }
    }
    std::env::current_dir().unwrap_or_else(|_| PathBuf::from("."))
}

/// Forensic context (case, logging, cleanup, change tracking)
pub struct ForensicsContext {
    /// Case metadata
    pub case: Option<Case>,
    /// Case directory structure
    pub directories: Option<CaseDirectories>,
    /// Hash-chained forensic logger
    pub logger: Option<Arc<ForensicLogger>>,
    /// Cleanup manager (shared with main)
    pub cleanup: Option<Arc<Mutex<Cleanup>>>,
    /// System state captured at session start
    pub initial_state: Option<SystemStateSnapshot>,
    /// Tracks all modifications made during session
    pub change_tracker: Arc<Mutex<ChangeTracker>>,
}

/// Core application state container
pub struct App {
    /// Current application state
    pub state: AppState,
    /// Main menu items
    pub menu_items: Vec<MenuItem>,
    /// Selected menu index
    pub menu_selected: usize,
    /// Selected menu action (persists across flow)
    pub selected_action: Option<MenuAction>,
    /// Additional options menu items
    pub additional_menu_items: Vec<MenuItem>,
    /// Selected additional menu index
    pub additional_menu_selected: usize,
    /// OneDrive menu items
    pub onedrive_menu_items: Vec<MenuItem>,
    /// Selected OneDrive menu index
    pub onedrive_menu_selected: usize,
    /// Mobile auth flow menu items
    pub mobile_flow_items: Vec<MenuItem>,
    /// Selected mobile auth flow index
    pub mobile_flow_selected: usize,
    /// Selected mobile auth flow choice
    pub mobile_auth_flow: Option<MobileAuthFlow>,
    /// Menu status message (shown in footer)
    pub menu_status: String,
    pub exit_requested: bool,
    /// Auth status message
    pub auth_status: String,
    /// SSO status for currently selected provider
    pub sso_status: Option<crate::providers::auth::SsoStatus>,
    /// Post-auth action choice (persisted across state transitions)
    pub post_auth_selected: usize,
    pub post_auth_action: Option<PostAuthAction>,
    /// Mounted remote for GUI selection
    pub mounted_remote: Option<MountedRemote>,
    /// Running Web GUI process (kept alive while TUI is open)
    pub web_gui_process: Option<crate::rclone::WebGuiProcess>,
    /// Remotes authenticated in this session: (remote_name, provider_display_name)
    pub authenticated_remotes: Vec<(String, String)>,
    /// Whether a combine remote was created (needs cleanup on exit)
    pub combine_remote_created: bool,
    /// Provider selection state
    pub provider: ProviderSelection,
    /// Browser selection state
    pub browser: BrowserSelection,
    /// Remote selection state
    pub remote: RemoteSelection,
    /// File listing and selection state
    pub files: FileSelection,
    /// Download progress state
    pub download: DownloadProgress,
    /// Config file browser state
    pub config_browser: ConfigBrowserState,
    /// Background listing task (non-blocking rclone lsjson)
    pub listing_task: Option<ListingTask>,
    /// Forensic context
    pub forensics: ForensicsContext,
}

impl App {
    /// Create a new app with the initial state
    pub fn new() -> Self {
        // Capture initial system state before any operations
        let initial_state = SystemStateSnapshot::capture("Initial state before session").ok();

        let menu_items = Self::default_menu_items();
        let additional_menu_items = Self::additional_menu_items();
        let onedrive_menu_items = Self::onedrive_menu_items();
        let mobile_flow_items = Self::mobile_flow_items();
        let mut providers = CloudProvider::entries();
        ProviderEntry::sort_entries(&mut providers);
        let providers_len = providers.len();
        let provider_status = format!(
            "Using built-in providers ({}). Press 'r' to refresh.",
            providers_len
        );
        let browser_list = crate::providers::auth::get_available_browsers();

        Self {
            state: AppState::MainMenu,
            menu_items,
            menu_selected: 0,
            selected_action: None,
            additional_menu_items,
            additional_menu_selected: 0,
            onedrive_menu_items,
            onedrive_menu_selected: 0,
            mobile_flow_items,
            mobile_flow_selected: 0,
            mobile_auth_flow: None,
            menu_status: String::new(),
            exit_requested: false,
            auth_status: String::new(),
            sso_status: None,
            post_auth_selected: 0,
            post_auth_action: None,
            mounted_remote: None,
            web_gui_process: None,
            authenticated_remotes: Vec::new(),
            combine_remote_created: false,
            provider: ProviderSelection {
                entries: providers,
                selected: 0,
                status: provider_status,
                checked: vec![false; providers_len],
                show_help: false,
                last_updated: None,
                last_error: None,
                chosen: None,
            },
            browser: BrowserSelection {
                entries: browser_list.clone(),
                selected: 0,
                checked: vec![false; browser_list.len() + 1],
                chosen: None,
            },
            remote: RemoteSelection {
                options: Vec::new(),
                selected: 0,
                checked: Vec::new(),
                chosen: None,
                chosen_multiple: Vec::new(),
            },
            files: FileSelection {
                entries: Vec::new(),
                entries_full: Vec::new(),
                selected: 0,
                to_download: Vec::new(),
            },
            download: DownloadProgress {
                status: String::new(),
                progress: (0, 0),
                current_bytes: None,
                total_bytes: None,
                done_bytes: 0,
                failures: Vec::new(),
                report_lines: Vec::new(),
            },
            config_browser: ConfigBrowserState::new(),
            listing_task: None,
            forensics: ForensicsContext {
                case: None,
                directories: None,
                logger: None,
                cleanup: None,
                initial_state,
                change_tracker: Arc::new(Mutex::new(ChangeTracker::new())),
            },
        }
    }

    fn default_menu_items() -> Vec<MenuItem> {
        vec![
            MenuItem {
                label: "Authenticate with the chosen Browsers & Providers (TO BE RUN ON SUSPECT DEVICE)",
                description: "Launch browser-based authentication on the suspect device for selected providers.",
                action: MenuAction::Authenticate,
            },
            MenuItem {
                label: "Retrieve a list of Files from an authenticated config (RUN AT OFFICE OR YOUR DEVICE)",
                description: "List remote files using an authenticated config to prepare exports and triage.",
                action: MenuAction::RetrieveList,
            },
            MenuItem {
                label: "Download Files from a CSV/xlsx (RUN AT OFFICE OR YOUR DEVICE)",
                description: "Download specific files using a CSV/XLSX selection created during triage.",
                action: MenuAction::DownloadFromCsv,
            },
            MenuItem {
                label: "Mount cloud provider as a Network Share",
                description: "Mount a remote as a drive to browse files in the OS file manager.",
                action: MenuAction::MountProvider,
            },
            MenuItem {
                label: "Silent/Smart Authentication (SSO)",
                description: "Attempt SSO auth; fall back to interactive if needed.",
                action: MenuAction::SmartAuth,
            },
            MenuItem {
                label: "Authenticate from Mobile Device (QR Code)",
                description: "Authenticate via mobile device using QR or device code flows.",
                action: MenuAction::MobileAuth,
            },
            MenuItem {
                label: "Additional Options",
                description: "Update tools, configure OAuth credentials, OneDrive utilities.",
                action: MenuAction::AdditionalOptions,
            },
            MenuItem {
                label: "Exit",
                description: "Exit the application.",
                action: MenuAction::Exit,
            },
        ]
    }

    fn additional_menu_items() -> Vec<MenuItem> {
        vec![
            MenuItem {
                label: "Update Tools",
                description: "Update rclone and bundled dependencies.",
                action: MenuAction::UpdateTools,
            },
            MenuItem {
                label: "Configure OAuth Client Credentials",
                description: "Enter custom OAuth credentials for rclone providers.",
                action: MenuAction::ConfigureOAuth,
            },
            MenuItem {
                label: "Show OAuth Credentials",
                description: "View client ID/secret status for an existing rclone config.",
                action: MenuAction::ShowOAuthCredentials,
            },
            MenuItem {
                label: "Export Browser Sessions (Cookies)",
                description: "Extract and export provider cookies from local browser profiles (best effort).",
                action: MenuAction::ExportBrowserSessions,
            },
            MenuItem {
                label: "Export Cookies by Domain Pattern",
                description: "Export cookies for arbitrary domains (comma-separated). Useful for unsupported providers.",
                action: MenuAction::ExportDomainCookies,
            },
            MenuItem {
                label: "OneDrive",
                description: "OneDrive utilities (vault, recovery).",
                action: MenuAction::OneDriveMenu,
            },
            MenuItem {
                label: "Start rclone Web GUI",
                description: "Launch the rclone web interface for browsing and configuring remotes.",
                action: MenuAction::StartWebGui,
            },
            MenuItem {
                label: "Back to Main Menu",
                description: "Return to the main menu.",
                action: MenuAction::BackToMainMenu,
            },
        ]
    }

    fn onedrive_menu_items() -> Vec<MenuItem> {
        vec![
            MenuItem {
                label: "Open Vault",
                description: "Locate and open OneDrive personal vault data.",
                action: MenuAction::OpenOneDriveVault,
            },
            MenuItem {
                label: "Back to Additional Options",
                description: "Return to additional options.",
                action: MenuAction::BackToAdditionalOptions,
            },
        ]
    }

    fn mobile_flow_items() -> Vec<MenuItem> {
        vec![
            MenuItem {
                label: "Redirect Flow (Recommended for Forensics)",
                description: "Phone connects to forensic WiFi; token captured via HTTP redirect.",
                action: MenuAction::MobileAuthRedirect,
            },
            MenuItem {
                label: "Redirect Flow + Create Access Point",
                description: "Auto-create WiFi hotspot; requires admin privileges.",
                action: MenuAction::MobileAuthRedirectWithAp,
            },
            MenuItem {
                label: "Device Code Flow",
                description: "No local network needed; requires full re-authentication.",
                action: MenuAction::MobileAuthDeviceCode,
            },
            MenuItem {
                label: "Back to Providers",
                description: "Return to provider selection.",
                action: MenuAction::BackToProviders,
            },
        ]
    }

    pub fn menu_selected_item(&self) -> Option<&MenuItem> {
        self.menu_items.get(self.menu_selected)
    }

    pub fn additional_menu_selected_item(&self) -> Option<&MenuItem> {
        self.additional_menu_items
            .get(self.additional_menu_selected)
    }

    pub fn onedrive_menu_selected_item(&self) -> Option<&MenuItem> {
        self.onedrive_menu_items.get(self.onedrive_menu_selected)
    }

    pub fn mobile_flow_selected_item(&self) -> Option<&MenuItem> {
        self.mobile_flow_items.get(self.mobile_flow_selected)
    }

    pub fn menu_up(&mut self) {
        if self.state == AppState::MainMenu {
            list_navigate_up(&mut self.menu_selected, self.menu_items.len());
        }
    }

    pub fn menu_down(&mut self) {
        if self.state == AppState::MainMenu {
            list_navigate_down(&mut self.menu_selected, self.menu_items.len());
        }
    }

    pub fn additional_menu_up(&mut self) {
        if self.state == AppState::AdditionalOptions {
            list_navigate_up(&mut self.additional_menu_selected, self.additional_menu_items.len());
        }
    }

    pub fn additional_menu_down(&mut self) {
        if self.state == AppState::AdditionalOptions {
            list_navigate_down(&mut self.additional_menu_selected, self.additional_menu_items.len());
        }
    }

    pub fn onedrive_menu_up(&mut self) {
        if self.state == AppState::OneDriveMenu {
            list_navigate_up(&mut self.onedrive_menu_selected, self.onedrive_menu_items.len());
        }
    }

    pub fn onedrive_menu_down(&mut self) {
        if self.state == AppState::OneDriveMenu {
            list_navigate_down(&mut self.onedrive_menu_selected, self.onedrive_menu_items.len());
        }
    }

    pub fn mobile_flow_up(&mut self) {
        if self.state == AppState::MobileAuthFlow {
            list_navigate_up(&mut self.mobile_flow_selected, self.mobile_flow_items.len());
        }
    }

    pub fn mobile_flow_down(&mut self) {
        if self.state == AppState::MobileAuthFlow {
            list_navigate_down(&mut self.mobile_flow_selected, self.mobile_flow_items.len());
        }
    }

    /// Initialize case and directories with an auto-generated case name.
    pub fn init_case(&mut self, output_dir: PathBuf) -> Result<()> {
        if self.forensics.case.is_some() {
            return Ok(());
        }
        let case = Case::new("", output_dir)?;
        let directories = crate::case::directory::create_case_directories(&case)?;

        // Track created directories
        {
            let mut tracker = self.forensics.change_tracker.lock().unwrap();
            tracker.track_file_created(&directories.base, "Created case base directory");
            tracker.track_file_created(&directories.logs, "Created logs directory");
            tracker.track_file_created(&directories.downloads, "Created downloads directory");
            tracker.track_file_created(&directories.listings, "Created listings directory");
            tracker.track_file_created(&directories.config, "Created config directory");
        }

        // Create forensic logger in logs directory
        let log_path = directories.logs.join("rclone-triage.log");
        let logger = ForensicLogger::new(&log_path)?;
        logger.info(format!("Case started: {}", case.session_id()))?;

        // Track log file creation
        self.track_file(&log_path, "Created forensic log file");

        self.forensics.case = Some(case);
        self.forensics.directories = Some(directories);
        self.forensics.logger = Some(Arc::new(logger));
        Ok(())
    }

    /// Attach shared cleanup manager
    pub fn set_cleanup(&mut self, cleanup: Arc<Mutex<Cleanup>>) {
        self.forensics.cleanup = Some(cleanup);
    }

    /// Track a temp file for cleanup
    pub fn cleanup_track_file(&self, path: impl AsRef<std::path::Path>) {
        if let Some(ref cleanup) = self.forensics.cleanup {
            if let Ok(mut cleanup) = cleanup.lock() {
                cleanup.track_file(path);
            }
        }
    }

    /// Track a temp directory for cleanup
    pub fn cleanup_track_dir(&self, path: impl AsRef<std::path::Path>) {
        if let Some(ref cleanup) = self.forensics.cleanup {
            if let Ok(mut cleanup) = cleanup.lock() {
                cleanup.track_dir(path);
            }
        }
    }

    /// Track an env var change for cleanup
    pub fn cleanup_track_env_value(&self, name: impl Into<String>, old_value: Option<String>) {
        if let Some(ref cleanup) = self.forensics.cleanup {
            if let Ok(mut cleanup) = cleanup.lock() {
                cleanup.track_env_value(name, old_value);
            }
        }
    }

    /// Track a file creation in the change tracker
    pub fn track_file(&self, path: impl AsRef<std::path::Path>, description: impl Into<String>) {
        if let Ok(mut tracker) = self.forensics.change_tracker.lock() {
            tracker.track_file_created(path, description);
        }
    }

    /// Track an environment variable change
    pub fn track_env_var(&self, name: impl Into<String>, description: impl Into<String>) {
        if let Ok(mut tracker) = self.forensics.change_tracker.lock() {
            tracker.track_env_set(name, description);
        }
    }

    /// Capture final state and return the diff from initial state
    pub fn capture_final_state(&self) -> Option<crate::forensics::state::StateDiff> {
        let final_state = SystemStateSnapshot::capture("Final state after session").ok()?;
        self.forensics
            .initial_state
            .as_ref()
            .map(|initial| initial.diff(&final_state))
    }

    /// Log an info message if logger is available
    pub fn log_info(&self, message: impl AsRef<str>) {
        if let Some(ref logger) = self.forensics.logger {
            let _ = logger.info(message);
        }
    }

    /// Log an error message if logger is available
    pub fn log_error(&self, message: impl AsRef<str>) {
        if let Some(ref logger) = self.forensics.logger {
            let _ = logger.error(message);
        }
    }

    /// Get downloads directory path
    pub fn downloads_dir(&self) -> Option<PathBuf> {
        self.forensics
            .directories
            .as_ref()
            .map(|d| d.downloads.clone())
    }

    /// Get config directory path
    pub fn config_dir(&self) -> Option<PathBuf> {
        self.forensics
            .directories
            .as_ref()
            .map(|d| d.config.clone())
    }

    /// Move to the next state in the flow
    pub fn advance(&mut self) {
        self.state = self.state.next();
    }

    /// Move to the previous state in the flow
    pub fn back(&mut self) {
        self.state = self.state.previous();
    }

    /// Move provider selection up
    pub fn provider_up(&mut self) {
        if self.state == AppState::ProviderSelect {
            list_navigate_up(&mut self.provider.selected, self.provider.entries.len());
        }
    }

    /// Move provider selection down
    pub fn provider_down(&mut self) {
        if self.state == AppState::ProviderSelect {
            list_navigate_down(&mut self.provider.selected, self.provider.entries.len());
        }
    }

    /// Toggle whether the current provider is selected
    pub fn toggle_provider_selection(&mut self) {
        if self.state != AppState::ProviderSelect || self.provider.entries.is_empty() {
            return;
        }
        if let Some(entry) = self.provider.checked.get_mut(self.provider.selected) {
            *entry = !*entry;
        }
    }

    /// Get all selected providers
    pub fn selected_providers(&self) -> Vec<ProviderEntry> {
        self.provider
            .entries
            .iter()
            .cloned()
            .zip(self.provider.checked.iter().copied())
            .filter_map(|(provider, checked)| if checked { Some(provider) } else { None })
            .collect()
    }

    /// Persist the current provider selection for authentication
    pub fn confirm_provider(&mut self) {
        let selected = self.selected_providers();
        if selected.is_empty() {
            self.provider.status =
                "Select at least one provider (Space toggles selection).".to_string();
            self.provider.chosen = None;
            return;
        }
        self.provider.chosen = Some(selected[0].clone());
        self.remote.chosen = None;
        self.remote.chosen_multiple.clear();
        self.remote.options.clear();
        self.remote.selected = 0;
        self.remote.checked.clear();
    }

    /// Move remote selection up
    pub fn remote_up(&mut self) {
        if self.state == AppState::RemoteSelect {
            list_navigate_up(&mut self.remote.selected, self.remote.options.len());
        }
    }

    /// Move remote selection down
    pub fn remote_down(&mut self) {
        if self.state == AppState::RemoteSelect {
            list_navigate_down(&mut self.remote.selected, self.remote.options.len());
        }
    }

    /// Persist the chosen remote selection
    pub fn confirm_remote(&mut self) -> Option<String> {
        if self.remote.options.is_empty() {
            self.provider.status = "No remotes available.".to_string();
            return None;
        }
        if self.remote.selected >= self.remote.options.len() {
            self.remote.selected = 0;
        }
        let remote = self.remote.options[self.remote.selected].clone();
        self.remote.chosen = Some(remote.clone());
        self.remote.options.clear();
        self.remote.selected = 0;
        self.remote.checked.clear();
        self.remote.chosen_multiple.clear();
        Some(remote)
    }

    /// Toggle whether the current remote is selected (multi-select mode)
    pub fn toggle_remote_selection(&mut self) {
        if self.state != AppState::RemoteSelect || self.remote.options.is_empty() {
            return;
        }
        if let Some(entry) = self.remote.checked.get_mut(self.remote.selected) {
            *entry = !*entry;
        }
    }

    /// Get all checked remote names
    pub fn selected_remotes(&self) -> Vec<String> {
        self.remote
            .options
            .iter()
            .zip(self.remote.checked.iter().copied())
            .filter_map(|(name, checked)| if checked { Some(name.clone()) } else { None })
            .collect()
    }

    /// Confirm multi-select remote selection. Returns list of selected remotes.
    /// If none are checked, falls back to the highlighted item (single-select behavior).
    pub fn confirm_remotes_multi(&mut self) -> Vec<String> {
        let selected = self.selected_remotes();
        if selected.is_empty() {
            // Single-select fallback: use highlighted item
            if let Some(remote) = self.confirm_remote() {
                return vec![remote];
            }
            return Vec::new();
        }
        self.remote.chosen_multiple = selected.clone();
        if selected.len() == 1 {
            self.remote.chosen = Some(selected[0].clone());
        }
        self.remote.options.clear();
        self.remote.selected = 0;
        self.remote.checked.clear();
        selected
    }

    /// Refresh browser list and reset selection
    pub fn refresh_browsers(&mut self) {
        self.browser.entries = crate::providers::auth::get_available_browsers();
        self.browser.selected = 0;
        self.browser.checked = vec![false; self.browser.entries.len() + 1];
        self.browser.chosen = None;
    }

    /// Move browser selection up
    pub fn browser_up(&mut self) {
        if self.state == AppState::BrowserSelect {
            let total = self.browser.entries.len() + 1; // +1 for "System Default"
            list_navigate_up(&mut self.browser.selected, total);
        }
    }

    /// Move browser selection down
    pub fn browser_down(&mut self) {
        if self.state == AppState::BrowserSelect {
            let total = self.browser.entries.len() + 1;
            list_navigate_down(&mut self.browser.selected, total);
        }
    }

    /// Toggle whether the current browser is selected
    pub fn toggle_browser_selection(&mut self) {
        if self.state != AppState::BrowserSelect {
            return;
        }
        let total = self.browser.entries.len() + 1;
        if total == 0 {
            return;
        }
        if self.browser.checked.len() != total {
            self.browser.checked = vec![false; total];
        }
        if let Some(entry) = self.browser.checked.get_mut(self.browser.selected) {
            *entry = !*entry;
        }
    }

    /// Check if any browser is selected
    pub fn has_selected_browsers(&self) -> bool {
        self.browser.checked.iter().any(|checked| *checked)
    }

    /// Persist the current browser selection for authentication
    pub fn confirm_browser(&mut self) {
        if !self.has_selected_browsers() {
            self.auth_status = "Select at least one browser (Space toggles selection).".to_string();
            self.browser.chosen = None;
            return;
        }
        let mut chosen = None;
        for (idx, checked) in self.browser.checked.iter().copied().enumerate() {
            if !checked {
                continue;
            }
            if idx == 0 {
                chosen = None;
                break;
            }
            chosen = self.browser.entries.get(idx - 1).cloned();
            break;
        }
        self.browser.chosen = chosen;
    }

    /// Move file selection up
    pub fn file_up(&mut self) {
        if self.state == AppState::FileList {
            list_navigate_up(&mut self.files.selected, self.files.entries.len());
        }
    }

    /// Move file selection down
    pub fn file_down(&mut self) {
        if self.state == AppState::FileList {
            list_navigate_down(&mut self.files.selected, self.files.entries.len());
        }
    }

    /// Toggle whether the current file is selected for download
    pub fn toggle_file_download(&mut self) {
        if self.state != AppState::FileList || self.files.entries.is_empty() {
            return;
        }
        if let Some(path) = self.files.entries.get(self.files.selected).cloned() {
            if self.files.to_download.contains(&path) {
                self.files.to_download.retain(|p| p != &path);
            } else {
                self.files.to_download.push(path);
            }
        }
    }

    /// Look up full FileEntry by display path.
    ///
    /// Searches by raw path first. Falls back to matching display entries
    /// by index (for multi-remote `[remote] path` display strings).
    pub fn get_file_entry(&self, display_path: &str) -> Option<&crate::files::FileEntry> {
        // Direct match by raw path
        if let Some(entry) = self.files.entries_full.iter().find(|e| e.path == display_path) {
            return Some(entry);
        }
        // Index-based match: find position in display entries, return corresponding full entry
        self.files
            .entries
            .iter()
            .position(|e| e == display_path)
            .and_then(|idx| self.files.entries_full.get(idx))
    }

    /// Path to selection file for GUI-based selection
    pub fn selection_file_path(&self) -> Option<PathBuf> {
        self.forensics
            .directories
            .as_ref()
            .map(|d| d.listings.join("selection.txt"))
    }

    /// Load file selection from a text file (one path per line).
    pub fn load_selection_from_file(&mut self, path: &PathBuf) -> Result<usize> {
        let content = std::fs::read_to_string(path)
            .with_context(|| format!("Failed to read selection file {:?}", path))?;

        let mount_prefix = self
            .mounted_remote
            .as_ref()
            .map(|m| m.mount_point().to_path_buf());

        let mut selected = Vec::new();
        for line in content.lines() {
            let line = line.trim();
            if line.is_empty() {
                continue;
            }

            let mut candidate = line.to_string();
            if let Some(ref prefix) = mount_prefix {
                if let Ok(stripped) = PathBuf::from(line).strip_prefix(prefix) {
                    candidate = stripped
                        .to_string_lossy()
                        .trim_start_matches(['/', '\\'])
                        .to_string();
                } else if line.starts_with(prefix.to_string_lossy().as_ref()) {
                    candidate = line[prefix.to_string_lossy().len()..]
                        .trim_start_matches(['/', '\\'])
                        .to_string();
                }
            }

            if self.files.entries.contains(&candidate) {
                selected.push(candidate);
            }
        }

        self.files.to_download = selected;
        Ok(self.files.to_download.len())
    }

    /// Unmount the currently mounted remote (if any).
    pub fn unmount_remote(&mut self) {
        if let Some(mounted) = self.mounted_remote.take() {
            let _ = mounted.unmount();
        }
    }

    /// Remove the auto-generated combine remote from the config (cleanup on exit).
    pub fn cleanup_combine_remote(&mut self) {
        if !self.combine_remote_created {
            return;
        }
        if let Some(ref dirs) = self.forensics.directories {
            let config_path = dirs.config.join("rclone.conf");
            if config_path.exists() {
                if let Ok(config) = crate::rclone::RcloneConfig::open_existing(&config_path) {
                    let _ = crate::rclone::combine::remove_combine_remote(&config);
                }
            }
        }
        self.combine_remote_created = false;
    }

    /// Select all files for download
    pub fn select_all_files(&mut self) {
        if self.state != AppState::FileList {
            return;
        }
        self.files.to_download = self.files.entries.clone();
    }
}

impl Default for App {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_state_sequence() {
        let mut state = AppState::MainMenu;
        state = state.next();
        assert_eq!(state, AppState::ProviderSelect);
        state = state.next();
        assert_eq!(state, AppState::BrowserSelect);
        state = state.next();
        assert_eq!(state, AppState::Authenticating);
        state = state.next();
        assert_eq!(state, AppState::PostAuthChoice);
        state = state.next();
        assert_eq!(state, AppState::FileList);
        state = state.next();
        assert_eq!(state, AppState::Downloading);
        state = state.next();
        assert_eq!(state, AppState::Complete);
        state = state.next();
        assert_eq!(state, AppState::Complete);
    }

    #[test]
    fn test_app_transitions() {
        let mut app = App::new();
        assert_eq!(app.state, AppState::MainMenu);

        app.advance();
        assert_eq!(app.state, AppState::ProviderSelect);

        app.back();
        assert_eq!(app.state, AppState::MainMenu);
    }

    #[test]
    fn test_provider_selection() {
        let mut app = App::new();
        app.state = AppState::ProviderSelect;
        let original = app.provider.selected;
        app.provider_down();
        assert_ne!(app.provider.selected, original);
        app.provider_up();
        assert_eq!(app.provider.selected, original);
    }

    #[test]
    fn test_confirm_provider() {
        let mut app = App::new();
        app.state = AppState::ProviderSelect;
        app.provider.checked[app.provider.selected] = true;
        app.confirm_provider();
        assert!(app.provider.chosen.is_some());
    }

    #[test]
    fn test_file_selection() {
        let mut app = App::new();
        app.state = AppState::FileList;
        app.files.entries = vec!["file1.txt".to_string(), "file2.txt".to_string()];

        assert_eq!(app.files.selected, 0);
        app.file_down();
        assert_eq!(app.files.selected, 1);
        app.file_up();
        assert_eq!(app.files.selected, 0);

        // Toggle download selection
        app.toggle_file_download();
        assert_eq!(app.files.to_download.len(), 1);
        assert!(app.files.to_download.contains(&"file1.txt".to_string()));

        // Toggle again to deselect
        app.toggle_file_download();
        assert!(app.files.to_download.is_empty());
    }

    #[test]
    fn test_load_selection_from_file() {
        use tempfile::tempdir;

        let mut app = App::new();
        app.state = AppState::FileList;
        app.files.entries = vec!["a.txt".to_string(), "b.txt".to_string()];

        let dir = tempdir().unwrap();
        let path = dir.path().join("selection.txt");
        std::fs::write(&path, "a.txt\nmissing.txt\n").unwrap();

        let count = app.load_selection_from_file(&path).unwrap();
        assert_eq!(count, 1);
        assert_eq!(app.files.to_download, vec!["a.txt".to_string()]);
    }

    #[test]
    fn test_browser_selection() {
        let mut app = App::new();
        app.state = AppState::BrowserSelect;
        app.browser.entries = vec![Browser::new(crate::providers::browser::BrowserType::Chrome)];
        app.browser.selected = 0;
        app.browser_down();
        assert_eq!(app.browser.selected, 1);
        app.browser_up();
        assert_eq!(app.browser.selected, 0);
        app.confirm_browser();
        assert!(app.browser.chosen.is_none());
    }

    #[test]
    fn test_init_case_creates_directories() {
        use tempfile::tempdir;

        let mut app = App::new();

        let temp_dir = tempdir().unwrap();
        app.init_case(temp_dir.path().to_path_buf()).unwrap();

        // Verify case was created
        assert!(app.forensics.case.is_some());
        assert!(app.forensics.directories.is_some());
        assert!(app.forensics.logger.is_some());

        // Verify directories exist
        let dirs = app.forensics.directories.as_ref().unwrap();
        assert!(dirs.base.exists());
        assert!(dirs.downloads.exists());
        assert!(dirs.config.exists());
        assert!(dirs.logs.exists());
        assert!(dirs.listings.exists());

        // Verify log file was created
        let log_path = dirs.logs.join("rclone-triage.log");
        assert!(log_path.exists());

        // Verify helper methods
        assert!(app.downloads_dir().is_some());
        assert!(app.config_dir().is_some());
    }

    #[test]
    fn test_logging_methods() {
        use tempfile::tempdir;

        let mut app = App::new();

        let temp_dir = tempdir().unwrap();
        app.init_case(temp_dir.path().to_path_buf()).unwrap();

        // Test logging methods don't panic
        app.log_info("Test info message");
        app.log_error("Test error message");

        // Verify log file has content
        let log_path = app
            .forensics
            .directories
            .as_ref()
            .unwrap()
            .logs
            .join("rclone-triage.log");
        let log_content = std::fs::read_to_string(&log_path).unwrap();
        assert!(log_content.contains("Test info message"));
        assert!(log_content.contains("Test error message"));
    }

    #[test]
    fn test_config_browser_load_entries_has_nav() {
        use tempfile::tempdir;

        let dir = tempdir().unwrap();
        let state = ConfigBrowserState::from_dir(dir.path().to_path_buf());

        // Even an empty directory should have . and ..
        assert!(state.entries.len() >= 2);
        assert_eq!(state.entries[0].name, ".");
        assert_eq!(state.entries[1].name, "..");
        assert!(state.entries[0].is_dir);
        assert!(state.entries[1].is_dir);
        assert_eq!(state.status, "0 items");
    }

    #[test]
    fn test_config_browser_enter_dot_refreshes() {
        use tempfile::tempdir;

        let dir = tempdir().unwrap();
        let mut state = ConfigBrowserState::from_dir(dir.path().to_path_buf());

        // Select "." (index 0) and press enter
        state.selected = 0;
        let result = state.enter_selected();
        assert!(result.is_none()); // No file selected
        assert_eq!(state.current_dir, dir.path().to_path_buf());
        assert!(state.entries.len() >= 2);
    }

    #[test]
    fn test_config_browser_enter_dotdot_navigates_parent() {
        use tempfile::tempdir;

        let dir = tempdir().unwrap();
        let child = dir.path().join("subdir");
        std::fs::create_dir(&child).unwrap();
        let mut state = ConfigBrowserState::from_dir(child.clone());

        // Select ".." (index 1) and press enter
        state.selected = 1;
        let result = state.enter_selected();
        assert!(result.is_none());
        assert_eq!(state.current_dir, dir.path().to_path_buf());
    }

    #[test]
    fn test_config_browser_nav_entries_before_real_dirs() {
        use tempfile::tempdir;

        let dir = tempdir().unwrap();
        std::fs::create_dir(dir.path().join("alpha")).unwrap();
        std::fs::write(dir.path().join("test.conf"), "[remote]\ntype=drive\n").unwrap();
        let state = ConfigBrowserState::from_dir(dir.path().to_path_buf());

        // First two entries must be . and ..
        assert_eq!(state.entries[0].name, ".");
        assert_eq!(state.entries[1].name, "..");
        // Real dir comes after nav entries
        assert_eq!(state.entries[2].name, "alpha");
        assert!(state.entries[2].is_dir);
        // File comes last
        assert_eq!(state.entries[3].name, "test.conf");
        assert!(!state.entries[3].is_dir);
        assert_eq!(state.status, "2 items"); // Only counts real entries
    }

    #[test]
    fn test_toggle_remote_selection() {
        let mut app = App::new();
        app.state = AppState::RemoteSelect;
        app.remote.options = vec!["gdrive".to_string(), "onedrive".to_string()];
        app.remote.checked = vec![false, false];
        app.remote.selected = 0;

        app.toggle_remote_selection();
        assert_eq!(app.remote.checked, vec![true, false]);

        app.remote.selected = 1;
        app.toggle_remote_selection();
        assert_eq!(app.remote.checked, vec![true, true]);

        app.toggle_remote_selection();
        assert_eq!(app.remote.checked, vec![true, false]);
    }

    #[test]
    fn test_selected_remotes() {
        let mut app = App::new();
        app.remote.options = vec!["a".to_string(), "b".to_string(), "c".to_string()];
        app.remote.checked = vec![true, false, true];

        let selected = app.selected_remotes();
        assert_eq!(selected, vec!["a".to_string(), "c".to_string()]);
    }

    #[test]
    fn test_confirm_remotes_multi_with_checked() {
        let mut app = App::new();
        app.state = AppState::RemoteSelect;
        app.remote.options = vec!["gdrive".to_string(), "onedrive".to_string()];
        app.remote.checked = vec![true, true];

        let result = app.confirm_remotes_multi();
        assert_eq!(result, vec!["gdrive".to_string(), "onedrive".to_string()]);
        assert_eq!(app.remote.chosen_multiple, result);
    }

    #[test]
    fn test_confirm_remotes_multi_none_checked_fallback() {
        let mut app = App::new();
        app.state = AppState::RemoteSelect;
        app.remote.options = vec!["gdrive".to_string(), "onedrive".to_string()];
        app.remote.checked = vec![false, false];
        app.remote.selected = 1;

        let result = app.confirm_remotes_multi();
        // Falls back to single-select on the highlighted item
        assert_eq!(result, vec!["onedrive".to_string()]);
        assert_eq!(app.remote.chosen.as_deref(), Some("onedrive"));
    }

    #[test]
    fn test_get_file_entry_with_remote_prefix() {
        let mut app = App::new();
        app.files.entries_full = vec![
            crate::files::FileEntry {
                path: "file.txt".to_string(),
                size: 42,
                modified: None,
                is_dir: false,
                hash: None,
                hash_type: None,
                remote_name: Some("gdrive".to_string()),
            },
        ];
        app.files.entries = vec!["[gdrive] file.txt".to_string()];

        // Index-based lookup via display path
        let entry = app.get_file_entry("[gdrive] file.txt");
        assert!(entry.is_some());
        assert_eq!(entry.unwrap().path, "file.txt");
        assert_eq!(entry.unwrap().remote_name.as_deref(), Some("gdrive"));

        // Direct path lookup also works
        let entry2 = app.get_file_entry("file.txt");
        assert!(entry2.is_some());
    }

    #[test]
    fn test_post_auth_add_another_tracks_remote() {
        let mut app = App::new();
        app.remote.chosen = Some("gdrive_remote".to_string());
        app.provider.chosen = Some(crate::providers::ProviderEntry::from_known(
            crate::providers::CloudProvider::GoogleDrive,
        ));

        // Simulate AddAnotherProvider
        if let Some(ref remote) = app.remote.chosen {
            let pname = app
                .provider
                .chosen
                .as_ref()
                .map(|p| p.display_name().to_string())
                .unwrap_or_else(|| "Unknown".to_string());
            if !app.authenticated_remotes.iter().any(|(r, _)| r == remote) {
                app.authenticated_remotes.push((remote.clone(), pname));
            }
        }

        assert_eq!(app.authenticated_remotes.len(), 1);
        assert_eq!(app.authenticated_remotes[0].0, "gdrive_remote");
        assert_eq!(app.authenticated_remotes[0].1, "Google Drive");
    }
}
