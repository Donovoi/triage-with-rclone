//! TUI application state machine
//!
//! Defines the core application state and transitions used by the UI.

use crate::case::directory::CaseDirectories;
use crate::cleanup::Cleanup;
use crate::case::Case;
use crate::forensics::changes::ChangeTracker;
use crate::forensics::logger::ForensicLogger;
use crate::forensics::state::SystemStateSnapshot;
use crate::providers::browser::Browser;
use crate::providers::{CloudProvider, ProviderEntry};
use crate::rclone::MountedRemote;
use crate::ui::widgets::SessionInputForm;
use anyhow::{bail, Context, Result};
use std::path::PathBuf;
use std::sync::{Arc, Mutex};

pub mod layout;
pub mod render;
pub mod runner;
pub mod screens;
pub mod widgets;

/// Application states for the TUI flow
#[allow(dead_code)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AppState {
    CaseSetup,
    ProviderSelect,
    BrowserSelect,
    Authenticating,
    FileList,
    Downloading,
    Complete,
}

impl AppState {
    /// Get the next logical state in the flow
    #[allow(dead_code)]
    pub fn next(self) -> Self {
        match self {
            AppState::CaseSetup => AppState::ProviderSelect,
            AppState::ProviderSelect => AppState::BrowserSelect,
            AppState::BrowserSelect => AppState::Authenticating,
            AppState::Authenticating => AppState::FileList,
            AppState::FileList => AppState::Downloading,
            AppState::Downloading => AppState::Complete,
            AppState::Complete => AppState::Complete,
        }
    }

    /// Get the previous logical state in the flow
    #[allow(dead_code)]
    pub fn previous(self) -> Self {
        match self {
            AppState::CaseSetup => AppState::CaseSetup,
            AppState::ProviderSelect => AppState::CaseSetup,
            AppState::BrowserSelect => AppState::ProviderSelect,
            AppState::Authenticating => AppState::BrowserSelect,
            AppState::FileList => AppState::Authenticating,
            AppState::Downloading => AppState::FileList,
            AppState::Complete => AppState::Downloading,
        }
    }
}

/// Core application state container
#[allow(dead_code)]
pub struct App {
    /// Current application state
    pub state: AppState,
    /// Session input form state
    pub session_form: SessionInputForm,
    /// Case metadata
    pub case: Option<Case>,
    /// Case directory structure
    pub directories: Option<CaseDirectories>,
    /// Forensic logger (hash-chained)
    pub logger: Option<Arc<ForensicLogger>>,
    /// Cleanup manager for temp files/env vars (shared with main)
    pub cleanup: Option<Arc<Mutex<Cleanup>>>,
    /// Initial system state snapshot (captured at start)
    pub initial_state: Option<SystemStateSnapshot>,
    /// Change tracker for documenting modifications
    pub change_tracker: Arc<Mutex<ChangeTracker>>,
    /// Provider list for selection
    pub providers: Vec<ProviderEntry>,
    /// Selected provider index
    pub provider_selected: usize,
    /// Chosen provider (persisted for auth)
    pub chosen_provider: Option<ProviderEntry>,
    /// Browser list for selection (installed browsers)
    pub browsers: Vec<Browser>,
    /// Selected browser index (0 = system default)
    pub browser_selected: usize,
    /// Chosen browser (None = system default)
    pub chosen_browser: Option<Browser>,
    /// Chosen remote name from auth (may include browser prefix)
    pub chosen_remote: Option<String>,
    /// Auth status message
    pub auth_status: String,
    /// File listing entries (paths only, for display)
    pub file_entries: Vec<String>,
    /// Full file entries with hash info (for download verification)
    pub file_entries_full: Vec<crate::files::FileEntry>,
    /// Currently highlighted file index
    pub file_selected: usize,
    /// Files marked for download (paths)
    pub files_to_download: Vec<String>,
    /// Download status message
    pub download_status: String,
    /// Download progress (current/total)
    pub download_progress: (usize, usize),
    /// Current file bytes progress (done/total)
    pub download_current_bytes: Option<(u64, u64)>,
    /// Total bytes across selected files (if known)
    pub download_total_bytes: Option<u64>,
    /// Bytes completed across downloads (if known)
    pub download_done_bytes: u64,
    /// Final report lines
    pub report_lines: Vec<String>,
    /// SSO status for currently selected provider
    pub sso_status: Option<crate::providers::auth::SsoStatus>,
    /// Mounted remote for GUI selection
    pub mounted_remote: Option<MountedRemote>,
}

impl App {
    /// Create a new app with the initial state
    #[allow(dead_code)]
    pub fn new() -> Self {
        // Capture initial system state before any operations
        let initial_state = SystemStateSnapshot::capture("Initial state before session").ok();

        Self {
            state: AppState::CaseSetup,
            session_form: SessionInputForm::new(),
            case: None,
            directories: None,
            logger: None,
            cleanup: None,
            initial_state,
            change_tracker: Arc::new(Mutex::new(ChangeTracker::new())),
            providers: CloudProvider::entries(),
            provider_selected: 0,
            chosen_provider: None,
            browsers: crate::providers::auth::get_available_browsers(),
            browser_selected: 0,
            chosen_browser: None,
            chosen_remote: None,
            auth_status: String::new(),
            file_entries: Vec::new(),
            file_entries_full: Vec::new(),
            file_selected: 0,
            files_to_download: Vec::new(),
            download_status: String::new(),
            download_progress: (0, 0),
            download_current_bytes: None,
            download_total_bytes: None,
            download_done_bytes: 0,
            report_lines: Vec::new(),
            sso_status: None,
            mounted_remote: None,
        }
    }

    /// Initialize case and directories from session name
    #[allow(dead_code)]
    pub fn init_case(&mut self, output_dir: PathBuf) -> Result<()> {
        let session_name = &self.session_form.session_name;
        let case = Case::new(session_name.clone(), output_dir)?;
        let directories = crate::case::directory::create_case_directories(&case)?;

        // Track created directories
        {
            let mut tracker = self.change_tracker.lock().unwrap();
            tracker.track_file_created(&directories.base, "Created case base directory");
            tracker.track_file_created(&directories.logs, "Created logs directory");
            tracker.track_file_created(&directories.downloads, "Created downloads directory");
            tracker.track_file_created(&directories.listings, "Created listings directory");
            tracker.track_file_created(&directories.config, "Created config directory");
        }

        // Create forensic logger in logs directory
        let log_path = directories.logs.join("rclone-triage.log");
        let logger = ForensicLogger::new(&log_path)?;
        logger.info(format!("Session started: {}", case.session_id()))?;

        // Track log file creation
        self.track_file(&log_path, "Created forensic log file");

        self.case = Some(case);
        self.directories = Some(directories);
        self.logger = Some(Arc::new(logger));
        Ok(())
    }

    /// Attach shared cleanup manager
    #[allow(dead_code)]
    pub fn set_cleanup(&mut self, cleanup: Arc<Mutex<Cleanup>>) {
        self.cleanup = Some(cleanup);
    }

    /// Track a temp file for cleanup
    #[allow(dead_code)]
    pub fn cleanup_track_file(&self, path: impl AsRef<std::path::Path>) {
        if let Some(ref cleanup) = self.cleanup {
            if let Ok(mut cleanup) = cleanup.lock() {
                cleanup.track_file(path);
            }
        }
    }

    /// Track a temp directory for cleanup
    #[allow(dead_code)]
    pub fn cleanup_track_dir(&self, path: impl AsRef<std::path::Path>) {
        if let Some(ref cleanup) = self.cleanup {
            if let Ok(mut cleanup) = cleanup.lock() {
                cleanup.track_dir(path);
            }
        }
    }

    /// Track an env var change for cleanup
    #[allow(dead_code)]
    pub fn cleanup_track_env_value(&self, name: impl Into<String>, old_value: Option<String>) {
        if let Some(ref cleanup) = self.cleanup {
            if let Ok(mut cleanup) = cleanup.lock() {
                cleanup.track_env_value(name, old_value);
            }
        }
    }

    /// Track a file creation in the change tracker
    #[allow(dead_code)]
    pub fn track_file(&self, path: impl AsRef<std::path::Path>, description: impl Into<String>) {
        if let Ok(mut tracker) = self.change_tracker.lock() {
            tracker.track_file_created(path, description);
        }
    }

    /// Track an environment variable change
    #[allow(dead_code)]
    pub fn track_env_var(&self, name: impl Into<String>, description: impl Into<String>) {
        if let Ok(mut tracker) = self.change_tracker.lock() {
            tracker.track_env_set(name, description);
        }
    }

    /// Capture final state and return the diff from initial state
    #[allow(dead_code)]
    pub fn capture_final_state(&self) -> Option<crate::forensics::state::StateDiff> {
        let final_state = SystemStateSnapshot::capture("Final state after session").ok()?;
        self.initial_state
            .as_ref()
            .map(|initial| initial.diff(&final_state))
    }

    /// Get the change tracker report
    #[allow(dead_code)]
    pub fn change_report(&self) -> String {
        self.change_tracker
            .lock()
            .map(|tracker| tracker.generate_report())
            .unwrap_or_else(|_| "Failed to generate change report".to_string())
    }

    /// Log an info message if logger is available
    #[allow(dead_code)]
    pub fn log_info(&self, message: impl AsRef<str>) {
        if let Some(ref logger) = self.logger {
            let _ = logger.info(message);
        }
    }

    /// Log an error message if logger is available
    #[allow(dead_code)]
    pub fn log_error(&self, message: impl AsRef<str>) {
        if let Some(ref logger) = self.logger {
            let _ = logger.error(message);
        }
    }

    /// Get downloads directory path
    #[allow(dead_code)]
    pub fn downloads_dir(&self) -> Option<PathBuf> {
        self.directories.as_ref().map(|d| d.downloads.clone())
    }

    /// Get config directory path
    #[allow(dead_code)]
    pub fn config_dir(&self) -> Option<PathBuf> {
        self.directories.as_ref().map(|d| d.config.clone())
    }

    /// Move to the next state in the flow
    #[allow(dead_code)]
    pub fn advance(&mut self) {
        self.state = self.state.next();
    }

    /// Move to the previous state in the flow
    #[allow(dead_code)]
    pub fn back(&mut self) {
        self.state = self.state.previous();
    }

    /// Handle character input in the current state
    #[allow(dead_code)]
    pub fn input_char(&mut self, ch: char) {
        if self.state != AppState::CaseSetup {
            return;
        }
        // Allow any printable character for session name
        if ch.is_ascii_graphic() || ch == ' ' {
            self.session_form.session_name.push(ch);
        }
    }

    /// Handle backspace in the current state
    #[allow(dead_code)]
    pub fn input_backspace(&mut self) {
        if self.state != AppState::CaseSetup {
            return;
        }
        self.session_form.session_name.pop();
    }

    /// Move provider selection up
    #[allow(dead_code)]
    pub fn provider_up(&mut self) {
        if self.state != AppState::ProviderSelect || self.providers.is_empty() {
            return;
        }
        if self.provider_selected == 0 {
            self.provider_selected = self.providers.len() - 1;
        } else {
            self.provider_selected -= 1;
        }
    }

    /// Move provider selection down
    #[allow(dead_code)]
    pub fn provider_down(&mut self) {
        if self.state != AppState::ProviderSelect || self.providers.is_empty() {
            return;
        }
        self.provider_selected = (self.provider_selected + 1) % self.providers.len();
    }

    /// Get the currently selected provider
    #[allow(dead_code)]
    pub fn selected_provider(&self) -> Option<ProviderEntry> {
        self.providers.get(self.provider_selected).cloned()
    }

    /// Persist the current provider selection for authentication
    #[allow(dead_code)]
    pub fn confirm_provider(&mut self) {
        self.chosen_provider = self.selected_provider();
        self.chosen_remote = None;
    }

    /// Refresh browser list and reset selection
    #[allow(dead_code)]
    pub fn refresh_browsers(&mut self) {
        self.browsers = crate::providers::auth::get_available_browsers();
        self.browser_selected = 0;
        self.chosen_browser = None;
    }

    /// Move browser selection up
    #[allow(dead_code)]
    pub fn browser_up(&mut self) {
        if self.state != AppState::BrowserSelect {
            return;
        }
        let total = self.browsers.len() + 1; // +1 for "System Default"
        if total == 0 {
            return;
        }
        if self.browser_selected == 0 {
            self.browser_selected = total - 1;
        } else {
            self.browser_selected -= 1;
        }
    }

    /// Move browser selection down
    #[allow(dead_code)]
    pub fn browser_down(&mut self) {
        if self.state != AppState::BrowserSelect {
            return;
        }
        let total = self.browsers.len() + 1;
        if total == 0 {
            return;
        }
        self.browser_selected = (self.browser_selected + 1) % total;
    }

    /// Get the currently selected browser (None = system default)
    #[allow(dead_code)]
    pub fn selected_browser(&self) -> Option<Browser> {
        if self.browser_selected == 0 {
            None
        } else {
            self.browsers.get(self.browser_selected - 1).cloned()
        }
    }

    /// Persist the current browser selection for authentication
    #[allow(dead_code)]
    pub fn confirm_browser(&mut self) {
        self.chosen_browser = self.selected_browser();
    }

    /// Update SSO status for the selected provider
    #[allow(dead_code)]
    pub fn update_sso_status(&mut self) {
        if let Some(provider) = self.selected_provider() {
            if let Some(known) = provider.known {
                self.sso_status = Some(crate::providers::auth::detect_sso_sessions(known));
            } else {
                self.sso_status = None;
            }
        }
    }

    /// Get SSO summary for display
    #[allow(dead_code)]
    pub fn sso_summary(&self) -> String {
        if let Some(provider) = self.selected_provider() {
            if let Some(known) = provider.known {
                crate::providers::auth::get_sso_summary(known)
            } else {
                "SSO not available for this provider".to_string()
            }
        } else {
            "No provider selected".to_string()
        }
    }

    /// Check if SSO authentication is available for the selected provider
    #[allow(dead_code)]
    pub fn has_sso_available(&self) -> bool {
        self.sso_status
            .as_ref()
            .map(|s| s.has_sessions)
            .unwrap_or(false)
    }

    /// Move file selection up
    #[allow(dead_code)]
    pub fn file_up(&mut self) {
        if self.state != AppState::FileList || self.file_entries.is_empty() {
            return;
        }
        if self.file_selected == 0 {
            self.file_selected = self.file_entries.len() - 1;
        } else {
            self.file_selected -= 1;
        }
    }

    /// Move file selection down
    #[allow(dead_code)]
    pub fn file_down(&mut self) {
        if self.state != AppState::FileList || self.file_entries.is_empty() {
            return;
        }
        self.file_selected = (self.file_selected + 1) % self.file_entries.len();
    }

    /// Toggle whether the current file is selected for download
    #[allow(dead_code)]
    pub fn toggle_file_download(&mut self) {
        if self.state != AppState::FileList || self.file_entries.is_empty() {
            return;
        }
        if let Some(path) = self.file_entries.get(self.file_selected).cloned() {
            if self.files_to_download.contains(&path) {
                self.files_to_download.retain(|p| p != &path);
            } else {
                self.files_to_download.push(path);
            }
        }
    }

    /// Look up full FileEntry by path (to get hash info for verification)
    #[allow(dead_code)]
    pub fn get_file_entry(&self, path: &str) -> Option<&crate::files::FileEntry> {
        self.file_entries_full.iter().find(|e| e.path == path)
    }

    /// Path to selection file for GUI-based selection
    pub fn selection_file_path(&self) -> Option<PathBuf> {
        self.directories
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
                    candidate = stripped.to_string_lossy().trim_start_matches(['/', '\\']).to_string();
                } else if line.starts_with(prefix.to_string_lossy().as_ref()) {
                    candidate = line[prefix.to_string_lossy().len()..]
                        .trim_start_matches(['/', '\\'])
                        .to_string();
                }
            }

            if self.file_entries.contains(&candidate) {
                selected.push(candidate);
            }
        }

        self.files_to_download = selected;
        Ok(self.files_to_download.len())
    }

    /// Unmount the currently mounted remote (if any).
    pub fn unmount_remote(&mut self) {
        if let Some(mounted) = self.mounted_remote.take() {
            let _ = mounted.unmount();
        }
    }

    /// Select all files for download
    #[allow(dead_code)]
    pub fn select_all_files(&mut self) {
        if self.state != AppState::FileList {
            return;
        }
        self.files_to_download = self.file_entries.clone();
    }

    /// Attempt an explicit transition with validation
    #[allow(dead_code)]
    pub fn transition(&mut self, next: AppState) -> Result<()> {
        if Self::is_valid_transition(self.state, next) {
            self.state = next;
            Ok(())
        } else {
            bail!("Invalid transition: {:?} -> {:?}", self.state, next);
        }
    }

    /// Check if a transition is valid
    #[allow(dead_code)]
    pub fn is_valid_transition(from: AppState, to: AppState) -> bool {
        match (from, to) {
            (AppState::CaseSetup, AppState::ProviderSelect) => true,
            (AppState::ProviderSelect, AppState::BrowserSelect) => true,
            (AppState::BrowserSelect, AppState::Authenticating) => true,
            (AppState::Authenticating, AppState::FileList) => true,
            (AppState::FileList, AppState::Downloading) => true,
            (AppState::Downloading, AppState::Complete) => true,
            (state, same) if state == same => true,
            _ => false,
        }
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
        let mut state = AppState::CaseSetup;
        state = state.next();
        assert_eq!(state, AppState::ProviderSelect);
        state = state.next();
        assert_eq!(state, AppState::BrowserSelect);
        state = state.next();
        assert_eq!(state, AppState::Authenticating);
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
        assert_eq!(app.state, AppState::CaseSetup);

        app.advance();
        assert_eq!(app.state, AppState::ProviderSelect);

        app.back();
        assert_eq!(app.state, AppState::CaseSetup);
    }

    #[test]
    fn test_session_input_handling() {
        let mut app = App::new();
        app.input_char('m');
        app.input_char('y');
        app.input_char('-');
        app.input_char('s');
        assert_eq!(app.session_form.session_name, "my-s");

        app.input_backspace();
        assert_eq!(app.session_form.session_name, "my-");
    }

    #[test]
    fn test_provider_selection() {
        let mut app = App::new();
        app.state = AppState::ProviderSelect;
        let original = app.provider_selected;
        app.provider_down();
        assert_ne!(app.provider_selected, original);
        app.provider_up();
        assert_eq!(app.provider_selected, original);
    }

    #[test]
    fn test_confirm_provider() {
        let mut app = App::new();
        app.state = AppState::ProviderSelect;
        app.confirm_provider();
        assert!(app.chosen_provider.is_some());
    }

    #[test]
    fn test_file_selection() {
        let mut app = App::new();
        app.state = AppState::FileList;
        app.file_entries = vec!["file1.txt".to_string(), "file2.txt".to_string()];

        assert_eq!(app.file_selected, 0);
        app.file_down();
        assert_eq!(app.file_selected, 1);
        app.file_up();
        assert_eq!(app.file_selected, 0);

        // Toggle download selection
        app.toggle_file_download();
        assert_eq!(app.files_to_download.len(), 1);
        assert!(app.files_to_download.contains(&"file1.txt".to_string()));

        // Toggle again to deselect
        app.toggle_file_download();
        assert!(app.files_to_download.is_empty());
    }

    #[test]
    fn test_load_selection_from_file() {
        use tempfile::tempdir;

        let mut app = App::new();
        app.state = AppState::FileList;
        app.file_entries = vec!["a.txt".to_string(), "b.txt".to_string()];

        let dir = tempdir().unwrap();
        let path = dir.path().join("selection.txt");
        std::fs::write(&path, "a.txt\nmissing.txt\n").unwrap();

        let count = app.load_selection_from_file(&path).unwrap();
        assert_eq!(count, 1);
        assert_eq!(app.files_to_download, vec!["a.txt".to_string()]);
    }

    #[test]
    fn test_valid_transition() {
        assert!(App::is_valid_transition(
            AppState::CaseSetup,
            AppState::ProviderSelect
        ));
        assert!(App::is_valid_transition(
            AppState::ProviderSelect,
            AppState::BrowserSelect
        ));
        assert!(!App::is_valid_transition(
            AppState::CaseSetup,
            AppState::FileList
        ));
    }

    #[test]
    fn test_browser_selection() {
        let mut app = App::new();
        app.state = AppState::BrowserSelect;
        app.browsers = vec![Browser::new(crate::providers::browser::BrowserType::Chrome)];
        app.browser_selected = 0;
        app.browser_down();
        assert_eq!(app.browser_selected, 1);
        app.browser_up();
        assert_eq!(app.browser_selected, 0);
        app.confirm_browser();
        assert!(app.chosen_browser.is_none());
    }

    #[test]
    fn test_transition_validation() {
        let mut app = App::new();
        app.transition(AppState::ProviderSelect).unwrap();
        let result = app.transition(AppState::FileList);
        assert!(result.is_err());
    }

    #[test]
    fn test_init_case_creates_directories() {
        use tempfile::tempdir;

        let mut app = App::new();
        app.session_form.session_name = "test-session".to_string();

        let temp_dir = tempdir().unwrap();
        app.init_case(temp_dir.path().to_path_buf()).unwrap();

        // Verify case was created
        assert!(app.case.is_some());
        assert!(app.directories.is_some());
        assert!(app.logger.is_some());

        // Verify directories exist
        let dirs = app.directories.as_ref().unwrap();
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
        app.session_form.session_name = "log-test".to_string();

        let temp_dir = tempdir().unwrap();
        app.init_case(temp_dir.path().to_path_buf()).unwrap();

        // Test logging methods don't panic
        app.log_info("Test info message");
        app.log_error("Test error message");

        // Verify log file has content
        let log_path = app
            .directories
            .as_ref()
            .unwrap()
            .logs
            .join("rclone-triage.log");
        let log_content = std::fs::read_to_string(&log_path).unwrap();
        assert!(log_content.contains("Test info message"));
        assert!(log_content.contains("Test error message"));
    }
}
