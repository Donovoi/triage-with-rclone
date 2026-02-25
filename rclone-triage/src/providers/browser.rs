//! Browser detection and management
//!
//! Detects installed browsers and manages authentication through them.
//! On Windows, supports changing the default browser for OAuth redirects.

use anyhow::{bail, Result};
use serde::{Deserialize, Serialize};
use std::path::PathBuf;

/// Known browser definitions
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum BrowserType {
    Chrome,
    ChromeBeta,
    Chromium,
    Edge,
    Brave,
    Firefox,
    Opera,
    OperaGX,
    Vivaldi,
    Yandex,
    Tor,
}

impl BrowserType {
    /// Get all known browser types
    pub fn all() -> &'static [BrowserType] {
        &[
            BrowserType::Chrome,
            BrowserType::ChromeBeta,
            BrowserType::Chromium,
            BrowserType::Edge,
            BrowserType::Brave,
            BrowserType::Firefox,
            BrowserType::Opera,
            BrowserType::OperaGX,
            BrowserType::Vivaldi,
            BrowserType::Yandex,
            BrowserType::Tor,
        ]
    }

    /// Get display name
    pub fn display_name(&self) -> &'static str {
        match self {
            BrowserType::Chrome => "Google Chrome",
            BrowserType::ChromeBeta => "Google Chrome Beta",
            BrowserType::Chromium => "Chromium",
            BrowserType::Edge => "Microsoft Edge",
            BrowserType::Brave => "Brave",
            BrowserType::Firefox => "Mozilla Firefox",
            BrowserType::Opera => "Opera",
            BrowserType::OperaGX => "Opera GX",
            BrowserType::Vivaldi => "Vivaldi",
            BrowserType::Yandex => "Yandex Browser",
            BrowserType::Tor => "Tor Browser",
        }
    }

    /// Get short name for file naming
    pub fn short_name(&self) -> &'static str {
        match self {
            BrowserType::Chrome => "chrome",
            BrowserType::ChromeBeta => "chrome-beta",
            BrowserType::Chromium => "chromium",
            BrowserType::Edge => "edge",
            BrowserType::Brave => "brave",
            BrowserType::Firefox => "firefox",
            BrowserType::Opera => "opera",
            BrowserType::OperaGX => "opera-gx",
            BrowserType::Vivaldi => "vivaldi",
            BrowserType::Yandex => "yandex",
            BrowserType::Tor => "tor",
        }
    }

    /// Get Windows ProgID for default browser setting
    #[cfg(windows)]
    pub fn prog_id(&self) -> &'static str {
        match self {
            BrowserType::Chrome => "ChromeHTML",
            BrowserType::ChromeBeta => "ChromeBHTML",
            BrowserType::Chromium => "ChromiumHTML",
            BrowserType::Edge => "MSEdgeHTM",
            BrowserType::Brave => "BraveHTML",
            BrowserType::Firefox => "FirefoxURL-308046B0AF4A39CB",
            BrowserType::Opera => "OperaStable",
            BrowserType::OperaGX => "OperaGXStable",
            BrowserType::Vivaldi => "VivaldiHTML",
            BrowserType::Yandex => "YandexHTML",
            BrowserType::Tor => "FirefoxURL-*",
        }
    }
}

impl std::fmt::Display for BrowserType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.display_name())
    }
}

/// Represents an installed browser
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Browser {
    /// Browser type
    pub browser_type: BrowserType,
    /// Path to the executable
    pub executable_path: Option<PathBuf>,
    /// Path to the profile/data directory
    pub profile_path: Option<PathBuf>,
    /// Whether the browser is installed
    pub is_installed: bool,
    /// Whether this is the current default browser
    pub is_default: bool,
}

impl Browser {
    /// Create a new Browser instance
    pub fn new(browser_type: BrowserType) -> Self {
        Self {
            browser_type,
            executable_path: None,
            profile_path: None,
            is_installed: false,
            is_default: false,
        }
    }

    /// Get display name
    pub fn display_name(&self) -> &'static str {
        self.browser_type.display_name()
    }

    /// Get short name for file naming
    pub fn short_name(&self) -> &'static str {
        self.browser_type.short_name()
    }

    /// Open a URL in this browser
    pub fn open_url(&self, url: &str) -> Result<()> {
        if !self.is_installed {
            bail!("Browser {} is not installed", self.browser_type);
        }

        let exe_path = self
            .executable_path
            .as_ref()
            .ok_or_else(|| anyhow::anyhow!("No executable path for {}", self.browser_type))?;

        std::process::Command::new(exe_path).arg(url).spawn()?;

        Ok(())
    }
}

/// Detects installed browsers on the system
pub struct BrowserDetector;

impl BrowserDetector {
    /// Detect all installed browsers
    pub fn detect_all() -> Vec<Browser> {
        let mut browsers = Vec::new();

        for browser_type in BrowserType::all() {
            if let Some(browser) = Self::detect(*browser_type) {
                if browser.is_installed {
                    browsers.push(browser);
                }
            }
        }

        browsers
    }

    /// Detect a specific browser
    pub fn detect(browser_type: BrowserType) -> Option<Browser> {
        #[cfg(windows)]
        {
            Self::detect_windows(browser_type)
        }

        #[cfg(target_os = "linux")]
        {
            Self::detect_linux(browser_type)
        }

        #[cfg(target_os = "macos")]
        {
            Self::detect_macos(browser_type)
        }
    }

    /// Detect browsers on Windows
    #[cfg(windows)]
    fn detect_windows(browser_type: BrowserType) -> Option<Browser> {
        let mut browser = Browser::new(browser_type);

        // Define paths for each browser
        let (exe_paths, profile_path) = match browser_type {
            BrowserType::Chrome => (
                vec![
                    PathBuf::from(r"C:\Program Files\Google\Chrome\Application\chrome.exe"),
                    PathBuf::from(r"C:\Program Files (x86)\Google\Chrome\Application\chrome.exe"),
                ],
                dirs::data_local_dir().map(|d| d.join(r"Google\Chrome\User Data\Default")),
            ),
            BrowserType::ChromeBeta => (
                vec![PathBuf::from(
                    r"C:\Program Files\Google\Chrome Beta\Application\chrome.exe",
                )],
                dirs::data_local_dir().map(|d| d.join(r"Google\Chrome Beta\User Data\Default")),
            ),
            BrowserType::Chromium => (
                vec![], // Dynamic path needed
                dirs::data_local_dir().map(|d| d.join(r"Chromium\User Data\Default")),
            ),
            BrowserType::Edge => (
                vec![
                    PathBuf::from(r"C:\Program Files (x86)\Microsoft\Edge\Application\msedge.exe"),
                    PathBuf::from(r"C:\Program Files\Microsoft\Edge\Application\msedge.exe"),
                ],
                dirs::data_local_dir().map(|d| d.join(r"Microsoft\Edge\User Data\Default")),
            ),
            BrowserType::Brave => (
                vec![PathBuf::from(
                    r"C:\Program Files\BraveSoftware\Brave-Browser\Application\brave.exe",
                )],
                dirs::data_local_dir()
                    .map(|d| d.join(r"BraveSoftware\Brave-Browser\User Data\Default")),
            ),
            BrowserType::Firefox => (
                vec![
                    PathBuf::from(r"C:\Program Files\Mozilla Firefox\firefox.exe"),
                    PathBuf::from(r"C:\Program Files (x86)\Mozilla Firefox\firefox.exe"),
                ],
                dirs::data_dir().map(|d| d.join(r"Mozilla\Firefox\Profiles")),
            ),
            BrowserType::Opera => (
                vec![], // User-specific path
                dirs::data_dir().map(|d| d.join(r"Opera Software\Opera Stable")),
            ),
            BrowserType::OperaGX => (
                vec![], // User-specific path
                dirs::data_dir().map(|d| d.join(r"Opera Software\Opera GX Stable")),
            ),
            BrowserType::Vivaldi => (
                vec![], // User-specific path
                dirs::data_local_dir().map(|d| d.join(r"Vivaldi\User Data\Default")),
            ),
            BrowserType::Yandex => (
                vec![], // User-specific path
                dirs::data_local_dir().map(|d| d.join(r"Yandex\YandexBrowser\User Data\Default")),
            ),
            BrowserType::Tor => (
                vec![], // Desktop path typically
                dirs::data_dir().map(|d| d.join(r"Tor Browser\Browser\TorBrowser\Data\Browser")),
            ),
        };

        // Check if executable exists
        for path in exe_paths {
            if path.exists() {
                browser.executable_path = Some(path);
                browser.is_installed = true;
                break;
            }
        }

        // Check profile path
        if let Some(profile) = profile_path {
            if profile.exists() {
                browser.profile_path = Some(profile);
                // If we found the profile but not the exe, still consider it installed
                // (user may have custom installation)
                if browser.executable_path.is_none() {
                    browser.is_installed = true;
                }
            }
        }

        // Check if this is the default browser
        browser.is_default = Self::is_default_windows(browser_type);

        if browser.is_installed {
            Some(browser)
        } else {
            None
        }
    }

    /// Check if a browser is the default on Windows
    #[cfg(windows)]
    fn is_default_windows(browser_type: BrowserType) -> bool {
        use winreg::enums::*;
        use winreg::RegKey;

        let hkcu = RegKey::predef(HKEY_CURRENT_USER);
        if let Ok(key) = hkcu.open_subkey(
            r"Software\Microsoft\Windows\Shell\Associations\UrlAssociations\http\UserChoice",
        ) {
            if let Ok(prog_id) = key.get_value::<String, _>("ProgId") {
                let expected_prog_id = browser_type.prog_id();
                // Handle wildcard for Tor
                if expected_prog_id.contains('*') {
                    let prefix = expected_prog_id.trim_end_matches('*');
                    return prog_id.starts_with(prefix);
                }
                return prog_id == expected_prog_id;
            }
        }
        false
    }

    /// Detect browsers on Linux
    #[cfg(target_os = "linux")]
    fn detect_linux(browser_type: BrowserType) -> Option<Browser> {
        let mut browser = Browser::new(browser_type);

        let exe_name = match browser_type {
            BrowserType::Chrome => "google-chrome",
            BrowserType::ChromeBeta => "google-chrome-beta",
            BrowserType::Chromium => "chromium-browser",
            BrowserType::Edge => "microsoft-edge",
            BrowserType::Brave => "brave-browser",
            BrowserType::Firefox => "firefox",
            BrowserType::Opera => "opera",
            BrowserType::OperaGX => "opera-gx",
            BrowserType::Vivaldi => "vivaldi",
            BrowserType::Yandex => "yandex-browser",
            BrowserType::Tor => "torbrowser",
        };

        // Check if executable is in PATH
        if let Ok(output) = std::process::Command::new("which").arg(exe_name).output() {
            if output.status.success() {
                let path = String::from_utf8_lossy(&output.stdout).trim().to_string();
                if !path.is_empty() {
                    browser.executable_path = Some(PathBuf::from(path));
                    browser.is_installed = true;
                }
            }
        }

        // Set profile paths
        if let Some(config_dir) = dirs::config_dir() {
            let profile_dir = match browser_type {
                BrowserType::Chrome => config_dir.join("google-chrome/Default"),
                BrowserType::ChromeBeta => config_dir.join("google-chrome-beta/Default"),
                BrowserType::Chromium => config_dir.join("chromium/Default"),
                BrowserType::Edge => config_dir.join("microsoft-edge/Default"),
                BrowserType::Brave => config_dir.join("BraveSoftware/Brave-Browser/Default"),
                BrowserType::Firefox => dirs::home_dir()
                    .map(|h| h.join(".mozilla/firefox"))
                    .unwrap_or_default(),
                BrowserType::Opera => config_dir.join("opera"),
                BrowserType::OperaGX => config_dir.join("opera-gx"),
                BrowserType::Vivaldi => config_dir.join("vivaldi/Default"),
                BrowserType::Yandex => config_dir.join("yandex-browser/Default"),
                BrowserType::Tor => dirs::home_dir()
                    .map(|h| h.join(".tor-browser"))
                    .unwrap_or_default(),
            };
            if profile_dir.exists() {
                browser.profile_path = Some(profile_dir);
            }
        }

        // Check default browser
        browser.is_default = Self::is_default_linux(browser_type);

        if browser.is_installed {
            Some(browser)
        } else {
            None
        }
    }

    /// Check if a browser is the default on Linux
    #[cfg(target_os = "linux")]
    fn is_default_linux(browser_type: BrowserType) -> bool {
        if let Ok(output) = std::process::Command::new("xdg-settings")
            .args(["get", "default-web-browser"])
            .output()
        {
            if output.status.success() {
                let default = String::from_utf8_lossy(&output.stdout)
                    .trim()
                    .to_lowercase();
                let short_name = browser_type.short_name().to_lowercase();
                return default.contains(&short_name);
            }
        }
        false
    }

    /// Detect browsers on macOS
    #[cfg(target_os = "macos")]
    fn detect_macos(browser_type: BrowserType) -> Option<Browser> {
        let mut browser = Browser::new(browser_type);

        let app_name = match browser_type {
            BrowserType::Chrome => "Google Chrome.app",
            BrowserType::ChromeBeta => "Google Chrome Beta.app",
            BrowserType::Chromium => "Chromium.app",
            BrowserType::Edge => "Microsoft Edge.app",
            BrowserType::Brave => "Brave Browser.app",
            BrowserType::Firefox => "Firefox.app",
            BrowserType::Opera => "Opera.app",
            BrowserType::OperaGX => "Opera GX.app",
            BrowserType::Vivaldi => "Vivaldi.app",
            BrowserType::Yandex => "Yandex.app",
            BrowserType::Tor => "Tor Browser.app",
        };

        // Check /Applications
        let app_path = PathBuf::from("/Applications").join(app_name);
        if app_path.exists() {
            browser.executable_path = Some(app_path.join("Contents/MacOS"));
            browser.is_installed = true;
        }

        // Check user Applications
        if let Some(home) = dirs::home_dir() {
            let user_app_path = home.join("Applications").join(app_name);
            if user_app_path.exists() {
                browser.executable_path = Some(user_app_path.join("Contents/MacOS"));
                browser.is_installed = true;
            }
        }

        // Set profile paths
        if let Some(app_support) = dirs::data_dir() {
            let profile_dir = match browser_type {
                BrowserType::Chrome => app_support.join("Google/Chrome/Default"),
                BrowserType::ChromeBeta => app_support.join("Google/Chrome Beta/Default"),
                BrowserType::Chromium => app_support.join("Chromium/Default"),
                BrowserType::Edge => app_support.join("Microsoft Edge/Default"),
                BrowserType::Brave => app_support.join("BraveSoftware/Brave-Browser/Default"),
                BrowserType::Firefox => app_support.join("Firefox/Profiles"),
                BrowserType::Opera => app_support.join("com.operasoftware.Opera"),
                BrowserType::OperaGX => app_support.join("com.operasoftware.OperaGX"),
                BrowserType::Vivaldi => app_support.join("Vivaldi/Default"),
                BrowserType::Yandex => app_support.join("Yandex/YandexBrowser/Default"),
                BrowserType::Tor => app_support.join("TorBrowser-Data/Browser"),
            };
            if profile_dir.exists() {
                browser.profile_path = Some(profile_dir);
            }
        }

        if browser.is_installed {
            Some(browser)
        } else {
            None
        }
    }

    /// Get the current default browser
    pub fn get_default_browser() -> Option<Browser> {
        Self::detect_all().into_iter().find(|b| b.is_default)
    }
}

/// Manage browser-specific authentication sessions
#[derive(Debug, Clone)]
pub struct BrowserAuthSession {
    /// The browser being used
    pub browser: Browser,
    /// Remote name prefix (browser-provider format)
    pub remote_prefix: String,
}

impl BrowserAuthSession {
    /// Create a new auth session for a browser
    pub fn new(browser: Browser, provider_name: &str) -> Self {
        let remote_prefix = format!("{}-{}", browser.short_name(), provider_name);
        Self {
            browser,
            remote_prefix,
        }
    }

    /// Generate a remote name for this session
    pub fn remote_name(&self, username: Option<&str>) -> String {
        match username {
            Some(user) => format!("{}-{}", self.remote_prefix, user),
            None => self.remote_prefix.clone(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_browser_type_all() {
        let all = BrowserType::all();
        assert!(!all.is_empty());
        assert!(all.contains(&BrowserType::Chrome));
        assert!(all.contains(&BrowserType::Firefox));
    }

    #[test]
    fn test_browser_type_display() {
        assert_eq!(BrowserType::Chrome.display_name(), "Google Chrome");
        assert_eq!(BrowserType::Edge.display_name(), "Microsoft Edge");
    }

    #[test]
    fn test_browser_type_short_name() {
        assert_eq!(BrowserType::Chrome.short_name(), "chrome");
        assert_eq!(BrowserType::Firefox.short_name(), "firefox");
    }

    #[test]
    fn test_browser_new() {
        let browser = Browser::new(BrowserType::Chrome);
        assert_eq!(browser.browser_type, BrowserType::Chrome);
        assert!(!browser.is_installed);
        assert!(!browser.is_default);
    }

    #[test]
    fn test_detect_all_runs() {
        // Just test that detection doesn't panic
        let browsers = BrowserDetector::detect_all();
        // We can't assert specific browsers are installed, but we can check the function runs
        for browser in &browsers {
            assert!(browser.is_installed);
        }
    }

    #[test]
    fn test_browser_auth_session() {
        let browser = Browser::new(BrowserType::Chrome);
        let session = BrowserAuthSession::new(browser, "gdrive");

        assert_eq!(session.remote_prefix, "chrome-gdrive");
        assert_eq!(session.remote_name(None), "chrome-gdrive");
        assert_eq!(
            session.remote_name(Some("user@example.com")),
            "chrome-gdrive-user@example.com"
        );
    }
}
