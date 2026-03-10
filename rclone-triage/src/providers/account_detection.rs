//! Automatic browser/profile-based account detection.
//!
//! Scans installed browsers and known browser profile roots, then reuses the
//! existing session extraction pipeline to identify likely cloud-provider
//! accounts. The resulting candidates are classified as either runnable
//! authentication targets or hint-only findings.

use anyhow::Result;
use std::collections::{HashMap, HashSet};
use std::path::{Path, PathBuf};

use super::browser::{Browser, BrowserDetector, BrowserType};
use super::session::{BrowserSession, ProviderCookieConfig, SessionExtractor};
use super::CloudProvider;

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum BrowserProfileSource {
    InstalledBrowser,
    KnownProfileRoot(PathBuf),
}

impl BrowserProfileSource {
    pub fn summary(&self) -> String {
        match self {
            BrowserProfileSource::InstalledBrowser => "Installed browser".to_string(),
            BrowserProfileSource::KnownProfileRoot(root) => {
                format!("Known profile root ({})", root.display())
            }
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DetectionCapability {
    RunnableAuth,
    HintOnly,
}

impl DetectionCapability {
    pub fn is_runnable(self) -> bool {
        matches!(self, DetectionCapability::RunnableAuth)
    }

    pub fn label(self) -> &'static str {
        match self {
            DetectionCapability::RunnableAuth => "Runnable auth",
            DetectionCapability::HintOnly => "Hint only",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum DetectionConfidence {
    Low,
    Medium,
    High,
}

impl DetectionConfidence {
    pub fn label(self) -> &'static str {
        match self {
            DetectionConfidence::High => "High",
            DetectionConfidence::Medium => "Medium",
            DetectionConfidence::Low => "Low",
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DetectionEvidence {
    pub label: String,
    pub detail: String,
}

impl DetectionEvidence {
    pub fn new(label: impl Into<String>, detail: impl Into<String>) -> Self {
        Self {
            label: label.into(),
            detail: detail.into(),
        }
    }
}

#[derive(Debug, Clone)]
pub struct DetectedBrowserProfile {
    pub browser: Browser,
    pub source: BrowserProfileSource,
    pub profile_name: String,
}

impl DetectedBrowserProfile {
    pub fn profile_path(&self) -> Option<&Path> {
        self.browser.profile_path.as_deref()
    }

    pub fn profile_display_name(&self) -> String {
        format!("{} [{}]", self.browser.display_name(), self.profile_name)
    }
}

#[derive(Debug, Clone)]
pub struct DetectedAccountCandidate {
    pub provider: CloudProvider,
    pub browser_profile: DetectedBrowserProfile,
    pub capability: DetectionCapability,
    pub confidence: DetectionConfidence,
    pub user_hint: Option<String>,
    pub evidence: Vec<DetectionEvidence>,
    pub hint_reason: Option<String>,
}

impl DetectedAccountCandidate {
    pub fn is_runnable(&self) -> bool {
        self.capability.is_runnable()
    }

    pub fn selection_allowed(&self) -> bool {
        self.is_runnable()
    }

    pub fn account_label(&self) -> &str {
        self.user_hint
            .as_deref()
            .filter(|hint| !hint.trim().is_empty())
            .unwrap_or("account not identified")
    }

    pub fn list_label(&self) -> String {
        format!(
            "{} via {} — {} ({})",
            self.provider.display_name(),
            self.browser_profile.profile_display_name(),
            self.account_label(),
            self.capability.label()
        )
    }
}

#[derive(Debug, Clone, Default)]
pub struct DetectionReport {
    pub scanned_profiles: Vec<DetectedBrowserProfile>,
    pub candidates: Vec<DetectedAccountCandidate>,
    pub errors: Vec<String>,
}

impl DetectionReport {
    pub fn runnable_count(&self) -> usize {
        self.candidates
            .iter()
            .filter(|candidate| candidate.is_runnable())
            .count()
    }

    pub fn hint_only_count(&self) -> usize {
        self.candidates
            .iter()
            .filter(|candidate| !candidate.is_runnable())
            .count()
    }

    pub fn summary_line(&self) -> String {
        let mut summary = format!(
            "Scanned {} browser profile(s); found {} runnable candidate(s) and {} hint-only finding(s).",
            self.scanned_profiles.len(),
            self.runnable_count(),
            self.hint_only_count(),
        );

        if !self.errors.is_empty() {
            summary.push_str(&format!(" {} scan warning(s) recorded.", self.errors.len()));
        }

        summary
    }
}

pub fn detect_accounts() -> Result<DetectionReport> {
    let extractor = SessionExtractor::new()?;
    let scanned_profiles = collect_detected_browser_profiles();
    let mut report = DetectionReport {
        scanned_profiles,
        candidates: Vec::new(),
        errors: Vec::new(),
    };

    for profile in &report.scanned_profiles {
        for provider in detectable_providers() {
            match extractor.extract_session(&profile.browser, provider) {
                Ok(session) => {
                    if let Some(candidate) = classify_candidate(profile, provider, &session) {
                        report.candidates.push(candidate);
                    }
                }
                Err(error) => {
                    report.errors.push(format!(
                        "{} / {} / {}: {}",
                        provider.display_name(),
                        profile.browser.display_name(),
                        profile.profile_name,
                        error
                    ));
                }
            }
        }
    }

    sort_detection_report(&mut report);
    Ok(report)
}

fn sort_detection_report(report: &mut DetectionReport) {
    report.scanned_profiles.sort_by(|left, right| {
        right
            .browser
            .is_default
            .cmp(&left.browser.is_default)
            .then_with(|| {
                left.browser
                    .display_name()
                    .cmp(right.browser.display_name())
            })
            .then_with(|| left.profile_name.cmp(&right.profile_name))
            .then_with(|| {
                left.profile_path()
                    .map(|path| path.display().to_string())
                    .cmp(&right.profile_path().map(|path| path.display().to_string()))
            })
    });

    report.candidates.sort_by(|left, right| {
        right
            .is_runnable()
            .cmp(&left.is_runnable())
            .then_with(|| right.confidence.cmp(&left.confidence))
            .then_with(|| {
                left.provider
                    .display_name()
                    .cmp(right.provider.display_name())
            })
            .then_with(|| {
                left.browser_profile
                    .browser
                    .display_name()
                    .cmp(right.browser_profile.browser.display_name())
            })
            .then_with(|| {
                left.browser_profile
                    .profile_name
                    .cmp(&right.browser_profile.profile_name)
            })
            .then_with(|| left.account_label().cmp(right.account_label()))
    });
}

fn detectable_providers() -> Vec<CloudProvider> {
    CloudProvider::all()
        .iter()
        .copied()
        .filter(|provider| {
            let config = ProviderCookieConfig::for_provider(*provider);
            !config.domains.is_empty() && !config.auth_cookies.is_empty()
        })
        .collect()
}

fn collect_detected_browser_profiles() -> Vec<DetectedBrowserProfile> {
    let installed_map: HashMap<BrowserType, Browser> = BrowserDetector::detect_all()
        .into_iter()
        .map(|browser| (browser.browser_type, browser))
        .collect();

    let mut profiles: HashMap<(BrowserType, PathBuf), DetectedBrowserProfile> = HashMap::new();

    for browser_type in BrowserType::all().iter().copied() {
        let template = installed_map
            .get(&browser_type)
            .cloned()
            .unwrap_or_else(|| Browser::new(browser_type));

        if let Some(profile_path) = template.profile_path.clone() {
            insert_detected_profile(
                &mut profiles,
                profile_from_path(
                    &template,
                    profile_path,
                    BrowserProfileSource::InstalledBrowser,
                ),
            );
        }

        for root in known_profile_roots(browser_type)
            .into_iter()
            .chain(derived_profile_roots(browser_type, &template))
        {
            for profile_path in enumerate_profile_paths(browser_type, &root) {
                insert_detected_profile(
                    &mut profiles,
                    profile_from_path(
                        &template,
                        profile_path,
                        BrowserProfileSource::KnownProfileRoot(root.clone()),
                    ),
                );
            }
        }
    }

    profiles.into_values().collect()
}

fn insert_detected_profile(
    profiles: &mut HashMap<(BrowserType, PathBuf), DetectedBrowserProfile>,
    incoming: DetectedBrowserProfile,
) {
    let Some(profile_path) = incoming.profile_path().map(Path::to_path_buf) else {
        return;
    };

    let key = (incoming.browser.browser_type, profile_path);
    match profiles.get_mut(&key) {
        Some(existing) => merge_detected_profiles(existing, incoming),
        None => {
            profiles.insert(key, incoming);
        }
    }
}

fn merge_detected_profiles(
    existing: &mut DetectedBrowserProfile,
    incoming: DetectedBrowserProfile,
) {
    if source_priority(&incoming.source) > source_priority(&existing.source) {
        existing.source = incoming.source.clone();
    }

    if existing.browser.executable_path.is_none() && incoming.browser.executable_path.is_some() {
        existing.browser.executable_path = incoming.browser.executable_path.clone();
        existing.browser.is_installed = incoming.browser.is_installed;
    }

    if !existing.browser.is_default && incoming.browser.is_default {
        existing.browser.is_default = true;
    }
}

fn source_priority(source: &BrowserProfileSource) -> u8 {
    match source {
        BrowserProfileSource::InstalledBrowser => 2,
        BrowserProfileSource::KnownProfileRoot(_) => 1,
    }
}

fn profile_from_path(
    template: &Browser,
    profile_path: PathBuf,
    source: BrowserProfileSource,
) -> DetectedBrowserProfile {
    let profile_name = profile_name_from_path(&profile_path);
    let mut browser = template.clone();
    browser.profile_path = Some(profile_path);

    DetectedBrowserProfile {
        browser,
        source,
        profile_name,
    }
}

fn profile_name_from_path(path: &Path) -> String {
    path.file_name()
        .and_then(|name| name.to_str())
        .filter(|name| !name.trim().is_empty())
        .map(|name| name.to_string())
        .unwrap_or_else(|| path.display().to_string())
}

fn derived_profile_roots(browser_type: BrowserType, browser: &Browser) -> Vec<PathBuf> {
    let mut roots = Vec::new();
    if let Some(profile_path) = browser.profile_path.as_deref() {
        let root = if is_chromium_family(browser_type)
            && browser_profile_has_session_store(browser_type, profile_path)
        {
            profile_path.parent().unwrap_or(profile_path).to_path_buf()
        } else {
            profile_path.to_path_buf()
        };
        roots.push(root);
    }
    dedupe_paths(roots)
}

fn known_profile_roots(browser_type: BrowserType) -> Vec<PathBuf> {
    let mut roots = Vec::new();

    #[cfg(target_os = "linux")]
    {
        if let Some(config_dir) = dirs::config_dir() {
            let config_root = match browser_type {
                BrowserType::Chrome => Some(config_dir.join("google-chrome")),
                BrowserType::ChromeBeta => Some(config_dir.join("google-chrome-beta")),
                BrowserType::Chromium => Some(config_dir.join("chromium")),
                BrowserType::Edge => Some(config_dir.join("microsoft-edge")),
                BrowserType::Brave => Some(config_dir.join("BraveSoftware/Brave-Browser")),
                BrowserType::Opera => Some(config_dir.join("opera")),
                BrowserType::OperaGX => Some(config_dir.join("opera-gx")),
                BrowserType::Vivaldi => Some(config_dir.join("vivaldi")),
                BrowserType::Yandex => Some(config_dir.join("yandex-browser")),
                BrowserType::Firefox | BrowserType::Tor => None,
            };

            if let Some(root) = config_root {
                roots.push(root);
            }
        }

        if let Some(home) = dirs::home_dir() {
            match browser_type {
                BrowserType::Firefox => roots.push(home.join(".mozilla/firefox")),
                BrowserType::Tor => roots.push(home.join(".tor-browser")),
                _ => {}
            }
        }
    }

    #[cfg(windows)]
    {
        if let Some(local) = dirs::data_local_dir() {
            let local_root = match browser_type {
                BrowserType::Chrome => Some(local.join(r"Google\Chrome\User Data")),
                BrowserType::ChromeBeta => Some(local.join(r"Google\Chrome Beta\User Data")),
                BrowserType::Chromium => Some(local.join(r"Chromium\User Data")),
                BrowserType::Edge => Some(local.join(r"Microsoft\Edge\User Data")),
                BrowserType::Brave => Some(local.join(r"BraveSoftware\Brave-Browser\User Data")),
                BrowserType::Vivaldi => Some(local.join(r"Vivaldi\User Data")),
                BrowserType::Yandex => Some(local.join(r"Yandex\YandexBrowser\User Data")),
                BrowserType::Firefox
                | BrowserType::Opera
                | BrowserType::OperaGX
                | BrowserType::Tor => None,
            };

            if let Some(root) = local_root {
                roots.push(root);
            }
        }

        if let Some(data) = dirs::data_dir() {
            let roaming_root = match browser_type {
                BrowserType::Firefox => Some(data.join(r"Mozilla\Firefox\Profiles")),
                BrowserType::Opera => Some(data.join(r"Opera Software\Opera Stable")),
                BrowserType::OperaGX => Some(data.join(r"Opera Software\Opera GX Stable")),
                BrowserType::Tor => Some(data.join(r"Tor Browser\Browser\TorBrowser\Data\Browser")),
                _ => None,
            };

            if let Some(root) = roaming_root {
                roots.push(root);
            }
        }
    }

    #[cfg(target_os = "macos")]
    {
        if let Some(data_dir) = dirs::data_dir() {
            let root = match browser_type {
                BrowserType::Chrome => Some(data_dir.join("Google/Chrome")),
                BrowserType::ChromeBeta => Some(data_dir.join("Google/Chrome Beta")),
                BrowserType::Chromium => Some(data_dir.join("Chromium")),
                BrowserType::Edge => Some(data_dir.join("Microsoft Edge")),
                BrowserType::Brave => Some(data_dir.join("BraveSoftware/Brave-Browser")),
                BrowserType::Firefox => Some(data_dir.join("Firefox/Profiles")),
                BrowserType::Opera => Some(data_dir.join("com.operasoftware.Opera")),
                BrowserType::OperaGX => Some(data_dir.join("com.operasoftware.OperaGX")),
                BrowserType::Vivaldi => Some(data_dir.join("Vivaldi")),
                BrowserType::Yandex => Some(data_dir.join("Yandex/YandexBrowser")),
                BrowserType::Tor => Some(data_dir.join("TorBrowser-Data/Browser")),
            };

            if let Some(root) = root {
                roots.push(root);
            }
        }
    }

    dedupe_paths(roots)
}

fn dedupe_paths(paths: Vec<PathBuf>) -> Vec<PathBuf> {
    let mut seen = HashSet::new();
    paths
        .into_iter()
        .filter(|path| seen.insert(path.clone()))
        .collect()
}

fn enumerate_profile_paths(browser_type: BrowserType, root: &Path) -> Vec<PathBuf> {
    if !root.exists() {
        return Vec::new();
    }

    let mut profiles = Vec::new();
    if browser_profile_has_session_store(browser_type, root) {
        profiles.push(root.to_path_buf());
    }

    if let Ok(entries) = std::fs::read_dir(root) {
        for entry in entries.flatten() {
            let path = entry.path();
            if !path.is_dir() {
                continue;
            }
            if browser_profile_has_session_store(browser_type, &path) {
                profiles.push(path);
            }
        }
    }

    profiles.sort_by_key(|path| path.display().to_string());
    profiles.dedup();
    profiles
}

fn browser_profile_has_session_store(browser_type: BrowserType, path: &Path) -> bool {
    match browser_type {
        BrowserType::Firefox | BrowserType::Tor => path.join("cookies.sqlite").exists(),
        _ => path.join("Cookies").exists() || path.join("Network").join("Cookies").exists(),
    }
}

fn is_chromium_family(browser_type: BrowserType) -> bool {
    !matches!(browser_type, BrowserType::Firefox | BrowserType::Tor)
}

fn classify_candidate(
    profile: &DetectedBrowserProfile,
    provider: CloudProvider,
    session: &BrowserSession,
) -> Option<DetectedAccountCandidate> {
    if session.cookies.is_empty() {
        return None;
    }

    let config = ProviderCookieConfig::for_provider(provider);
    let auth_cookie_hits = session
        .cookies
        .iter()
        .filter(|cookie| {
            config
                .auth_cookies
                .iter()
                .any(|name| cookie.name.eq_ignore_ascii_case(name))
                && !cookie.is_expired()
        })
        .count();
    let identity_cookie_hits = session
        .cookies
        .iter()
        .filter(|cookie| {
            config
                .identity_cookies
                .iter()
                .any(|name| cookie.name.eq_ignore_ascii_case(name))
        })
        .count();

    let is_runnable = session.is_valid
        && profile.browser.is_installed
        && profile.browser.executable_path.is_some()
        && profile.browser.profile_path.is_some();
    let capability = if is_runnable {
        DetectionCapability::RunnableAuth
    } else {
        DetectionCapability::HintOnly
    };

    let user_hint = session
        .user_hint
        .as_deref()
        .map(str::trim)
        .filter(|hint| !hint.is_empty())
        .map(|hint| hint.to_string());

    let confidence = match (capability, user_hint.is_some()) {
        (DetectionCapability::RunnableAuth, true) => DetectionConfidence::High,
        (DetectionCapability::RunnableAuth, false) => DetectionConfidence::Medium,
        (DetectionCapability::HintOnly, true) => DetectionConfidence::Medium,
        (DetectionCapability::HintOnly, false) => DetectionConfidence::Low,
    };

    let hint_reason = if is_runnable {
        None
    } else if !session.is_valid {
        Some("Reusable authenticated session could not be confirmed.".to_string())
    } else if profile.browser.executable_path.is_none() {
        Some("Browser profile was found, but the browser executable is unavailable.".to_string())
    } else {
        Some("Profile can only be treated as an investigative hint.".to_string())
    };

    let mut evidence = vec![
        DetectionEvidence::new("Source", profile.source.summary()),
        DetectionEvidence::new(
            "Profile path",
            profile
                .profile_path()
                .map(|path| path.display().to_string())
                .unwrap_or_else(|| "unknown".to_string()),
        ),
        DetectionEvidence::new("Provider cookies", session.cookies.len().to_string()),
        DetectionEvidence::new("Auth cookie hits", auth_cookie_hits.to_string()),
    ];

    if identity_cookie_hits > 0 {
        evidence.push(DetectionEvidence::new(
            "Identity cookie hits",
            identity_cookie_hits.to_string(),
        ));
    }

    if let Some(user) = user_hint.as_ref() {
        evidence.push(DetectionEvidence::new("Account hint", user.clone()));
    }

    if let Some(reason) = hint_reason.as_ref() {
        evidence.push(DetectionEvidence::new(
            "Why not auto-runnable",
            reason.clone(),
        ));
    }

    Some(DetectedAccountCandidate {
        provider,
        browser_profile: profile.clone(),
        capability,
        confidence,
        user_hint,
        evidence,
        hint_reason,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::providers::browser::BrowserType;
    use crate::providers::session::Cookie;

    fn sample_cookie(name: &str) -> Cookie {
        Cookie {
            name: name.to_string(),
            value: "value".to_string(),
            domain: ".example.com".to_string(),
            path: "/".to_string(),
            expires: 4_102_444_800,
            secure: true,
            http_only: true,
        }
    }

    fn sample_profile() -> DetectedBrowserProfile {
        let mut browser = Browser::new(BrowserType::Chrome);
        browser.is_installed = true;
        browser.is_default = true;
        browser.executable_path = Some(PathBuf::from("/usr/bin/google-chrome"));
        browser.profile_path = Some(PathBuf::from("/profiles/Default"));

        DetectedBrowserProfile {
            browser,
            source: BrowserProfileSource::InstalledBrowser,
            profile_name: "Default".to_string(),
        }
    }

    #[test]
    fn test_classify_candidate_marks_valid_session_as_runnable() {
        let profile = sample_profile();
        let session = BrowserSession {
            browser_type: BrowserType::Chrome,
            provider: CloudProvider::GoogleDrive,
            cookies: vec![sample_cookie("SID"), sample_cookie("ACCOUNT_CHOOSER")],
            user_hint: Some("analyst@example.com".to_string()),
            is_valid: true,
            local_state_key: None,
        };

        let candidate = classify_candidate(&profile, CloudProvider::GoogleDrive, &session)
            .expect("candidate should be created");

        assert_eq!(candidate.capability, DetectionCapability::RunnableAuth);
        assert_eq!(candidate.confidence, DetectionConfidence::High);
        assert!(candidate.selection_allowed());
        assert_eq!(candidate.account_label(), "analyst@example.com");
    }

    #[test]
    fn test_classify_candidate_marks_missing_executable_as_hint_only() {
        let mut profile = sample_profile();
        profile.browser.executable_path = None;
        profile.browser.is_installed = false;

        let session = BrowserSession {
            browser_type: BrowserType::Chrome,
            provider: CloudProvider::GoogleDrive,
            cookies: vec![sample_cookie("SID")],
            user_hint: Some("hint@example.com".to_string()),
            is_valid: true,
            local_state_key: None,
        };

        let candidate = classify_candidate(&profile, CloudProvider::GoogleDrive, &session)
            .expect("candidate should be created");

        assert_eq!(candidate.capability, DetectionCapability::HintOnly);
        assert_eq!(candidate.confidence, DetectionConfidence::Medium);
        assert!(!candidate.selection_allowed());
        assert!(candidate
            .hint_reason
            .as_deref()
            .unwrap_or_default()
            .contains("executable"));
    }

    #[test]
    fn test_enumerate_profile_paths_finds_chromium_profiles() {
        let temp = tempfile::tempdir().unwrap();
        let root = temp.path();
        std::fs::create_dir_all(root.join("Default").join("Network")).unwrap();
        std::fs::write(root.join("Default").join("Network").join("Cookies"), b"db").unwrap();
        std::fs::create_dir_all(root.join("Profile 1")).unwrap();
        std::fs::write(root.join("Profile 1").join("Cookies"), b"db").unwrap();
        std::fs::create_dir_all(root.join("Ignored")).unwrap();

        let profiles = enumerate_profile_paths(BrowserType::Chrome, root);

        assert_eq!(profiles.len(), 2);
        assert!(profiles.iter().any(|path| path.ends_with("Default")));
        assert!(profiles.iter().any(|path| path.ends_with("Profile 1")));
    }

    #[test]
    fn test_enumerate_profile_paths_finds_firefox_profiles() {
        let temp = tempfile::tempdir().unwrap();
        let root = temp.path();
        std::fs::create_dir_all(root.join("abcd.default-release")).unwrap();
        std::fs::write(
            root.join("abcd.default-release").join("cookies.sqlite"),
            b"db",
        )
        .unwrap();

        let profiles = enumerate_profile_paths(BrowserType::Firefox, root);

        assert_eq!(profiles, vec![root.join("abcd.default-release")]);
    }

    #[test]
    fn test_detection_report_summary_counts_runnable_and_hints() {
        let profile = sample_profile();
        let runnable = DetectedAccountCandidate {
            provider: CloudProvider::GoogleDrive,
            browser_profile: profile.clone(),
            capability: DetectionCapability::RunnableAuth,
            confidence: DetectionConfidence::High,
            user_hint: Some("analyst@example.com".to_string()),
            evidence: Vec::new(),
            hint_reason: None,
        };
        let hint = DetectedAccountCandidate {
            provider: CloudProvider::OneDrive,
            browser_profile: profile,
            capability: DetectionCapability::HintOnly,
            confidence: DetectionConfidence::Low,
            user_hint: None,
            evidence: Vec::new(),
            hint_reason: Some("Investigative hint".to_string()),
        };

        let report = DetectionReport {
            scanned_profiles: Vec::new(),
            candidates: vec![runnable, hint],
            errors: vec!["warning".to_string()],
        };

        assert_eq!(report.runnable_count(), 1);
        assert_eq!(report.hint_only_count(), 1);
        assert!(report.summary_line().contains("1 runnable candidate"));
        assert!(report.summary_line().contains("1 hint-only finding"));
        assert!(report.summary_line().contains("1 scan warning"));
    }
}
