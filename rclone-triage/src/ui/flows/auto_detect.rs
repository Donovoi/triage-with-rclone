use anyhow::{bail, Result};
use ratatui::Terminal;

use crate::ui::render::render_state;
use crate::ui::{App, AppState, AuthBatchTask};

pub(crate) fn perform_detection_flow<B: ratatui::backend::Backend>(
    app: &mut App,
    terminal: &mut Terminal<B>,
) -> Result<()> {
    app.state = AppState::DetectingAccounts;
    app.detected_accounts.status =
        "Scanning installed browsers and known profile roots for likely provider accounts..."
            .to_string();
    terminal.draw(|f| render_state(f, app))?;

    match crate::providers::account_detection::detect_accounts() {
        Ok(report) => {
            let summary = report.summary_line();
            app.load_detected_accounts(report);
            app.detected_accounts.status = summary.clone();
            app.state = AppState::ReviewDetectedAccounts;
            app.log_info(summary);
        }
        Err(error) => {
            let message = format!("Automatic account detection failed: {}", error);
            app.detected_accounts.report = None;
            app.detected_accounts.checked.clear();
            app.detected_accounts.selected = 0;
            app.detected_accounts.status = message.clone();
            app.state = AppState::ReviewDetectedAccounts;
            app.log_error(message);
        }
    }

    Ok(())
}

pub(crate) fn build_auth_tasks_from_detected_accounts(app: &App) -> Result<Vec<AuthBatchTask>> {
    let selected = app.selected_detected_accounts();
    if selected.is_empty() {
        bail!("Select at least one runnable detected account.");
    }

    Ok(selected
        .into_iter()
        .map(|candidate| AuthBatchTask {
            provider: crate::providers::ProviderEntry::from_known(candidate.provider),
            browser: Some(candidate.browser_profile.browser),
        })
        .collect())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::providers::account_detection::{
        BrowserProfileSource, DetectedAccountCandidate, DetectedBrowserProfile,
        DetectionCapability, DetectionConfidence, DetectionReport,
    };
    use crate::providers::browser::{Browser, BrowserType};
    use crate::providers::CloudProvider;
    use std::path::PathBuf;

    fn sample_candidate(
        provider: CloudProvider,
        capability: DetectionCapability,
        profile_path: &str,
    ) -> DetectedAccountCandidate {
        let mut browser = Browser::new(BrowserType::Chrome);
        browser.is_installed = true;
        browser.executable_path = Some(PathBuf::from("/usr/bin/google-chrome"));
        browser.profile_path = Some(PathBuf::from(profile_path));

        DetectedAccountCandidate {
            provider,
            browser_profile: DetectedBrowserProfile {
                browser,
                source: BrowserProfileSource::InstalledBrowser,
                profile_name: PathBuf::from(profile_path)
                    .file_name()
                    .and_then(|name| name.to_str())
                    .unwrap_or("Default")
                    .to_string(),
            },
            capability,
            confidence: DetectionConfidence::High,
            user_hint: Some("analyst@example.com".to_string()),
            evidence: Vec::new(),
            hint_reason: None,
        }
    }

    #[test]
    fn test_build_auth_tasks_from_detected_accounts_preserves_profile_path() {
        let mut app = App::new();
        app.state = AppState::ReviewDetectedAccounts;
        app.load_detected_accounts(DetectionReport {
            scanned_profiles: Vec::new(),
            candidates: vec![sample_candidate(
                CloudProvider::GoogleDrive,
                DetectionCapability::RunnableAuth,
                "/profiles/Profile 1",
            )],
            errors: Vec::new(),
        });

        let tasks = build_auth_tasks_from_detected_accounts(&app).unwrap();
        let expected_profile_path = PathBuf::from("/profiles/Profile 1");

        assert_eq!(tasks.len(), 1);
        assert_eq!(tasks[0].provider.id, "drive");
        assert_eq!(
            tasks[0]
                .browser
                .as_ref()
                .and_then(|browser| browser.profile_path.as_deref()),
            Some(expected_profile_path.as_path())
        );
    }

    #[test]
    fn test_build_auth_tasks_from_detected_accounts_skips_hint_only_findings() {
        let mut app = App::new();
        app.state = AppState::ReviewDetectedAccounts;
        app.load_detected_accounts(DetectionReport {
            scanned_profiles: Vec::new(),
            candidates: vec![sample_candidate(
                CloudProvider::OneDrive,
                DetectionCapability::HintOnly,
                "/profiles/Profile 2",
            )],
            errors: Vec::new(),
        });

        let error = build_auth_tasks_from_detected_accounts(&app).unwrap_err();
        assert!(error.to_string().contains("Select at least one runnable detected account"));
    }
}