//! Screen rendering based on application state

use ratatui::Frame;

use crate::ui::screens::{
    auth::AuthScreen, browser_select::BrowserSelectScreen, case_setup::CaseSetupScreen,
    download::DownloadScreen, files::FilesScreen, provider_select::ProviderSelectScreen,
    report::ReportScreen,
};
use crate::ui::{App, AppState};

/// Render the current state into the frame
pub fn render_state(frame: &mut Frame, app: &App) {
    let area = frame.area();
    match app.state {
        AppState::CaseSetup => {
            let mut screen = CaseSetupScreen::new();
            screen.form = app.session_form.clone();
            frame.render_widget(&screen, area);
        }
        AppState::ProviderSelect => {
            let names = app
                .providers
                .iter()
                .map(|p| p.display_name().to_string())
                .collect::<Vec<_>>();
            let mut screen = ProviderSelectScreen::new(names);
            screen.list.selected = app.provider_selected;
            frame.render_widget(&screen, area);
        }
        AppState::BrowserSelect => {
            let mut names = Vec::new();
            names.push("System Default".to_string());
            for browser in &app.browsers {
                if browser.is_default {
                    names.push(format!("{} (default)", browser.display_name()));
                } else {
                    names.push(browser.display_name().to_string());
                }
            }
            let mut screen = BrowserSelectScreen::new(names);
            screen.list.selected = app.browser_selected;
            frame.render_widget(&screen, area);
        }
        AppState::Authenticating => {
            let name = app
                .chosen_provider
                .map(|p| p.display_name().to_string())
                .unwrap_or_else(|| "Provider".to_string());
            let status = if app.auth_status.is_empty() {
                "Opening browser...".to_string()
            } else {
                app.auth_status.clone()
            };
            let screen = AuthScreen::new(name, status);
            frame.render_widget(&screen, area);
        }
        AppState::FileList => {
            let entries = if app.file_entries.is_empty() {
                vec!["/".to_string()]
            } else {
                // Mark files that are selected for download with [x]
                app.file_entries
                    .iter()
                    .map(|e| {
                        if app.files_to_download.contains(e) {
                            format!("[x] {}", e)
                        } else {
                            format!("[ ] {}", e)
                        }
                    })
                    .collect()
            };
            let mut screen = FilesScreen::new(entries);
            screen.tree.selected = app.file_selected;
            frame.render_widget(&screen, area);
        }
        AppState::Downloading => {
            let mut screen = DownloadScreen::new();
            if !app.download_status.is_empty() {
                screen.overall.label = app.download_status.clone();
            }
            let overall_ratio = if let Some(total_bytes) = app.download_total_bytes {
                if total_bytes > 0 {
                    let done = app.download_done_bytes.min(total_bytes);
                    done as f64 / total_bytes as f64
                } else {
                    0.0
                }
            } else if app.download_progress.1 > 0 {
                app.download_progress.0 as f64 / app.download_progress.1 as f64
            } else {
                0.0
            };
            screen.overall.set_progress(overall_ratio);

            if let Some((done, total)) = app.download_current_bytes {
                if total > 0 {
                    screen.current.set_progress(done as f64 / total as f64);
                    screen.current.label =
                        format!("Current: {} / {} bytes", done, total);
                }
            }
            frame.render_widget(&screen, area);
        }
        AppState::Complete => {
            let lines = if app.report_lines.is_empty() {
                vec!["Complete".to_string(), "No errors".to_string()]
            } else {
                app.report_lines.clone()
            };
            let screen = ReportScreen::new(lines);
            frame.render_widget(&screen, area);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ratatui::backend::TestBackend;
    use ratatui::Terminal;

    #[test]
    fn test_render_state_all() {
        let backend = TestBackend::new(80, 24);
        let mut terminal = Terminal::new(backend).unwrap();

        for state in [
            AppState::CaseSetup,
            AppState::ProviderSelect,
            AppState::BrowserSelect,
            AppState::Authenticating,
            AppState::FileList,
            AppState::Downloading,
            AppState::Complete,
        ] {
            terminal
                .draw(|f| {
                    let mut app = App::new();
                    app.state = state;
                    app.provider_selected = 0;
                    render_state(f, &app);
                })
                .unwrap();
        }
    }
}
