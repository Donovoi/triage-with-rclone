//! Screen rendering based on application state

use ratatui::Frame;

use crate::ui::screens::{
    auth::AuthScreen, case_setup::CaseSetupScreen, download::DownloadScreen, files::FilesScreen,
    provider_select::ProviderSelectScreen, report::ReportScreen, welcome::WelcomeScreen,
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
