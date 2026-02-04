//! Screen rendering based on application state

use ratatui::Frame;
use ratatui::layout::{Constraint, Direction, Layout, Rect};
use ratatui::text::Line;
use ratatui::widgets::{Block, Borders, Paragraph, Wrap};

use crate::ui::screens::{
    auth::AuthScreen, browser_select::BrowserSelectScreen, case_setup::CaseSetupScreen,
    download::DownloadScreen, files::FilesScreen, main_menu::MainMenuScreen,
    mode_confirm::ModeConfirmScreen,
    provider_select::ProviderSelectScreen, report::ReportScreen,
};
use crate::ui::{App, AppState};

/// Render the current state into the frame
pub fn render_state(frame: &mut Frame, app: &App) {
    let area = frame.area();
    match app.state {
        AppState::MainMenu => {
            let chunks = Layout::default()
                .direction(Direction::Vertical)
                .constraints([Constraint::Min(3), Constraint::Length(4)])
                .split(area);
            let labels = app
                .menu_items
                .iter()
                .map(|item| item.label.to_string())
                .collect::<Vec<_>>();
            let mut screen = MainMenuScreen::new(labels);
            screen.list.selected = app.menu_selected;
            frame.render_widget(&screen, chunks[0]);

            let description = app
                .menu_selected_item()
                .map(|item| item.description)
                .unwrap_or("Select an option to continue.");
            let status = if app.menu_status.is_empty() {
                None
            } else {
                Some(app.menu_status.clone())
            };
            let actions = "Actions: Authenticate • Retrieve list • Download CSV/XLSX • Mount • Silent/Smart Auth • Mobile Auth • Additional Options • Exit".to_string();
            let controls =
                "Up/Down select • Click select • Enter choose • Backspace back • q quit".to_string();
            let mut footer_lines = vec![Line::from(description)];
            if let Some(status) = status {
                footer_lines.push(Line::from(status));
            }
            footer_lines.push(Line::from(actions));
            footer_lines.push(Line::from(controls));
            let footer = Paragraph::new(footer_lines)
                .wrap(Wrap { trim: true });
            frame.render_widget(footer, chunks[1]);
        }
        AppState::AdditionalOptions => {
            let chunks = Layout::default()
                .direction(Direction::Vertical)
                .constraints([Constraint::Min(3), Constraint::Length(4)])
                .split(area);
            let labels = app
                .additional_menu_items
                .iter()
                .map(|item| item.label.to_string())
                .collect::<Vec<_>>();
            let mut screen = MainMenuScreen::new(labels);
            screen.list.selected = app.additional_menu_selected;
            frame.render_widget(&screen, chunks[0]);

            let description = app
                .additional_menu_selected_item()
                .map(|item| item.description)
                .unwrap_or("Select an option to continue.");
            let status = if app.menu_status.is_empty() {
                "Additional options".to_string()
            } else {
                app.menu_status.clone()
            };
            let controls =
                "Up/Down select • Click select • Enter choose • Backspace back • q quit".to_string();
            let footer = Paragraph::new(vec![Line::from(description), Line::from(status), Line::from(controls)])
                .wrap(Wrap { trim: true });
            frame.render_widget(footer, chunks[1]);
        }
        AppState::OneDriveMenu => {
            let chunks = Layout::default()
                .direction(Direction::Vertical)
                .constraints([Constraint::Min(3), Constraint::Length(4)])
                .split(area);
            let labels = app
                .onedrive_menu_items
                .iter()
                .map(|item| item.label.to_string())
                .collect::<Vec<_>>();
            let mut screen = MainMenuScreen::new(labels);
            screen.list.selected = app.onedrive_menu_selected;
            frame.render_widget(&screen, chunks[0]);

            let description = app
                .onedrive_menu_selected_item()
                .map(|item| item.description)
                .unwrap_or("Select an option to continue.");
            let status = if app.menu_status.is_empty() {
                "OneDrive utilities".to_string()
            } else {
                app.menu_status.clone()
            };
            let controls =
                "Up/Down select • Click select • Enter choose • Backspace back • q quit".to_string();
            let footer = Paragraph::new(vec![Line::from(description), Line::from(status), Line::from(controls)])
                .wrap(Wrap { trim: true });
            frame.render_widget(footer, chunks[1]);
        }
        AppState::ModeConfirm => {
            let chunks = Layout::default()
                .direction(Direction::Vertical)
                .constraints([Constraint::Min(3), Constraint::Length(3)])
                .split(area);
            let (title, description) = app
                .selected_action
                .and_then(|action| app.menu_items.iter().find(|item| item.action == action))
                .map(|item| (item.label.to_string(), item.description.to_string()))
                .unwrap_or_else(|| {
                    (
                        "Authenticate with the chosen Browsers & Providers".to_string(),
                        "Launch browser-based authentication on the suspect device for selected providers."
                            .to_string(),
                    )
                });
            let screen = ModeConfirmScreen::new(title, description);
            screen.render(frame, chunks[0]);

            let why =
                "Why this step: confirm the selected mode before creating a case and log chain."
                    .to_string();
            let controls = "Enter continue • Backspace back • q quit".to_string();
            let footer = Paragraph::new(vec![Line::from(why), Line::from(controls)])
                .wrap(Wrap { trim: true });
            frame.render_widget(footer, chunks[1]);
        }
        AppState::CaseSetup => {
            let chunks = Layout::default()
                .direction(Direction::Vertical)
                .constraints([Constraint::Min(3), Constraint::Length(3)])
                .split(area);
            let mut screen = CaseSetupScreen::new();
            screen.form = app.session_form.clone();
            frame.render_widget(&screen, chunks[0]);

            let mode = app
                .selected_action
                .and_then(|action| app.menu_items.iter().find(|item| item.action == action))
                .map(|item| format!("Mode: {}", item.label))
                .unwrap_or_else(|| "Mode: Authenticate (default)".to_string());
            let why = "Why this step: create a case folder and logging before contacting providers."
                .to_string();
            let controls = "Enter continue • Backspace back • q quit".to_string();
            let footer = Paragraph::new(vec![Line::from(mode), Line::from(why), Line::from(controls)])
                .wrap(Wrap { trim: true });
            frame.render_widget(footer, chunks[1]);
        }
        AppState::ProviderSelect => {
            let chunks = Layout::default()
                .direction(Direction::Vertical)
                .constraints([Constraint::Min(3), Constraint::Length(4)])
                .split(area);
            let content_chunks = Layout::default()
                .direction(Direction::Horizontal)
                .constraints([Constraint::Percentage(65), Constraint::Percentage(35)])
                .split(chunks[0]);
            let names = app
                .providers
                .iter()
                .map(|p| p.display_name().to_string())
                .collect::<Vec<_>>();
            let screen =
                ProviderSelectScreen::new(names, app.provider_checked.clone(), app.provider_selected);
            frame.render_widget(&screen, content_chunks[0]);

            let mode = app
                .selected_action
                .and_then(|action| app.menu_items.iter().find(|item| item.action == action))
                .map(|item| format!("Mode: {}", item.label))
                .unwrap_or_else(|| "Mode: Authenticate (default)".to_string());
            let status = if app.provider_status.is_empty() {
                format!("Providers: built-in ({})", app.providers.len())
            } else {
                app.provider_status.clone()
            };
            let last_update = app
                .provider_last_updated
                .as_ref()
                .map(|ts| ts.format("%Y-%m-%d %H:%M:%S").to_string())
                .unwrap_or_else(|| "never".to_string());
            let last_error = app
                .provider_last_error
                .as_deref()
                .unwrap_or("none");
            let show_status_panel = content_chunks[1].width >= 26 && content_chunks[1].height >= 6;
            if show_status_panel {
                let help_lines = vec![
                    Line::from(mode.clone()),
                    Line::from(format!("Providers: {}", app.providers.len())),
                    Line::from(format!("Last update: {}", last_update)),
                    Line::from(format!("Last error: {}", last_error)),
                    Line::from(format!("Status: {}", status)),
                    Line::from("Tip: Press r to refresh from rclone."),
                    Line::from("Tip: Press ? for provider help."),
                    Line::from("Next: Enter confirms selection → browser/auth flow."),
                ];
                let help = Paragraph::new(help_lines)
                    .block(Block::default().title("Status").borders(Borders::ALL))
                    .wrap(Wrap { trim: true });
                frame.render_widget(help, content_chunks[1]);
            }

            let controls = "Up/Down select • Space toggle • Enter confirm • r refresh • ? help • Backspace back • q quit".to_string();
            let footer_lines = if show_status_panel {
                vec![Line::from(mode), Line::from(controls)]
            } else {
                vec![
                    Line::from(mode),
                    Line::from(format!("Providers: {}", app.providers.len())),
                    Line::from(format!("Status: {}", status)),
                    Line::from(format!("Last error: {}", last_error)),
                    Line::from("Tip: Press r to refresh from rclone if the list looks short."),
                    Line::from("Next: Enter confirms selection → browser/auth flow."),
                    Line::from(controls),
                ]
            };
            let footer = Paragraph::new(footer_lines).wrap(Wrap { trim: true });
            frame.render_widget(footer, chunks[1]);

            if app.show_provider_help {
                let overlay = centered_rect(70, 60, area);
                let help_lines = vec![
                    Line::from("Provider list sources"),
                    Line::from(""),
                    Line::from("Built-in list: ships with the app for offline use."),
                    Line::from("Refresh: runs `rclone config providers --json`."),
                    Line::from("If refresh fails, the built-in list remains."),
                    Line::from("Set RCLONE_TRIAGE_DYNAMIC_PROVIDERS=0 to disable refresh."),
                    Line::from(""),
                    Line::from("Press ? or Esc to close."),
                ];
                let help = Paragraph::new(help_lines)
                    .block(Block::default().title("Provider Help").borders(Borders::ALL))
                    .wrap(Wrap { trim: true });
                frame.render_widget(help, overlay);
            }
        }
        AppState::MobileAuthFlow => {
            let chunks = Layout::default()
                .direction(Direction::Vertical)
                .constraints([Constraint::Min(3), Constraint::Length(4)])
                .split(area);
            let labels = app
                .mobile_flow_items
                .iter()
                .map(|item| item.label.to_string())
                .collect::<Vec<_>>();
            let mut screen = MainMenuScreen::new(labels);
            screen.list.selected = app.mobile_flow_selected;
            frame.render_widget(&screen, chunks[0]);

            let description = app
                .mobile_flow_selected_item()
                .map(|item| item.description)
                .unwrap_or("Select an authentication method.");
            let status = if app.menu_status.is_empty() {
                "Mobile device authentication".to_string()
            } else {
                app.menu_status.clone()
            };
            let controls =
                "Up/Down select • Click select • Enter choose • Backspace back • q quit".to_string();
            let footer = Paragraph::new(vec![Line::from(description), Line::from(status), Line::from(controls)])
                .wrap(Wrap { trim: true });
            frame.render_widget(footer, chunks[1]);
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
            let chunks = Layout::default()
                .direction(Direction::Vertical)
                .constraints([Constraint::Min(3), Constraint::Length(3)])
                .split(area);
            let screen =
                BrowserSelectScreen::new(names, app.browser_checked.clone(), app.browser_selected);
            frame.render_widget(&screen, chunks[0]);

            let next = "Next: Enter selects browser → authentication opens.";
            let status = if app.auth_status.is_empty() {
                "Select one or more browsers for authentication.".to_string()
            } else {
                app.auth_status.clone()
            };
            let controls =
                "Up/Down select • Space toggle • Enter confirm • Backspace back • q quit";
            let footer = Paragraph::new(vec![Line::from(next), Line::from(status), Line::from(controls)])
                .wrap(Wrap { trim: true });
            frame.render_widget(footer, chunks[1]);
        }
        AppState::Authenticating => {
            let name = app
                .chosen_provider
                .as_ref()
                .map(|p| p.display_name().to_string())
                .unwrap_or_else(|| "Provider".to_string());
            let status = if app.auth_status.is_empty() {
                "Opening browser...".to_string()
            } else {
                app.auth_status.clone()
            };
            let chunks = Layout::default()
                .direction(Direction::Vertical)
                .constraints([Constraint::Min(3), Constraint::Length(3)])
                .split(area);
            let screen = AuthScreen::new(name, status);
            frame.render_widget(&screen, chunks[0]);

            let hint =
                "What happens now: complete auth in the browser, then return here to continue.";
            let footer = Paragraph::new(vec![Line::from(hint)]).wrap(Wrap { trim: true });
            frame.render_widget(footer, chunks[1]);
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
            let chunks = Layout::default()
                .direction(Direction::Vertical)
                .constraints([Constraint::Min(3), Constraint::Length(3)])
                .split(area);
            let mut screen = FilesScreen::new(entries);
            screen.tree.selected = app.file_selected;
            frame.render_widget(&screen, chunks[0]);

            let (hint, controls) = match app.selected_action {
                Some(crate::ui::MenuAction::MountProvider) => {
                    let mount_hint = app
                        .mounted_remote
                        .as_ref()
                        .map(|m| format!("Mounted at {:?}. Press 'u' to unmount.", m.mount_point()))
                        .unwrap_or_else(|| "Press 'm' to mount the remote.".to_string());
                    (
                        mount_hint,
                        "m mount • u unmount • Backspace back • q quit".to_string(),
                    )
                }
                Some(crate::ui::MenuAction::RetrieveList) => (
                    "Listing complete: select files to download or press Backspace to return."
                        .to_string(),
                    "Up/Down select • Space toggle • Enter download • Backspace back • q quit"
                        .to_string(),
                ),
                _ => (
                    "What happens now: select files (toggle) then press Enter to start download."
                        .to_string(),
                    "Up/Down select • Space toggle • Enter download • Backspace back • q quit"
                        .to_string(),
                ),
            };
            let footer = Paragraph::new(vec![Line::from(hint), Line::from(controls)])
                .wrap(Wrap { trim: true });
            frame.render_widget(footer, chunks[1]);
        }
        AppState::Downloading => {
            let chunks = Layout::default()
                .direction(Direction::Vertical)
                .constraints([Constraint::Min(3), Constraint::Length(3)])
                .split(area);
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
            frame.render_widget(&screen, chunks[0]);

            let hint =
                "What happens now: downloads run sequentially; progress and logs update below.";
            let footer = Paragraph::new(vec![Line::from(hint)]).wrap(Wrap { trim: true });
            frame.render_widget(footer, chunks[1]);
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

fn centered_rect(percent_x: u16, percent_y: u16, area: Rect) -> Rect {
    let popup_layout = Layout::default()
        .direction(Direction::Vertical)
        .constraints([
            Constraint::Percentage((100 - percent_y) / 2),
            Constraint::Percentage(percent_y),
            Constraint::Percentage((100 - percent_y) / 2),
        ])
        .split(area);

    let vertical = popup_layout[1];
    let horizontal_layout = Layout::default()
        .direction(Direction::Horizontal)
        .constraints([
            Constraint::Percentage((100 - percent_x) / 2),
            Constraint::Percentage(percent_x),
            Constraint::Percentage((100 - percent_x) / 2),
        ])
        .split(vertical);

    horizontal_layout[1]
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
            AppState::MainMenu,
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
