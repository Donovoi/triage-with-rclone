//! Screen rendering based on application state

use ratatui::Frame;
use ratatui::layout::{Constraint, Direction, Layout, Rect};
use ratatui::text::Line;
use ratatui::widgets::{Block, Borders, Paragraph, Wrap};

use crate::ui::screens::{
    auth::AuthScreen, browser_select::BrowserSelectScreen, case_setup::CaseSetupScreen,
    download::DownloadScreen, files::FilesScreen, main_menu::MainMenuScreen,
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
            let controls =
                "Up/Down select • Click select • Enter choose • Backspace back • q quit".to_string();
            let footer = Paragraph::new(vec![Line::from(description), Line::from(controls)])
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
            let controls =
                "Enter continue • Backspace back • q quit".to_string();
            let footer = Paragraph::new(vec![Line::from(mode), Line::from(controls)])
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
            let mut screen = ProviderSelectScreen::new(names);
            screen.list.selected = app.provider_selected;
            frame.render_widget(&screen, content_chunks[0]);

            let status = if app.provider_status.is_empty() {
                "Using built-in providers.".to_string()
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
            let help_lines = vec![
                Line::from(format!("Providers: {}", app.providers.len())),
                Line::from(format!("Last update: {}", last_update)),
                Line::from(format!("Last error: {}", last_error)),
                Line::from(format!("Status: {}", status)),
                Line::from("Tip: Press r to refresh from rclone."),
                Line::from("Tip: Press ? for provider help."),
                Line::from("Tip: Enter selects provider."),
            ];
            let help = Paragraph::new(help_lines)
                .block(Block::default().title("Status").borders(Borders::ALL))
                .wrap(Wrap { trim: true });
            frame.render_widget(help, content_chunks[1]);

            let controls = "Up/Down select • Click select • Enter choose • r refresh • ? help • Backspace back • q quit".to_string();
            let footer = Paragraph::new(vec![Line::from(controls)])
                .wrap(Wrap { trim: true });
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
                .as_ref()
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
