//! Screen rendering based on application state

use ratatui::layout::{Alignment, Constraint, Direction, Layout};
use ratatui::style::Color;
use ratatui::text::{Line, Span};
use ratatui::widgets::{Paragraph, Wrap};
use ratatui::Frame;

use crate::ui::screens::{
    auth::AuthScreen, browser_select::BrowserSelectScreen, config_browser::ConfigBrowserScreen,
    download::DownloadScreen, files::FilesScreen, listing::ListingScreen,
    main_menu::MainMenuScreen, provider_select::ProviderSelectScreen,
    remote_select::RemoteSelectScreen, report::ReportScreen,
};
use crate::ui::theme;
use crate::ui::{App, AppState, MenuAction, MenuItem};

fn main_menu_banner_lines(frame: u64) -> Vec<Line<'static>> {
    vec![
        Line::from(Span::styled(
            ".------------------------------------------------------------.",
            theme::panel_border_style(),
        )),
        Line::from(vec![
            Span::styled("| ", theme::panel_border_style()),
            Span::styled("rclone-triage", theme::panel_title_style()),
            Span::styled(" // ", theme::muted_style()),
            Span::styled("forensic cloud ops deck", theme::strong_style()),
            Span::styled(" ", theme::muted_style()),
            Span::styled(theme::banner_activity(frame), theme::success_style()),
            Span::styled(" |", theme::panel_border_style()),
        ]),
        Line::from(vec![
            Span::styled("| ", theme::panel_border_style()),
            Span::styled("auth", theme::info_style()),
            Span::styled(" • ", theme::muted_style()),
            Span::styled("enumerate", theme::warning_style()),
            Span::styled(" • ", theme::muted_style()),
            Span::styled("xfer", theme::success_style()),
            Span::styled(" • ", theme::muted_style()),
            Span::styled("mount", theme::menu_badge_style("MOUNT")),
            Span::styled(" • ", theme::muted_style()),
            Span::styled("toolbox", theme::menu_badge_style("TOOLS")),
            Span::styled(" |", theme::panel_border_style()),
        ]),
        Line::from(Span::styled(
            "'------------------------------------------------------------'",
            theme::panel_border_style(),
        )),
    ]
}

fn main_menu_display_label(item: &MenuItem) -> String {
    match item.action {
        MenuAction::Authenticate => "[AUTH] Browser auth on suspect device".to_string(),
        MenuAction::RetrieveList => "[LIST] Load authenticated config".to_string(),
        MenuAction::DownloadFromCsv => "[XFER] Download from CSV/XLSX".to_string(),
        MenuAction::MountProvider => "[MOUNT] Mount remote as network share".to_string(),
        MenuAction::SmartAuth => "[SSO] Silent / smart authentication".to_string(),
        MenuAction::MobileAuth => "[MOB] Mobile-device authentication".to_string(),
        MenuAction::AdditionalOptions => "[TOOLS] Additional options".to_string(),
        MenuAction::Exit => "[EXIT] Exit application".to_string(),
        _ => item.label.to_string(),
    }
}

fn main_menu_footer_lines(app: &App) -> Vec<Line<'static>> {
    let description = app
        .menu_selected_item()
        .map(|item| item.description)
        .unwrap_or("Select an option to continue.");

    let mut lines = vec![Line::from(vec![
        Span::styled("Selected ", theme::warning_style()),
        Span::styled(description.to_string(), theme::strong_style()),
    ])];

    if !app.menu_status.is_empty() {
        lines.push(Line::from(vec![
            Span::styled(
                theme::footer_spinner(app.animation_frame),
                theme::success_style(),
            ),
            Span::raw(" "),
            Span::styled(app.menu_status.clone(), theme::info_style()),
        ]));
    }

    lines.push(Line::from(vec![
        Span::styled("Ops ", theme::panel_title_style()),
        Span::styled(
            "auth • list • xfer • mount • sso • mobile • tools",
            theme::muted_style(),
        ),
    ]));
    lines.push(Line::from(vec![
        Span::styled("Keys ", theme::warning_style()),
        Span::styled(
            "↑/↓ move • Enter launch • Backspace back • Ctrl+E export • q quit",
            theme::muted_style(),
        ),
    ]));

    lines
}

/// Render the current state into the frame
pub fn render_state(frame: &mut Frame, app: &App) {
    let area = frame.area();
    match app.state {
        AppState::MainMenu => {
            let chunks = Layout::default()
                .direction(Direction::Vertical)
                .constraints([
                    Constraint::Length(4),
                    Constraint::Min(3),
                    Constraint::Length(5),
                ])
                .split(area);

            let banner = Paragraph::new(main_menu_banner_lines(app.animation_frame))
                .alignment(Alignment::Center);
            frame.render_widget(banner, chunks[0]);

            let labels = app
                .menu_items
                .iter()
                .map(main_menu_display_label)
                .collect::<Vec<_>>();
            let mut screen = MainMenuScreen::new(labels);
            screen.list.selected = app.menu_selected;
            screen.list.title = "rclone-triage // mission menu".to_string();
            screen.list.animation_frame = app.animation_frame;
            frame.render_widget(&screen, chunks[1]);

            let footer = Paragraph::new(main_menu_footer_lines(app)).wrap(Wrap { trim: true });
            frame.render_widget(footer, chunks[2]);
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
            screen.list.title = "toolbox // extra ops".to_string();
            screen.list.animation_frame = app.animation_frame;
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
                "Up/Down select • Enter choose • Backspace back • Ctrl+E export screen • q quit"
                    .to_string();
            let footer = Paragraph::new(vec![
                Line::from(description),
                Line::from(status),
                Line::from(controls),
            ])
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
            screen.list.title = "onedrive // utilities".to_string();
            screen.list.animation_frame = app.animation_frame;
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
                "Up/Down select • Enter choose • Backspace back • Ctrl+E export screen • q quit"
                    .to_string();
            let footer = Paragraph::new(vec![
                Line::from(description),
                Line::from(status),
                Line::from(controls),
            ])
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
                .provider
                .entries
                .iter()
                .map(|p| p.display_name().to_string())
                .collect::<Vec<_>>();
            let screen = ProviderSelectScreen::new(
                names,
                app.provider.checked.clone(),
                app.provider.selected,
            );
            frame.render_widget(&screen, content_chunks[0]);

            let mode = app
                .selected_action
                .and_then(|action| app.menu_items.iter().find(|item| item.action == action))
                .map(|item| format!("Mode: {}", item.label))
                .unwrap_or_else(|| "Mode: Authenticate (default)".to_string());
            let status = if app.provider.status.is_empty() {
                format!("Providers: built-in ({})", app.provider.entries.len())
            } else {
                app.provider.status.clone()
            };
            let last_update = app
                .provider
                .last_updated
                .as_ref()
                .map(|ts| ts.format("%Y-%m-%d %H:%M:%S").to_string())
                .unwrap_or_else(|| "never".to_string());
            let last_error = app.provider.last_error.as_deref().unwrap_or("none");
            let show_status_panel = content_chunks[1].width >= 26 && content_chunks[1].height >= 6;
            if show_status_panel {
                let mut help_lines = Vec::new();
                help_lines.push(Line::from(mode.clone()));
                if let Some(provider) = app.provider.entries.get(app.provider.selected) {
                    help_lines.push(Line::from(format!("Selected: {}", provider.display_name())));
                    help_lines.push(Line::from(format!("Backend: {}", provider.short_name())));
                    if let Some(desc) = provider.description() {
                        help_lines.push(Line::from(format!("Description: {}", desc)));
                    }
                    let auth = match provider.auth_kind() {
                        crate::providers::ProviderAuthKind::OAuth => "OAuth",
                        crate::providers::ProviderAuthKind::KeyBased => "Key-based",
                        crate::providers::ProviderAuthKind::UserPass => "User/pass",
                        crate::providers::ProviderAuthKind::Unknown => "Unknown/manual",
                    };
                    help_lines.push(Line::from(format!("Auth: {}", auth)));
                    if let Some(known) = provider.known {
                        let hashes = known.hash_types();
                        if hashes.is_empty() {
                            help_lines.push(Line::from("Hashes: none".to_string()));
                        } else {
                            help_lines.push(Line::from(format!("Hashes: {}", hashes.join(", "))));
                        }
                    } else {
                        help_lines.push(Line::from("Hashes: unknown".to_string()));
                    }
                    help_lines.push(Line::from(""));
                }
                help_lines.push(Line::from(format!(
                    "Providers: {}",
                    app.provider.entries.len()
                )));
                help_lines.push(Line::from(format!("Last update: {}", last_update)));
                help_lines.push(Line::from(format!("Last error: {}", last_error)));
                help_lines.push(Line::from(format!("Status: {}", status)));
                help_lines.push(Line::from("Tip: Press r to refresh from rclone."));
                help_lines.push(Line::from("Tip: Press ? for provider help."));
                help_lines.push(Line::from(
                    "Next: Enter confirms selection → browser/auth flow.",
                ));
                let help = Paragraph::new(help_lines)
                    .block(theme::panel_block("Status"))
                    .wrap(Wrap { trim: true });
                frame.render_widget(help, content_chunks[1]);
            }

            let controls = "Up/Down select • Space toggle • Enter confirm • r refresh • ? help • Ctrl+E export • Backspace back • q quit".to_string();
            let footer_lines = if show_status_panel {
                vec![Line::from(mode), Line::from(controls)]
            } else {
                vec![
                    Line::from(mode),
                    Line::from(format!("Providers: {}", app.provider.entries.len())),
                    Line::from(format!("Status: {}", status)),
                    Line::from(format!("Last error: {}", last_error)),
                    Line::from("Tip: Press r to refresh from rclone if the list looks short."),
                    Line::from("Next: Enter confirms selection → browser/auth flow."),
                    Line::from(controls),
                ]
            };
            let footer = Paragraph::new(footer_lines).wrap(Wrap { trim: true });
            frame.render_widget(footer, chunks[1]);

            if app.provider.show_help {
                let overlay = centered_rect(70, 60, area);
                let help_lines = vec![
                    Line::from("Provider list sources"),
                    Line::from(""),
                    Line::from("Built-in list: ships with the app for offline use."),
                    Line::from("Refresh: runs `rclone config providers` (uses JSON output when available)."),
                    Line::from("If refresh fails, the built-in list remains."),
                    Line::from("Set RCLONE_TRIAGE_DYNAMIC_PROVIDERS=0 to disable refresh."),
                    Line::from(""),
                    Line::from("Press ? or Esc to close."),
                ];
                let help = Paragraph::new(help_lines)
                    .block(theme::panel_block("Provider Help"))
                    .wrap(Wrap { trim: true });
                frame.render_widget(help, overlay);
            }
        }
        AppState::RemoteSelect => {
            let chunks = Layout::default()
                .direction(Direction::Vertical)
                .constraints([Constraint::Min(3), Constraint::Length(4)])
                .split(area);
            let screen = RemoteSelectScreen::new(
                app.remote.options.clone(),
                app.remote.checked.clone(),
                app.remote.selected,
            );
            frame.render_widget(&screen, chunks[0]);

            let provider_name = app
                .provider
                .chosen
                .as_ref()
                .map(|p| p.display_name().to_string())
                .unwrap_or_else(|| "Provider".to_string());
            let status = if app.provider.status.is_empty() {
                format!("Select a remote for {}.", provider_name)
            } else {
                app.provider.status.clone()
            };
            let controls =
                "Up/Down select • Space toggle • Enter confirm • Backspace back • Ctrl+E export screen • q quit"
                    .to_string();
            let footer = Paragraph::new(vec![
                Line::from(format!("Provider: {}", provider_name)),
                Line::from(status),
                Line::from(controls),
            ])
            .wrap(Wrap { trim: true });
            frame.render_widget(footer, chunks[1]);
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
            screen.list.title = "mobile auth // field kit".to_string();
            screen.list.animation_frame = app.animation_frame;
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
                "Up/Down select • Enter choose • Backspace back • Ctrl+E export screen • q quit"
                    .to_string();
            let footer = Paragraph::new(vec![
                Line::from(description),
                Line::from(status),
                Line::from(controls),
            ])
            .wrap(Wrap { trim: true });
            frame.render_widget(footer, chunks[1]);
        }
        AppState::BrowserSelect => {
            let mut names = Vec::new();
            names.push("System Default".to_string());
            for browser in &app.browser.entries {
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
                BrowserSelectScreen::new(names, app.browser.checked.clone(), app.browser.selected);
            frame.render_widget(&screen, chunks[0]);

            let next = "Next: Enter selects browser → authentication opens.";
            let status = if app.auth_status.is_empty() {
                "Select one or more browsers for authentication.".to_string()
            } else {
                app.auth_status.clone()
            };
            let controls =
                "Up/Down select • Space toggle • Enter confirm • Ctrl+E export • Backspace back • q quit";
            let footer = Paragraph::new(vec![
                Line::from(next),
                Line::from(status),
                Line::from(controls),
            ])
            .wrap(Wrap { trim: true });
            frame.render_widget(footer, chunks[1]);
        }
        AppState::Authenticating => {
            let name = app
                .provider
                .chosen
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

            let auth_done = app.auth_status.starts_with("Testing connectivity")
                || app.auth_status.starts_with("Listing files")
                || app.auth_status.starts_with("Connectivity")
                || app.auth_status.starts_with("Authentication succeeded")
                || app.auth_status.starts_with("Found ")
                || app.auth_status.starts_with("Exported ");
            let hint = if auth_done {
                "Authentication complete. Processing..."
            } else {
                "What happens now: complete auth in the browser, then return here to continue."
            };
            let footer = Paragraph::new(vec![Line::from(Span::styled(hint, theme::hint_style()))])
                .wrap(Wrap { trim: true });
            frame.render_widget(footer, chunks[1]);
        }
        AppState::PostAuthChoice => {
            let provider_name = app
                .provider
                .chosen
                .as_ref()
                .map(|p| p.display_name().to_string())
                .unwrap_or_else(|| "Remote".to_string());

            let num_post_auth_choices: usize = 4;

            let mut choices: Vec<(&str, String)> = vec![
                ("List all files to CSV/XLSX", "Recursively list every file in the remote and export to CSV. Best for triage and selective download.".to_string()),
                ("Mount as drive (File Explorer)", "Mount the remote as a local drive letter / mount point and browse files in your OS file manager.".to_string()),
                ("Skip to file list (empty)", "Go to the file list screen without listing. You can list or mount later from the main menu.".to_string()),
            ];

            // 4th option: Add Another Provider
            let add_desc = if app.authenticated_remotes.is_empty() {
                "Authenticate another cloud provider to combine multiple remotes into one listing/mount.".to_string()
            } else {
                let names: Vec<&str> = app
                    .authenticated_remotes
                    .iter()
                    .map(|(_, name)| name.as_str())
                    .collect();
                format!(
                    "Already authenticated: {}. Add another to combine into one listing/mount.",
                    names.join(", ")
                )
            };
            choices.push(("Add another provider", add_desc));

            let chunks = Layout::default()
                .direction(Direction::Vertical)
                .constraints([Constraint::Min(3), Constraint::Length(3)])
                .split(area);

            let mut lines: Vec<Line> = Vec::new();
            lines.push(Line::from(vec![
                Span::styled(
                    "Authenticated: ",
                    ratatui::style::Style::default().add_modifier(ratatui::style::Modifier::BOLD),
                ),
                Span::styled(
                    &provider_name,
                    ratatui::style::Style::default()
                        .fg(Color::LightGreen)
                        .add_modifier(ratatui::style::Modifier::BOLD),
                ),
            ]));

            if !app.authenticated_remotes.is_empty() {
                let total = app.authenticated_remotes.len();
                let remote_names: Vec<&str> = app
                    .authenticated_remotes
                    .iter()
                    .map(|(r, _)| r.as_str())
                    .collect();
                lines.push(Line::from(Span::styled(
                    format!("{} remote(s) ready: {}", total, remote_names.join(", ")),
                    ratatui::style::Style::default().fg(Color::LightCyan),
                )));
            }

            if !app.auth_status.is_empty() {
                for line in app.auth_status.lines().take(3) {
                    lines.push(Line::from(Span::styled(
                        line.to_string(),
                        ratatui::style::Style::default().fg(Color::LightGreen),
                    )));
                }
            }

            lines.push(Line::from(""));
            lines.push(Line::from(Span::styled(
                "What would you like to do with this remote?",
                ratatui::style::Style::default().add_modifier(ratatui::style::Modifier::BOLD),
            )));
            lines.push(Line::from(""));

            for (i, (label, desc)) in choices.iter().enumerate() {
                let marker = if i == app.post_auth_selected {
                    "▶ "
                } else {
                    "  "
                };
                let style = if i == app.post_auth_selected {
                    ratatui::style::Style::default()
                        .fg(Color::Yellow)
                        .add_modifier(ratatui::style::Modifier::BOLD)
                } else {
                    ratatui::style::Style::default()
                };
                lines.push(Line::from(Span::styled(
                    format!("{}  {}", marker, label),
                    style,
                )));
                let desc_style = ratatui::style::Style::default().fg(Color::DarkGray);
                lines.push(Line::from(Span::styled(
                    format!("     {}", desc),
                    desc_style,
                )));
                lines.push(Line::from(""));
            }

            let _ = num_post_auth_choices; // used in runner.rs for wrapping
            let paragraph = Paragraph::new(lines);
            frame.render_widget(paragraph, chunks[0]);

            let hint = "↑/↓ Navigate   Enter: Confirm   Ctrl+E: Export   Backspace: Back";
            let footer = Paragraph::new(vec![Line::from(Span::styled(hint, theme::hint_style()))])
                .wrap(Wrap { trim: true });
            frame.render_widget(footer, chunks[1]);
        }
        AppState::FileList => {
            let entries = if app.files.entries.is_empty() {
                // Show status/error message so the user understands why the list is empty.
                let status = if !app.auth_status.is_empty() {
                    app.auth_status.clone()
                } else if !app.provider.status.is_empty() {
                    app.provider.status.clone()
                } else {
                    "No files found. The listing may have failed — check logs.".to_string()
                };
                vec![status]
            } else {
                // Mark files that are selected for download with [x]
                app.files
                    .entries
                    .iter()
                    .map(|e| {
                        if app.files.to_download.contains(e) {
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
            screen.tree.selected = app.files.selected;
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
                        "m mount • u unmount • Ctrl+E export • Backspace back • q quit".to_string(),
                    )
                }
                Some(crate::ui::MenuAction::RetrieveList) => (
                    "Listing complete: select files to download or press Backspace to return."
                        .to_string(),
                    "Up/Down select • Space toggle • Enter download • Ctrl+E export • Backspace back • q quit"
                        .to_string(),
                ),
                _ => (
                    "What happens now: select files (toggle) then press Enter to start download."
                        .to_string(),
                    "Up/Down select • Space toggle • Enter download • Ctrl+E export • Backspace back • q quit"
                        .to_string(),
                ),
            };
            let footer = Paragraph::new(vec![
                Line::from(Span::styled(&*hint, theme::hint_style())),
                Line::from(controls),
            ])
            .wrap(Wrap { trim: true });
            frame.render_widget(footer, chunks[1]);
        }
        AppState::Mounted => {
            let chunks = Layout::default()
                .direction(Direction::Vertical)
                .constraints([Constraint::Min(3), Constraint::Length(3)])
                .split(area);

            let mount_info = if let Some(ref mounted) = app.mounted_remote {
                let remote = app.remote.chosen.as_deref().unwrap_or("unknown");
                format!(
                    "Drive Mounted\n\nRemote: {}\nMount point: {:?}\n\nThe cloud drive is mounted and accessible via file explorer.\nPress 'u' to unmount, Backspace to go back, or 'q' to quit.",
                    remote,
                    mounted.mount_point()
                )
            } else {
                format!(
                    "{}\n\nPress Backspace to go back and try again.",
                    app.auth_status
                )
            };

            let body = Paragraph::new(mount_info)
                .block(theme::panel_block("Mounted Drive"))
                .wrap(Wrap { trim: true });
            frame.render_widget(body, chunks[0]);

            let hint = "u unmount • Ctrl+E export • Backspace back • q quit";
            let footer = Paragraph::new(vec![Line::from(Span::styled(hint, theme::hint_style()))])
                .wrap(Wrap { trim: true });
            frame.render_widget(footer, chunks[1]);
        }
        AppState::Downloading => {
            let chunks = Layout::default()
                .direction(Direction::Vertical)
                .constraints([Constraint::Min(3), Constraint::Length(3)])
                .split(area);
            let mut screen = DownloadScreen::new();
            if !app.download.status.is_empty() {
                screen.overall.label = app.download.status.clone();
            }
            let overall_ratio = if let Some(total_bytes) = app.download.total_bytes {
                if total_bytes > 0 {
                    let done = app.download.done_bytes.min(total_bytes);
                    done as f64 / total_bytes as f64
                } else {
                    0.0
                }
            } else if app.download.progress.1 > 0 {
                app.download.progress.0 as f64 / app.download.progress.1 as f64
            } else {
                0.0
            };
            screen.overall.set_progress(overall_ratio);

            if let Some((done, total)) = app.download.current_bytes {
                if total > 0 {
                    screen.current.set_progress(done as f64 / total as f64);
                    screen.current.label = format!("Current: {} / {} bytes", done, total);
                }
            }
            frame.render_widget(&screen, chunks[0]);

            let hint =
                "What happens now: downloads run sequentially; progress and logs update below.";
            let footer = Paragraph::new(vec![Line::from(Span::styled(hint, theme::hint_style()))])
                .wrap(Wrap { trim: true });
            frame.render_widget(footer, chunks[1]);
        }
        AppState::Complete => {
            let lines = if app.download.report_lines.is_empty() {
                vec!["Complete".to_string(), "No errors".to_string()]
            } else {
                app.download.report_lines.clone()
            };
            let screen = ReportScreen::new(lines);
            frame.render_widget(&screen, area);
        }
        AppState::OAuthCredentials => {
            let lines = if app.download.report_lines.is_empty() {
                vec!["No OAuth credential data loaded.".to_string()]
            } else {
                app.download.report_lines.clone()
            };
            let screen = ReportScreen::new(lines);
            frame.render_widget(&screen, area);
        }
        AppState::ConfigBrowser => {
            let chunks = Layout::default()
                .direction(Direction::Vertical)
                .constraints([Constraint::Min(3), Constraint::Length(3)])
                .split(area);
            let has_error = app.config_browser.last_error.is_some();
            let screen = ConfigBrowserScreen::new(
                app.config_browser.current_dir.display().to_string(),
                app.config_browser.entries.clone(),
                app.config_browser.selected,
                app.config_browser.status.clone(),
                app.config_browser.preview.clone(),
            )
            .with_error(app.config_browser.last_error.clone());
            frame.render_widget(&screen, chunks[0]);

            let (hint, controls) = if has_error {
                (
                    "Listing failed — see error details in the panel. Re-authenticate or try a different config.",
                    "Esc back to main menu \u{2022} q quit",
                )
            } else {
                (
                    "Select an rclone config file to load remotes from.",
                    "Up/Down select \u{2022} Enter open/select \u{2022} Ctrl+E export \u{2022} Backspace parent dir \u{2022} Esc back \u{2022} q quit",
                )
            };
            let hint_style = if has_error {
                theme::error_style()
            } else {
                theme::hint_style()
            };
            let footer = Paragraph::new(vec![
                Line::from(Span::styled(hint, hint_style)),
                Line::from(controls),
            ])
            .wrap(Wrap { trim: true });
            frame.render_widget(footer, chunks[1]);
        }
        AppState::Listing => {
            let chunks = Layout::default()
                .direction(Direction::Vertical)
                .constraints([Constraint::Min(3), Constraint::Length(3)])
                .split(area);

            let (remote_name, count, elapsed_secs, status) =
                if let Some(ref task) = app.listing_task {
                    (
                        task.context.remote_name.clone(),
                        task.count,
                        task.started.elapsed().as_secs(),
                        app.provider.status.clone(),
                    )
                } else {
                    ("unknown".to_string(), 0, 0, app.provider.status.clone())
                };

            let screen = ListingScreen::new(remote_name, count, elapsed_secs, status);
            frame.render_widget(&screen, chunks[0]);

            let footer = Paragraph::new(vec![
                Line::from(Span::styled(
                    "Listing files from remote...",
                    theme::hint_style(),
                )),
                Line::from("Esc cancel \u{2022} Ctrl+E export \u{2022} q quit"),
            ])
            .wrap(Wrap { trim: true });
            frame.render_widget(footer, chunks[1]);
        }
    }
}

use super::layout::centered_rect;

/// Render the current screen to a string for text export.
///
/// Uses a headless test backend to capture exactly what the user sees,
/// then extracts the text content line by line (trailing whitespace trimmed).
pub fn export_screen_text(app: &App, width: u16, height: u16) -> String {
    use ratatui::backend::TestBackend;

    let backend = TestBackend::new(width, height);
    let mut terminal = match ratatui::Terminal::new(backend) {
        Ok(t) => t,
        Err(_) => return String::new(),
    };
    let _ = terminal.draw(|f| {
        render_state(f, app);
    });
    let buf = terminal.backend().buffer();
    let mut lines = Vec::new();
    for y in 0..buf.area.height {
        let mut line = String::new();
        for x in 0..buf.area.width {
            let cell = &buf[(x, y)];
            line.push_str(cell.symbol());
        }
        lines.push(line.trim_end().to_string());
    }
    // Trim trailing empty lines
    while lines.last().is_some_and(|l| l.is_empty()) {
        lines.pop();
    }
    lines.join("\n")
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
            AppState::ProviderSelect,
            AppState::ConfigBrowser,
            AppState::RemoteSelect,
            AppState::BrowserSelect,
            AppState::Authenticating,
            AppState::PostAuthChoice,
            AppState::FileList,
            AppState::Downloading,
            AppState::OAuthCredentials,
            AppState::Complete,
        ] {
            terminal
                .draw(|f| {
                    let mut app = App::new();
                    app.state = state;
                    app.provider.selected = 0;
                    if state == AppState::RemoteSelect {
                        app.remote.options = vec!["Personal".to_string(), "Business".to_string()];
                    }
                    render_state(f, &app);
                })
                .unwrap();
        }
    }
}
