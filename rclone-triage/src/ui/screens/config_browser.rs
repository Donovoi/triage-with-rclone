//! Config file browser screen

use ratatui::buffer::Buffer;
use ratatui::layout::{Constraint, Direction, Layout, Rect};
use ratatui::style::{Color, Modifier, Style};
use ratatui::text::{Line, Span};
use ratatui::widgets::{
    Block, Borders, List, ListItem, ListState, Paragraph, StatefulWidget, Widget, Wrap,
};

use crate::ui::ConfigBrowserEntry;

pub struct ConfigBrowserScreen {
    pub current_dir: String,
    pub entries: Vec<ConfigBrowserEntry>,
    pub selected: usize,
    pub status: String,
    pub preview: Vec<String>,
    pub error: Option<String>,
}

impl ConfigBrowserScreen {
    pub fn new(
        current_dir: String,
        entries: Vec<ConfigBrowserEntry>,
        selected: usize,
        status: String,
        preview: Vec<String>,
    ) -> Self {
        Self {
            current_dir,
            entries,
            selected,
            status,
            preview,
            error: None,
        }
    }

    pub fn with_error(mut self, error: Option<String>) -> Self {
        self.error = error;
        self
    }
}

impl Widget for &ConfigBrowserScreen {
    fn render(self, area: Rect, buf: &mut Buffer) {
        let content_chunks = Layout::default()
            .direction(Direction::Horizontal)
            .constraints([Constraint::Percentage(65), Constraint::Percentage(35)])
            .split(area);

        // Left panel: directory listing
        let list_items: Vec<ListItem> = self
            .entries
            .iter()
            .map(|entry| {
                let is_nav = entry.name == "." || entry.name == "..";
                let (prefix, style) = if is_nav {
                    ("[NAV]  ", Style::default().fg(Color::Yellow))
                } else if entry.is_dir {
                    ("[DIR]  ", Style::default().fg(Color::LightBlue))
                } else if entry.name.ends_with(".conf") || entry.name.ends_with(".cfg") {
                    ("[FILE] ", Style::default().fg(Color::LightGreen))
                } else {
                    ("[FILE] ", Style::default())
                };
                let label = if entry.name == "." {
                    ".  (current directory)".to_string()
                } else if entry.name == ".." {
                    "..  (parent directory)".to_string()
                } else {
                    entry.name.clone()
                };
                let size_str = if is_nav {
                    String::new()
                } else {
                    entry
                        .size
                        .map(|s| format!("  ({} B)", s))
                        .unwrap_or_default()
                };
                ListItem::new(Line::from(vec![
                    Span::styled(prefix, style),
                    Span::styled(label, style),
                    Span::styled(size_str, Style::default().fg(Color::DarkGray)),
                ]))
            })
            .collect();

        let title = format!("Browse: {}", self.current_dir);
        let list = List::new(list_items)
            .block(Block::default().title(title).borders(Borders::ALL))
            .highlight_style(
                Style::default()
                    .fg(Color::White)
                    .bg(Color::DarkGray)
                    .add_modifier(Modifier::BOLD),
            )
            .highlight_symbol("▶ ");

        let mut state = ListState::default();
        if !self.entries.is_empty() {
            let selected = self.selected.min(self.entries.len().saturating_sub(1));
            state.select(Some(selected));
        }
        StatefulWidget::render(list, content_chunks[0], buf, &mut state);

        // Right panel: error display or status + preview
        let show_panel = content_chunks[1].width >= 20 && content_chunks[1].height >= 4;
        if show_panel {
            let mut lines = Vec::new();

            if let Some(ref error) = self.error {
                // Prominent error display with next steps
                let error_style = Style::default()
                    .fg(Color::LightRed)
                    .add_modifier(Modifier::BOLD);
                let hint_style = Style::default().fg(Color::Yellow);

                lines.push(Line::from(Span::styled(
                    "!! Listing Failed !!",
                    error_style,
                )));
                lines.push(Line::from(""));

                // Wrap error text into lines for the panel
                for chunk in error.as_bytes().chunks(40) {
                    let s = String::from_utf8_lossy(chunk);
                    lines.push(Line::from(Span::styled(
                        s.to_string(),
                        Style::default().fg(Color::LightRed),
                    )));
                }
                lines.push(Line::from(""));

                // Classify the error and give specific advice
                let advice = classify_listing_error(error);
                lines.push(Line::from(Span::styled("What happened:", hint_style)));
                lines.push(Line::from(Span::styled(
                    advice.explanation,
                    Style::default().fg(Color::White),
                )));
                lines.push(Line::from(""));

                lines.push(Line::from(Span::styled("Next steps:", hint_style)));
                for step in &advice.next_steps {
                    lines.push(Line::from(Span::styled(
                        format!("  {}", step),
                        Style::default().fg(Color::White),
                    )));
                }
                lines.push(Line::from(""));
                lines.push(Line::from("Esc: back to main menu"));
            } else {
                lines.push(Line::from(Span::styled(
                    "Config File Browser",
                    Style::default().add_modifier(Modifier::BOLD),
                )));
                lines.push(Line::from(""));

                if let Some(entry) = self.entries.get(self.selected) {
                    let kind = if entry.name == "." || entry.name == ".." {
                        "Navigation"
                    } else if entry.is_dir {
                        "Directory"
                    } else {
                        "File"
                    };
                    lines.push(Line::from(format!("Selected: {}", entry.name)));
                    lines.push(Line::from(format!("Type: {}", kind)));
                    if let Some(size) = entry.size {
                        lines.push(Line::from(format!("Size: {} bytes", size)));
                    }
                    lines.push(Line::from(""));
                }

                if !self.preview.is_empty() {
                    for line in &self.preview {
                        lines.push(Line::from(Span::styled(
                            line.as_str(),
                            Style::default().fg(Color::LightGreen),
                        )));
                    }
                    lines.push(Line::from(""));
                }

                lines.push(Line::from(format!("Status: {}", self.status)));
                lines.push(Line::from(""));
                lines.push(Line::from("Enter: open dir / select file"));
                lines.push(Line::from("Backspace: parent directory"));
                lines.push(Line::from("Esc: back to main menu"));
            }

            let title = if self.error.is_some() {
                "Error"
            } else {
                "Details"
            };
            let panel = Paragraph::new(lines)
                .block(Block::default().title(title).borders(Borders::ALL))
                .wrap(Wrap { trim: true });
            panel.render(content_chunks[1], buf);
        }
    }
}

struct ErrorAdvice {
    explanation: &'static str,
    next_steps: Vec<&'static str>,
}

fn classify_listing_error(error: &str) -> ErrorAdvice {
    let lower = error.to_lowercase();

    if lower.contains("access_denied")
        || lower.contains("account restricted")
        || lower.contains("servicenotallowed")
    {
        ErrorAdvice {
            explanation: "Access was denied by the cloud provider. The token may have been revoked or the account restricted.",
            next_steps: vec![
                "1. Go back to Main Menu (Esc)",
                "2. Re-authenticate with a fresh token",
                "3. Or use a different config file",
                "   with a valid, active token",
            ],
        }
    } else if lower.contains("token") && (lower.contains("expired") || lower.contains("invalid")) {
        ErrorAdvice {
            explanation: "The OAuth token has expired or is no longer valid.",
            next_steps: vec![
                "1. Go back to Main Menu (Esc)",
                "2. Re-authenticate to get a fresh",
                "   token for this provider",
                "3. Or select a config file with a",
                "   current, valid token",
            ],
        }
    } else if lower.contains("couldn't find root") || lower.contains("root directory") {
        ErrorAdvice {
            explanation: "Could not access the remote storage root. The token may be invalid or permissions revoked.",
            next_steps: vec![
                "1. Go back to Main Menu (Esc)",
                "2. Re-authenticate the provider",
                "3. Ensure the account still has",
                "   access to the remote storage",
            ],
        }
    } else if lower.contains("couldn't fetch token") || lower.contains("fetch token") {
        ErrorAdvice {
            explanation: "Could not retrieve a valid token. The saved credentials are likely stale or revoked.",
            next_steps: vec![
                "1. Go back to Main Menu (Esc)",
                "2. Re-authenticate to refresh the",
                "   OAuth token for this provider",
                "3. Or try a different config file",
            ],
        }
    } else {
        ErrorAdvice {
            explanation: "The remote could not be listed. Credentials may be invalid or the remote misconfigured.",
            next_steps: vec![
                "1. Go back to Main Menu (Esc)",
                "2. Re-authenticate the provider",
                "3. Or try a different config file",
                "   with working credentials",
            ],
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::PathBuf;

    #[test]
    fn test_render_empty() {
        let mut buf = Buffer::empty(Rect::new(0, 0, 80, 20));
        // Even an "empty" directory should have . and .. entries
        let entries = vec![
            ConfigBrowserEntry {
                name: ".".to_string(),
                path: PathBuf::from("/tmp"),
                is_dir: true,
                size: None,
            },
            ConfigBrowserEntry {
                name: "..".to_string(),
                path: PathBuf::from("/"),
                is_dir: true,
                size: None,
            },
        ];
        let screen = ConfigBrowserScreen::new(
            "/tmp".to_string(),
            entries,
            0,
            "0 items".to_string(),
            vec![],
        );
        (&screen).render(Rect::new(0, 0, 80, 20), &mut buf);
    }

    #[test]
    fn test_render_with_entries() {
        let mut buf = Buffer::empty(Rect::new(0, 0, 80, 20));
        let entries = vec![
            ConfigBrowserEntry {
                name: ".".to_string(),
                path: PathBuf::from("/tmp"),
                is_dir: true,
                size: None,
            },
            ConfigBrowserEntry {
                name: "..".to_string(),
                path: PathBuf::from("/"),
                is_dir: true,
                size: None,
            },
            ConfigBrowserEntry {
                name: "subdir".to_string(),
                path: PathBuf::from("/tmp/subdir"),
                is_dir: true,
                size: None,
            },
            ConfigBrowserEntry {
                name: "rclone.conf".to_string(),
                path: PathBuf::from("/tmp/rclone.conf"),
                is_dir: false,
                size: Some(1024),
            },
        ];
        let screen = ConfigBrowserScreen::new(
            "/tmp".to_string(),
            entries,
            3,
            "2 items".to_string(),
            vec!["Remotes (1)".to_string(), "  myremote (drive)".to_string()],
        );
        (&screen).render(Rect::new(0, 0, 80, 20), &mut buf);
    }

    #[test]
    fn test_render_with_error() {
        let mut buf = Buffer::empty(Rect::new(0, 0, 80, 20));
        let entries = vec![
            ConfigBrowserEntry {
                name: ".".to_string(),
                path: PathBuf::from("/tmp"),
                is_dir: true,
                size: None,
            },
            ConfigBrowserEntry {
                name: "..".to_string(),
                path: PathBuf::from("/"),
                is_dir: true,
                size: None,
            },
        ];
        let screen =
            ConfigBrowserScreen::new("/tmp".to_string(), entries, 0, String::new(), vec![])
                .with_error(Some(
                    "Listing failed: oauth2: access_denied \"Account Restricted\"".to_string(),
                ));
        (&screen).render(Rect::new(0, 0, 80, 20), &mut buf);
    }

    #[test]
    fn test_classify_access_denied() {
        let advice = classify_listing_error("oauth2: access_denied \"Account Restricted\"");
        assert!(advice.explanation.contains("Access was denied"));
    }

    #[test]
    fn test_classify_token_expired() {
        let advice = classify_listing_error("token expired: refresh failed");
        assert!(advice.explanation.contains("expired"));
    }

    #[test]
    fn test_classify_fetch_token() {
        let advice = classify_listing_error("couldn't fetch token: invalid_grant");
        assert!(advice.explanation.contains("token"));
    }

    #[test]
    fn test_classify_generic_error() {
        let advice = classify_listing_error("connection timed out");
        assert!(advice.explanation.contains("could not be listed"));
    }
}
