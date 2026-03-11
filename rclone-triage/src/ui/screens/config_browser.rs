//! Config file browser screen

use ratatui::buffer::Buffer;
use ratatui::layout::{Constraint, Direction, Layout, Rect};
use ratatui::style::Style;
use ratatui::text::{Line, Span, Text};
use ratatui::widgets::{List, ListItem, ListState, Paragraph, StatefulWidget, Widget, Wrap};

use crate::ui::widgets::{marquee_text_line, text_width, wrap_line, MarqueeSegment};
use crate::ui::{theme, ConfigBrowserEntry};

pub struct ConfigBrowserScreen {
    pub current_dir: String,
    pub entries: Vec<ConfigBrowserEntry>,
    pub selected: usize,
    pub status: String,
    pub preview: Vec<String>,
    pub error: Option<String>,
    pub animation_frame: u64,
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
            animation_frame: 0,
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

        let highlight_symbol = theme::list_highlight_symbol(self.animation_frame);
        let highlight_width = text_width(highlight_symbol) as u16;
        let list_inner_width = content_chunks[0].width.saturating_sub(2);

        // Left panel: directory listing
        let list_items: Vec<ListItem> = self
            .entries
            .iter()
            .enumerate()
            .map(|(idx, entry)| {
                let is_nav = entry.name == "." || entry.name == "..";
                let (prefix, style) = if is_nav {
                    ("[NAV]  ", theme::warning_style())
                } else if entry.is_dir {
                    ("[DIR]  ", theme::info_style())
                } else if entry.name.ends_with(".conf") || entry.name.ends_with(".cfg") {
                    ("[CONF] ", theme::success_style())
                } else {
                    ("[FILE] ", theme::strong_style())
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
                let available_width = list_inner_width.saturating_sub(if idx == self.selected {
                    highlight_width
                } else {
                    0
                });
                ListItem::new(Text::from(wrap_line(
                    vec![Span::styled(prefix, style)],
                    vec![
                        MarqueeSegment::new(label, style),
                        MarqueeSegment::new(size_str, theme::muted_style()),
                    ],
                    available_width,
                )))
            })
            .collect();

        let title = format!("Browse // {}", self.current_dir);
        let list = List::new(list_items)
            .block(theme::panel_block(title))
            .style(theme::list_style())
            .highlight_style(theme::list_highlight_style())
            .highlight_symbol(highlight_symbol);

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
            let panel_width = content_chunks[1].width.saturating_sub(2);

            if let Some(ref error) = self.error {
                // Prominent error display with next steps
                let error_style = theme::error_style();
                let hint_style = theme::warning_style();

                lines.push(marquee_text_line(
                    "!! Remote listing failed !!",
                    error_style,
                    panel_width,
                    self.animation_frame,
                ));
                lines.push(Line::from(""));

                lines.push(marquee_text_line(
                    error,
                    theme::error_style(),
                    panel_width,
                    self.animation_frame,
                ));
                lines.push(Line::from(""));

                // Classify the error and give specific advice
                let advice = classify_listing_error(error);
                lines.push(marquee_text_line(
                    "What happened:",
                    hint_style,
                    panel_width,
                    self.animation_frame,
                ));
                lines.push(marquee_text_line(
                    advice.explanation,
                    Style::default().fg(theme::text_primary()),
                    panel_width,
                    self.animation_frame,
                ));
                lines.push(Line::from(""));

                lines.push(marquee_text_line(
                    "Next steps:",
                    hint_style,
                    panel_width,
                    self.animation_frame,
                ));
                for step in &advice.next_steps {
                    lines.push(marquee_text_line(
                        format!("  {}", step),
                        Style::default().fg(theme::text_primary()),
                        panel_width,
                        self.animation_frame,
                    ));
                }
                lines.push(Line::from(""));
                lines.push(marquee_text_line(
                    "Esc: back to main menu",
                    theme::strong_style(),
                    panel_width,
                    self.animation_frame,
                ));
            } else {
                lines.push(marquee_text_line(
                    "Config File Browser",
                    theme::panel_title_style(),
                    panel_width,
                    self.animation_frame,
                ));
                lines.push(Line::from(""));

                if let Some(entry) = self.entries.get(self.selected) {
                    let kind = if entry.name == "." || entry.name == ".." {
                        "Navigation"
                    } else if entry.is_dir {
                        "Directory"
                    } else {
                        "File"
                    };
                    lines.push(marquee_text_line(
                        format!("Selected: {}", entry.name),
                        theme::strong_style(),
                        panel_width,
                        self.animation_frame,
                    ));
                    lines.push(marquee_text_line(
                        format!("Type: {}", kind),
                        theme::strong_style(),
                        panel_width,
                        self.animation_frame,
                    ));
                    if let Some(size) = entry.size {
                        lines.push(marquee_text_line(
                            format!("Size: {} bytes", size),
                            theme::strong_style(),
                            panel_width,
                            self.animation_frame,
                        ));
                    }
                    lines.push(Line::from(""));
                }

                if !self.preview.is_empty() {
                    for line in &self.preview {
                        lines.push(marquee_text_line(
                            line,
                            theme::success_style(),
                            panel_width,
                            self.animation_frame,
                        ));
                    }
                    lines.push(Line::from(""));
                }

                lines.push(marquee_text_line(
                    format!("Status: {}", self.status),
                    theme::strong_style(),
                    panel_width,
                    self.animation_frame,
                ));
                lines.push(Line::from(""));
                lines.push(marquee_text_line(
                    "Enter: open dir / select file",
                    theme::strong_style(),
                    panel_width,
                    self.animation_frame,
                ));
                lines.push(marquee_text_line(
                    "Backspace: parent directory",
                    theme::strong_style(),
                    panel_width,
                    self.animation_frame,
                ));
                lines.push(marquee_text_line(
                    "Esc: back to main menu",
                    theme::strong_style(),
                    panel_width,
                    self.animation_frame,
                ));
            }

            let title = if self.error.is_some() {
                "Error"
            } else {
                "Details"
            };
            let panel = Paragraph::new(lines)
                .block(theme::panel_block(title))
                .wrap(Wrap { trim: false });
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
