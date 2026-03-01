//! Config file browser screen

use ratatui::buffer::Buffer;
use ratatui::layout::{Constraint, Direction, Layout, Rect};
use ratatui::style::{Color, Modifier, Style};
use ratatui::text::{Line, Span};
use ratatui::widgets::{Block, Borders, List, ListItem, ListState, Paragraph, StatefulWidget, Widget, Wrap};

use crate::ui::ConfigBrowserEntry;

pub struct ConfigBrowserScreen {
    pub current_dir: String,
    pub entries: Vec<ConfigBrowserEntry>,
    pub selected: usize,
    pub status: String,
    pub preview: Vec<String>,
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
        }
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
                let prefix = if entry.is_dir { "[DIR]  " } else { "[FILE] " };
                let style = if entry.is_dir {
                    Style::default().fg(Color::LightBlue)
                } else if entry.name.ends_with(".conf") || entry.name.ends_with(".cfg") {
                    Style::default().fg(Color::LightGreen)
                } else {
                    Style::default()
                };
                let size_str = entry
                    .size
                    .map(|s| format!("  ({} B)", s))
                    .unwrap_or_default();
                ListItem::new(Line::from(vec![
                    Span::styled(prefix, style),
                    Span::styled(&entry.name, style),
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

        // Right panel: status + preview
        let show_panel = content_chunks[1].width >= 20 && content_chunks[1].height >= 4;
        if show_panel {
            let mut lines = Vec::new();
            lines.push(Line::from(Span::styled(
                "Config File Browser",
                Style::default().add_modifier(Modifier::BOLD),
            )));
            lines.push(Line::from(""));

            if let Some(entry) = self.entries.get(self.selected) {
                let kind = if entry.is_dir { "Directory" } else { "File" };
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

            let panel = Paragraph::new(lines)
                .block(Block::default().title("Details").borders(Borders::ALL))
                .wrap(Wrap { trim: true });
            panel.render(content_chunks[1], buf);
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
        let screen = ConfigBrowserScreen::new(
            "/tmp".to_string(),
            vec![],
            0,
            "Empty directory".to_string(),
            vec![],
        );
        (&screen).render(Rect::new(0, 0, 80, 20), &mut buf);
    }

    #[test]
    fn test_render_with_entries() {
        let mut buf = Buffer::empty(Rect::new(0, 0, 80, 20));
        let entries = vec![
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
            1,
            "2 items".to_string(),
            vec!["Remotes (1)".to_string(), "  myremote (drive)".to_string()],
        );
        (&screen).render(Rect::new(0, 0, 80, 20), &mut buf);
    }
}
