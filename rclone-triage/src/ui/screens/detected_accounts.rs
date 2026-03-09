//! Detected-account review screen.

use ratatui::buffer::Buffer;
use ratatui::layout::{Constraint, Direction, Layout, Rect};
use ratatui::text::{Line, Span};
use ratatui::widgets::{List, ListItem, ListState, Paragraph, StatefulWidget, Widget, Wrap};

use crate::ui::theme;

#[derive(Debug, Clone)]
pub struct DetectedAccountRow {
    pub label: String,
    pub checked: bool,
    pub selectable: bool,
}

pub struct DetectedAccountsScreen {
    pub rows: Vec<DetectedAccountRow>,
    pub selected: usize,
    pub details: Vec<String>,
}

impl DetectedAccountsScreen {
    pub fn new(rows: Vec<DetectedAccountRow>, selected: usize, details: Vec<String>) -> Self {
        Self {
            rows,
            selected,
            details,
        }
    }
}

impl Widget for &DetectedAccountsScreen {
    fn render(self, area: Rect, buf: &mut Buffer) {
        let chunks = Layout::default()
            .direction(Direction::Horizontal)
            .constraints([Constraint::Percentage(62), Constraint::Percentage(38)])
            .split(area);

        let items: Vec<ListItem> = self
            .rows
            .iter()
            .map(|row| {
                let prefix = if row.selectable {
                    if row.checked { "[x] " } else { "[ ] " }
                } else {
                    "[·] "
                };
                let prefix_style = if row.selectable {
                    if row.checked {
                        theme::success_style()
                    } else {
                        theme::muted_style()
                    }
                } else {
                    theme::warning_style()
                };
                let label_style = if row.selectable {
                    theme::strong_style()
                } else {
                    theme::muted_style()
                };

                ListItem::new(Line::from(vec![
                    Span::styled(prefix, prefix_style),
                    Span::styled(row.label.clone(), label_style),
                ]))
            })
            .collect();

        let list = List::new(items)
            .block(theme::panel_block(format!("Detected accounts ({})", self.rows.len())))
            .style(theme::list_style())
            .highlight_style(theme::list_highlight_style())
            .highlight_symbol(theme::list_highlight_symbol(0));

        let mut state = ListState::default();
        if !self.rows.is_empty() {
            state.select(Some(self.selected.min(self.rows.len().saturating_sub(1))));
        }
        StatefulWidget::render(list, chunks[0], buf, &mut state);

        let detail_lines: Vec<Line> = self.details.iter().cloned().map(Line::from).collect();
        let details = Paragraph::new(detail_lines)
            .block(theme::panel_block("Detection details"))
            .wrap(Wrap { trim: true });
        details.render(chunks[1], buf);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ratatui::buffer::Buffer;

    #[test]
    fn test_render_detected_accounts_screen() {
        let mut buf = Buffer::empty(Rect::new(0, 0, 90, 20));
        let screen = DetectedAccountsScreen::new(
            vec![
                DetectedAccountRow {
                    label: "Google Drive via Google Chrome [Default] — analyst@example.com (Runnable auth)"
                        .to_string(),
                    checked: true,
                    selectable: true,
                },
                DetectedAccountRow {
                    label: "Microsoft OneDrive via Google Chrome [Profile 1] — account not identified (Hint only)"
                        .to_string(),
                    checked: false,
                    selectable: false,
                },
            ],
            0,
            vec![
                "Provider: Google Drive".to_string(),
                "Capability: Runnable auth".to_string(),
            ],
        );

        (&screen).render(Rect::new(0, 0, 90, 20), &mut buf);
    }
}