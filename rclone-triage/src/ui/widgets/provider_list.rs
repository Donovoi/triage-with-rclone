//! Provider list widget

use ratatui::buffer::Buffer;
use ratatui::layout::Rect;
use ratatui::style::{Color, Modifier, Style};
use ratatui::widgets::{Block, Borders, List, ListItem, ListState, StatefulWidget, Widget};

/// Provider list widget
#[derive(Debug, Clone)]
pub struct ProviderList {
    pub providers: Vec<String>,
    pub checked: Vec<bool>,
    pub selected: usize,
}

impl ProviderList {
    pub fn new(providers: Vec<String>, checked: Vec<bool>, selected: usize) -> Self {
        Self {
            providers,
            checked,
            selected,
        }
    }

    pub fn select_next(&mut self) {
        if !self.providers.is_empty() {
            self.selected = (self.selected + 1) % self.providers.len();
        }
    }

    pub fn select_previous(&mut self) {
        if !self.providers.is_empty() {
            if self.selected == 0 {
                self.selected = self.providers.len() - 1;
            } else {
                self.selected -= 1;
            }
        }
    }
}

impl Widget for &ProviderList {
    fn render(self, area: Rect, buf: &mut Buffer) {
        let items: Vec<ListItem> = self
            .providers
            .iter()
            .enumerate()
            .map(|(idx, p)| {
                let checked = self.checked.get(idx).copied().unwrap_or(false);
                let prefix = if checked { "[x] " } else { "[ ] " };
                ListItem::new(format!("{prefix}{p}"))
            })
            .collect();

        let title = if self.providers.is_empty() {
            "Providers".to_string()
        } else {
            format!("Providers ({})", self.providers.len())
        };
        let list = List::new(items)
            .block(Block::default().title(title).borders(Borders::ALL))
            .style(Style::default().fg(Color::Black).bg(Color::Gray))
            .highlight_style(
                Style::default()
                    .fg(Color::White)
                    .bg(Color::DarkGray)
                    .add_modifier(Modifier::BOLD),
            )
            .highlight_symbol("▶ ");

        let mut state = ListState::default();
        if !self.providers.is_empty() {
            state.select(Some(self.selected));
        }

        StatefulWidget::render(list, area, buf, &mut state);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ratatui::buffer::Buffer;

    #[test]
    fn test_provider_list_render() {
        let mut buf = Buffer::empty(Rect::new(0, 0, 40, 10));
        let list = ProviderList::new(
            vec!["Google Drive".to_string(), "OneDrive".to_string()],
            vec![true, false],
            0,
        );

        (&list).render(Rect::new(0, 0, 40, 10), &mut buf);
    }
}
