//! Simple list widget for single-selection lists

use ratatui::buffer::Buffer;
use ratatui::layout::Rect;
use ratatui::style::{Color, Modifier, Style};
use ratatui::widgets::{Block, Borders, List, ListItem, ListState, StatefulWidget, Widget};

/// Simple list widget
#[derive(Debug, Clone)]
pub struct SimpleList {
    pub title: String,
    pub items: Vec<String>,
    pub selected: usize,
}

impl SimpleList {
    pub fn new(title: impl Into<String>, items: Vec<String>, selected: usize) -> Self {
        Self {
            title: title.into(),
            items,
            selected,
        }
    }
}

impl Widget for &SimpleList {
    fn render(self, area: Rect, buf: &mut Buffer) {
        let list_items = self
            .items
            .iter()
            .map(|item| ListItem::new(item.clone()))
            .collect::<Vec<_>>();

        let list = List::new(list_items)
            .block(
                Block::default()
                    .title(self.title.as_str())
                    .borders(Borders::ALL),
            )
            .style(Style::default().fg(Color::Black).bg(Color::Gray))
            .highlight_style(
                Style::default()
                    .fg(Color::White)
                    .bg(Color::DarkGray)
                    .add_modifier(Modifier::BOLD),
            )
            .highlight_symbol("▶ ");

        let mut state = ListState::default();
        if !self.items.is_empty() {
            let selected = self.selected.min(self.items.len().saturating_sub(1));
            state.select(Some(selected));
        }

        StatefulWidget::render(list, area, buf, &mut state);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ratatui::buffer::Buffer;

    #[test]
    fn test_simple_list_render() {
        let mut buf = Buffer::empty(Rect::new(0, 0, 40, 10));
        let list = SimpleList::new(
            "Remotes",
            vec!["Personal".to_string(), "Business".to_string()],
            0,
        );

        (&list).render(Rect::new(0, 0, 40, 10), &mut buf);
    }
}
