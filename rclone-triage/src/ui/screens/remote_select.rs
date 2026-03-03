//! Remote selection screen

use ratatui::buffer::Buffer;
use ratatui::layout::Rect;
use ratatui::style::{Color, Modifier, Style};
use ratatui::widgets::{Block, Borders, List, ListItem, ListState, StatefulWidget, Widget};

pub struct RemoteSelectScreen {
    pub remotes: Vec<String>,
    pub checked: Vec<bool>,
    pub selected: usize,
}

impl RemoteSelectScreen {
    pub fn new(remotes: Vec<String>, checked: Vec<bool>, selected: usize) -> Self {
        Self {
            remotes,
            checked,
            selected,
        }
    }
}

impl Widget for &RemoteSelectScreen {
    fn render(self, area: Rect, buf: &mut Buffer) {
        let title = if self.remotes.is_empty() {
            "Remotes".to_string()
        } else {
            format!("Remotes ({}) — Space: toggle, Enter: confirm", self.remotes.len())
        };

        let items: Vec<ListItem> = self
            .remotes
            .iter()
            .enumerate()
            .map(|(idx, name)| {
                let checked = self.checked.get(idx).copied().unwrap_or(false);
                let prefix = if checked { "[x] " } else { "[ ] " };
                ListItem::new(format!("{prefix}{name}"))
            })
            .collect();

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
        if !self.remotes.is_empty() {
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
    fn test_render() {
        let mut buf = Buffer::empty(Rect::new(0, 0, 50, 10));
        let screen = RemoteSelectScreen::new(
            vec!["Personal".to_string(), "Business".to_string()],
            vec![false, true],
            0,
        );
        (&screen).render(Rect::new(0, 0, 50, 10), &mut buf);
    }
}
