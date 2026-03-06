//! Remote selection screen

use ratatui::buffer::Buffer;
use ratatui::layout::Rect;
use ratatui::text::{Line, Span};
use ratatui::widgets::{List, ListItem, ListState, StatefulWidget, Widget};

use crate::ui::theme;

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
            format!(
                "Remotes ({}) — Space: toggle, Enter: confirm",
                self.remotes.len()
            )
        };

        let items: Vec<ListItem> = self
            .remotes
            .iter()
            .enumerate()
            .map(|(idx, name)| {
                let checked = self.checked.get(idx).copied().unwrap_or(false);
                let prefix = if checked { "[x] " } else { "[ ] " };
                let prefix_style = if checked {
                    theme::success_style()
                } else {
                    theme::muted_style()
                };
                ListItem::new(Line::from(vec![
                    Span::styled(prefix, prefix_style),
                    Span::styled(name.to_string(), theme::strong_style()),
                ]))
            })
            .collect();

        let list = List::new(items)
            .block(theme::panel_block(title))
            .style(theme::list_style())
            .highlight_style(theme::list_highlight_style())
            .highlight_symbol(theme::list_highlight_symbol(0));

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
