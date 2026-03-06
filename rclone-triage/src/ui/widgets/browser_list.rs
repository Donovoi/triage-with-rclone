//! Browser list widget

use ratatui::buffer::Buffer;
use ratatui::layout::Rect;
use ratatui::text::{Line, Span};
use ratatui::widgets::{Block, Borders, List, ListItem, ListState, StatefulWidget, Widget};

use crate::ui::theme;

/// Browser list widget
#[derive(Debug, Clone)]
pub struct BrowserList {
    pub browsers: Vec<String>,
    pub checked: Vec<bool>,
    pub selected: usize,
}

impl BrowserList {
    pub fn new(browsers: Vec<String>, checked: Vec<bool>, selected: usize) -> Self {
        Self {
            browsers,
            checked,
            selected,
        }
    }

    pub fn select_next(&mut self) {
        if !self.browsers.is_empty() {
            self.selected = (self.selected + 1) % self.browsers.len();
        }
    }

    pub fn select_previous(&mut self) {
        if !self.browsers.is_empty() {
            if self.selected == 0 {
                self.selected = self.browsers.len() - 1;
            } else {
                self.selected -= 1;
            }
        }
    }
}

impl Widget for &BrowserList {
    fn render(self, area: Rect, buf: &mut Buffer) {
        let items: Vec<ListItem> = self
            .browsers
            .iter()
            .enumerate()
            .map(|(idx, b)| {
                let checked = self.checked.get(idx).copied().unwrap_or(false);
                let prefix = if checked { "[x] " } else { "[ ] " };
                let prefix_style = if checked {
                    theme::success_style()
                } else {
                    theme::muted_style()
                };
                ListItem::new(Line::from(vec![
                    Span::styled(prefix, prefix_style),
                    Span::styled(b.to_string(), theme::strong_style()),
                ]))
            })
            .collect();

        let list = List::new(items)
            .block(
                Block::default()
                    .title(Line::from(Span::styled(
                        "Browsers",
                        theme::panel_title_style(),
                    )))
                    .borders(Borders::ALL)
                    .border_style(theme::panel_border_style()),
            )
            .style(theme::list_style())
            .highlight_style(theme::list_highlight_style())
            .highlight_symbol(theme::list_highlight_symbol(0));

        let mut state = ListState::default();
        if !self.browsers.is_empty() {
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
    fn test_browser_list_render() {
        let mut buf = Buffer::empty(Rect::new(0, 0, 40, 10));
        let list = BrowserList::new(
            vec!["System Default".to_string(), "Google Chrome".to_string()],
            vec![false, true],
            0,
        );

        (&list).render(Rect::new(0, 0, 40, 10), &mut buf);
    }
}
