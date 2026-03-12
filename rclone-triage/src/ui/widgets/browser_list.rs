//! Browser list widget

use ratatui::buffer::Buffer;
use ratatui::layout::Rect;
use ratatui::text::{Line, Span, Text};
use ratatui::widgets::{Block, Borders, List, ListItem, ListState, StatefulWidget, Widget};

use crate::ui::theme;
use crate::ui::widgets::{text_width, wrap_line, StyledSegment};

/// Browser list widget
#[derive(Debug, Clone)]
pub struct BrowserList {
    pub browsers: Vec<String>,
    pub checked: Vec<bool>,
    pub selected: usize,
    pub animation_frame: u64,
}

impl BrowserList {
    pub fn new(browsers: Vec<String>, checked: Vec<bool>, selected: usize) -> Self {
        Self {
            browsers,
            checked,
            selected,
            animation_frame: 0,
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
        let highlight_symbol = theme::list_highlight_symbol(self.animation_frame);
        let highlight_width = text_width(highlight_symbol) as u16;
        let inner_width = area.width.saturating_sub(2);
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
                let available_width = inner_width.saturating_sub(if idx == self.selected {
                    highlight_width
                } else {
                    0
                });
                ListItem::new(Text::from(wrap_line(
                    vec![Span::styled(prefix, prefix_style)],
                    vec![StyledSegment::new(b, theme::strong_style())],
                    available_width,
                )))
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
            .highlight_symbol(highlight_symbol);

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
