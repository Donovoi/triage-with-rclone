//! Simple list widget for single-selection lists

use ratatui::buffer::Buffer;
use ratatui::layout::Rect;
use ratatui::text::{Line, Span};
use ratatui::widgets::{Block, Borders, List, ListItem, ListState, StatefulWidget, Widget};

use crate::ui::theme;
use crate::ui::widgets::{marquee_text_line, text_width};

/// Simple list widget
#[derive(Debug, Clone)]
pub struct SimpleList {
    pub title: String,
    pub items: Vec<String>,
    pub selected: usize,
    pub animation_frame: u64,
}

impl SimpleList {
    pub fn new(title: impl Into<String>, items: Vec<String>, selected: usize) -> Self {
        Self {
            title: title.into(),
            items,
            selected,
            animation_frame: 0,
        }
    }
}

impl Widget for &SimpleList {
    fn render(self, area: Rect, buf: &mut Buffer) {
        let highlight_width = text_width(theme::list_highlight_symbol(self.animation_frame)) as u16;
        let inner_width = area.width.saturating_sub(2);
        let list_items = self
            .items
            .iter()
            .enumerate()
            .map(|(idx, item)| {
                let available_width = inner_width.saturating_sub(if idx == self.selected {
                    highlight_width
                } else {
                    0
                });
                ListItem::new(marquee_text_line(
                    item,
                    theme::strong_style(),
                    available_width,
                    self.animation_frame,
                ))
            })
            .collect::<Vec<_>>();

        let list = List::new(list_items)
            .block(
                Block::default()
                    .title(Line::from(Span::styled(
                        self.title.clone(),
                        theme::panel_title_style(),
                    )))
                    .borders(Borders::ALL)
                    .border_style(theme::panel_border_style()),
            )
            .style(theme::list_style())
            .highlight_style(theme::list_highlight_style())
            .highlight_symbol(theme::list_highlight_symbol(self.animation_frame));

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
