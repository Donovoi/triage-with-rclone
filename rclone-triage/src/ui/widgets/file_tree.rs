//! File tree widget for browsing remote files

use ratatui::buffer::Buffer;
use ratatui::layout::Rect;
use ratatui::text::{Line, Span, Text};
use ratatui::widgets::{Block, Borders, List, ListItem, ListState, StatefulWidget, Widget};

use crate::ui::theme;
use crate::ui::widgets::{text_width, wrap_text_lines};

/// File tree widget
#[derive(Debug, Clone)]
pub struct FileTree {
    pub entries: Vec<String>,
    pub selected: usize,
    pub animation_frame: u64,
}

impl FileTree {
    pub fn new(entries: Vec<String>) -> Self {
        Self {
            entries,
            selected: 0,
            animation_frame: 0,
        }
    }

    pub fn select_next(&mut self) {
        if !self.entries.is_empty() {
            self.selected = (self.selected + 1) % self.entries.len();
        }
    }

    pub fn select_previous(&mut self) {
        if !self.entries.is_empty() {
            if self.selected == 0 {
                self.selected = self.entries.len() - 1;
            } else {
                self.selected -= 1;
            }
        }
    }
}

impl Widget for &FileTree {
    fn render(self, area: Rect, buf: &mut Buffer) {
        let highlight_symbol = theme::list_highlight_symbol(self.animation_frame);
        let highlight_width = text_width(highlight_symbol) as u16;
        let inner_width = area.width.saturating_sub(2);
        let items: Vec<ListItem> = self
            .entries
            .iter()
            .enumerate()
            .map(|(idx, e)| {
                let available_width = inner_width.saturating_sub(if idx == self.selected {
                    highlight_width
                } else {
                    0
                });
                ListItem::new(Text::from(wrap_text_lines(
                    e,
                    theme::strong_style(),
                    available_width,
                )))
            })
            .collect();

        let list = List::new(items)
            .block(
                Block::default()
                    .title(Line::from(Span::styled(
                        "Files",
                        theme::panel_title_style(),
                    )))
                    .borders(Borders::ALL)
                    .border_style(theme::panel_border_style()),
            )
            .style(theme::list_style())
            .highlight_style(theme::list_highlight_style())
            .highlight_symbol(highlight_symbol);

        let mut state = ListState::default();
        if !self.entries.is_empty() {
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
    fn test_file_tree_render() {
        let mut buf = Buffer::empty(Rect::new(0, 0, 60, 10));
        let tree = FileTree::new(vec![
            "Documents/".to_string(),
            "Documents/report.pdf".to_string(),
        ]);

        (&tree).render(Rect::new(0, 0, 60, 10), &mut buf);
    }
}
