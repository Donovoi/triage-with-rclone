//! File tree widget for browsing remote files

use ratatui::buffer::Buffer;
use ratatui::layout::Rect;
use ratatui::style::{Color, Modifier, Style};
use ratatui::widgets::{Block, Borders, List, ListItem, ListState, StatefulWidget, Widget};

/// File tree widget
#[derive(Debug, Clone)]
pub struct FileTree {
    pub entries: Vec<String>,
    pub selected: usize,
}

impl FileTree {
    pub fn new(entries: Vec<String>) -> Self {
        Self {
            entries,
            selected: 0,
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
        let items: Vec<ListItem> = self
            .entries
            .iter()
            .map(|e| ListItem::new(e.clone()))
            .collect();

        let list = List::new(items)
            .block(Block::default().title("Files").borders(Borders::ALL))
            .style(Style::default().fg(Color::Black).bg(Color::Gray))
            .highlight_style(
                Style::default()
                    .fg(Color::White)
                    .bg(Color::DarkGray)
                    .add_modifier(Modifier::BOLD),
            )
            .highlight_symbol("▶ ");

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
