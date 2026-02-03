//! Browser list widget

use ratatui::buffer::Buffer;
use ratatui::layout::Rect;
use ratatui::style::{Modifier, Style};
use ratatui::widgets::{Block, Borders, List, ListItem, ListState, StatefulWidget, Widget};

/// Browser list widget
#[derive(Debug, Clone)]
pub struct BrowserList {
    pub browsers: Vec<String>,
    pub selected: usize,
}

impl BrowserList {
    pub fn new(browsers: Vec<String>) -> Self {
        Self {
            browsers,
            selected: 0,
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
            .map(|b| ListItem::new(b.clone()))
            .collect();

        let list = List::new(items)
            .block(Block::default().title("Browsers").borders(Borders::ALL))
            .highlight_style(Style::default().add_modifier(Modifier::BOLD));

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
        let list = BrowserList::new(vec![
            "System Default".to_string(),
            "Google Chrome".to_string(),
        ]);

        (&list).render(Rect::new(0, 0, 40, 10), &mut buf);
    }
}
