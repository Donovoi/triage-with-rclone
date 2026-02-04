//! Main menu list widget

use ratatui::buffer::Buffer;
use ratatui::layout::Rect;
use ratatui::style::{Modifier, Style};
use ratatui::widgets::{Block, Borders, List, ListItem, ListState, StatefulWidget, Widget};

/// Main menu list widget
#[derive(Debug, Clone)]
pub struct MenuList {
    pub items: Vec<String>,
    pub selected: usize,
}

impl MenuList {
    pub fn new(items: Vec<String>) -> Self {
        Self { items, selected: 0 }
    }
}

impl Widget for &MenuList {
    fn render(self, area: Rect, buf: &mut Buffer) {
        let list_items = self
            .items
            .iter()
            .map(|item| ListItem::new(item.clone()))
            .collect::<Vec<_>>();

        let list = List::new(list_items)
            .block(Block::default().title("rcloned Menu").borders(Borders::ALL))
            .highlight_style(Style::default().add_modifier(Modifier::BOLD));

        let mut state = ListState::default();
        if !self.items.is_empty() {
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
    fn test_menu_list_render() {
        let mut buf = Buffer::empty(Rect::new(0, 0, 40, 10));
        let list = MenuList::new(vec![
            "Authenticate".to_string(),
            "Retrieve list".to_string(),
        ]);

        (&list).render(Rect::new(0, 0, 40, 10), &mut buf);
    }
}
