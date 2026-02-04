//! Main menu screen

use ratatui::buffer::Buffer;
use ratatui::layout::Rect;
use ratatui::widgets::Widget;

use crate::ui::widgets::MenuList;

pub struct MainMenuScreen {
    pub list: MenuList,
}

impl MainMenuScreen {
    pub fn new(items: Vec<String>) -> Self {
        Self {
            list: MenuList::new(items),
        }
    }
}

impl Widget for &MainMenuScreen {
    fn render(self, area: Rect, buf: &mut Buffer) {
        (&self.list).render(area, buf);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ratatui::buffer::Buffer;

    #[test]
    fn test_render() {
        let mut buf = Buffer::empty(Rect::new(0, 0, 50, 10));
        let screen = MainMenuScreen::new(vec![
            "Authenticate".to_string(),
            "Retrieve list".to_string(),
        ]);
        (&screen).render(Rect::new(0, 0, 50, 10), &mut buf);
    }
}
