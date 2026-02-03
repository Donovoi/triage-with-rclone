//! Browser selection screen

use ratatui::buffer::Buffer;
use ratatui::layout::Rect;
use ratatui::widgets::Widget;

use crate::ui::widgets::BrowserList;

pub struct BrowserSelectScreen {
    pub list: BrowserList,
}

impl BrowserSelectScreen {
    pub fn new(browsers: Vec<String>) -> Self {
        Self {
            list: BrowserList::new(browsers),
        }
    }
}

impl Widget for &BrowserSelectScreen {
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
        let screen = BrowserSelectScreen::new(vec![
            "System Default".to_string(),
            "Mozilla Firefox".to_string(),
        ]);
        (&screen).render(Rect::new(0, 0, 50, 10), &mut buf);
    }
}
