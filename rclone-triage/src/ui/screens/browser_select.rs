//! Browser selection screen

use ratatui::buffer::Buffer;
use ratatui::layout::Rect;
use ratatui::widgets::Widget;

use crate::ui::widgets::BrowserList;

pub struct BrowserSelectScreen {
    pub list: BrowserList,
}

impl BrowserSelectScreen {
    pub fn new(browsers: Vec<String>, checked: Vec<bool>, selected: usize) -> Self {
        Self {
            list: BrowserList::new(browsers, checked, selected),
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
        ], vec![false, true], 1);
        (&screen).render(Rect::new(0, 0, 50, 10), &mut buf);
    }
}
