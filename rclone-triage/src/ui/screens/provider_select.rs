//! Provider selection screen

use ratatui::buffer::Buffer;
use ratatui::layout::Rect;
use ratatui::widgets::Widget;

use crate::ui::widgets::ProviderList;

pub struct ProviderSelectScreen {
    pub list: ProviderList,
}

impl ProviderSelectScreen {
    pub fn new(providers: Vec<String>) -> Self {
        Self {
            list: ProviderList::new(providers),
        }
    }
}

impl Widget for &ProviderSelectScreen {
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
        let screen = ProviderSelectScreen::new(vec![
            "Google Drive".to_string(),
            "Dropbox".to_string(),
        ]);
        (&screen).render(Rect::new(0, 0, 50, 10), &mut buf);
    }
}
