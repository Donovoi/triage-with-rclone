//! Remote selection screen

use ratatui::buffer::Buffer;
use ratatui::layout::Rect;
use ratatui::widgets::Widget;

use crate::ui::widgets::SimpleList;

pub struct RemoteSelectScreen {
    pub list: SimpleList,
}

impl RemoteSelectScreen {
    pub fn new(remotes: Vec<String>, selected: usize) -> Self {
        let title = if remotes.is_empty() {
            "Remotes".to_string()
        } else {
            format!("Remotes ({})", remotes.len())
        };
        Self {
            list: SimpleList::new(title, remotes, selected),
        }
    }
}

impl Widget for &RemoteSelectScreen {
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
        let screen =
            RemoteSelectScreen::new(vec!["Personal".to_string(), "Business".to_string()], 0);
        (&screen).render(Rect::new(0, 0, 50, 10), &mut buf);
    }
}
