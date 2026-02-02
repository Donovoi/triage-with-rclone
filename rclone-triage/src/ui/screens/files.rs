//! File listing screen

use ratatui::buffer::Buffer;
use ratatui::layout::Rect;
use ratatui::widgets::Widget;

use crate::ui::widgets::FileTree;

pub struct FilesScreen {
    pub tree: FileTree,
}

impl FilesScreen {
    pub fn new(entries: Vec<String>) -> Self {
        Self {
            tree: FileTree::new(entries),
        }
    }
}

impl Widget for &FilesScreen {
    fn render(self, area: Rect, buf: &mut Buffer) {
        (&self.tree).render(area, buf);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ratatui::buffer::Buffer;

    #[test]
    fn test_render() {
        let mut buf = Buffer::empty(Rect::new(0, 0, 60, 10));
        let screen = FilesScreen::new(vec!["/".to_string(), "/docs".to_string()]);
        (&screen).render(Rect::new(0, 0, 60, 10), &mut buf);
    }
}
