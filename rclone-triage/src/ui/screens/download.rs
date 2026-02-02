//! Download progress screen

use ratatui::buffer::Buffer;
use ratatui::layout::{Constraint, Direction, Layout, Rect};
use ratatui::widgets::Widget;

use crate::ui::widgets::ProgressBar;

pub struct DownloadScreen {
    pub overall: ProgressBar,
    pub current: ProgressBar,
}

impl DownloadScreen {
    pub fn new() -> Self {
        Self {
            overall: ProgressBar::new("Overall", 0.0),
            current: ProgressBar::new("Current", 0.0),
        }
    }
}

impl Widget for &DownloadScreen {
    fn render(self, area: Rect, buf: &mut Buffer) {
        let chunks = Layout::default()
            .direction(Direction::Vertical)
            .constraints([Constraint::Length(3), Constraint::Length(3)].as_ref())
            .split(area);

        (&self.overall).render(chunks[0], buf);
        (&self.current).render(chunks[1], buf);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ratatui::buffer::Buffer;

    #[test]
    fn test_render() {
        let mut buf = Buffer::empty(Rect::new(0, 0, 50, 8));
        let screen = DownloadScreen::new();
        (&screen).render(Rect::new(0, 0, 50, 8), &mut buf);
    }
}
