//! Final report screen

use ratatui::buffer::Buffer;
use ratatui::layout::Rect;
use ratatui::text::Line;
use ratatui::widgets::{Paragraph, Widget};

pub struct ReportScreen {
    pub summary: Vec<String>,
}

impl ReportScreen {
    pub fn new(summary: Vec<String>) -> Self {
        Self { summary }
    }
}

impl Widget for &ReportScreen {
    fn render(self, area: Rect, buf: &mut Buffer) {
        let lines = self
            .summary
            .iter()
            .cloned()
            .map(Line::from)
            .collect::<Vec<_>>();
        let paragraph = Paragraph::new(lines);
        paragraph.render(area, buf);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ratatui::buffer::Buffer;

    #[test]
    fn test_render() {
        let mut buf = Buffer::empty(Rect::new(0, 0, 60, 8));
        let screen = ReportScreen::new(vec!["Done".to_string(), "No errors".to_string()]);
        (&screen).render(Rect::new(0, 0, 60, 8), &mut buf);
    }
}
