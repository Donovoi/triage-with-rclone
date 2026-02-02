//! Log viewer widget

use ratatui::buffer::Buffer;
use ratatui::layout::Rect;
use ratatui::text::{Line, Text};
use ratatui::widgets::{Block, Borders, Paragraph, Widget, Wrap};

/// Log viewer widget
#[derive(Debug, Clone)]
pub struct LogViewer {
    pub lines: Vec<String>,
}

impl LogViewer {
    pub fn new(lines: Vec<String>) -> Self {
        Self { lines }
    }

    pub fn push(&mut self, line: impl Into<String>) {
        self.lines.push(line.into());
    }
}

impl Widget for &LogViewer {
    fn render(self, area: Rect, buf: &mut Buffer) {
        let text = Text::from(
            self.lines
                .iter()
                .map(|l| Line::from(l.clone()))
                .collect::<Vec<_>>(),
        );

        let paragraph = Paragraph::new(text)
            .wrap(Wrap { trim: true })
            .block(Block::default().title("Log").borders(Borders::ALL));

        paragraph.render(area, buf);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ratatui::buffer::Buffer;

    #[test]
    fn test_log_viewer_render() {
        let mut buf = Buffer::empty(Rect::new(0, 0, 60, 6));
        let viewer = LogViewer::new(vec![
            "[INFO] Started".to_string(),
            "[WARN] Example warning".to_string(),
        ]);

        (&viewer).render(Rect::new(0, 0, 60, 6), &mut buf);
    }
}
