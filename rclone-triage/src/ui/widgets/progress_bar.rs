//! Progress bar widget

use ratatui::buffer::Buffer;
use ratatui::layout::Rect;
use ratatui::widgets::{Block, Borders, Gauge, Widget};

/// Progress bar widget
#[derive(Debug, Clone)]
pub struct ProgressBar {
    pub label: String,
    pub progress: f64,
}

impl ProgressBar {
    pub fn new(label: impl Into<String>, progress: f64) -> Self {
        Self {
            label: label.into(),
            progress: progress.clamp(0.0, 1.0),
        }
    }

    pub fn set_progress(&mut self, value: f64) {
        self.progress = value.clamp(0.0, 1.0);
    }
}

impl Widget for &ProgressBar {
    fn render(self, area: Rect, buf: &mut Buffer) {
        let gauge = Gauge::default()
            .block(
                Block::default()
                    .title(self.label.clone())
                    .borders(Borders::ALL),
            )
            .ratio(self.progress);

        gauge.render(area, buf);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ratatui::buffer::Buffer;

    #[test]
    fn test_progress_bar_render() {
        let mut buf = Buffer::empty(Rect::new(0, 0, 40, 3));
        let bar = ProgressBar::new("Download", 0.42);

        (&bar).render(Rect::new(0, 0, 40, 3), &mut buf);
    }
}
