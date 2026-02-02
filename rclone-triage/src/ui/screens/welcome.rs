//! Welcome screen

use ratatui::buffer::Buffer;
use ratatui::layout::{Alignment, Rect};
use ratatui::style::{Modifier, Style};
use ratatui::text::{Line, Text};
use ratatui::widgets::{Paragraph, Widget};

pub struct WelcomeScreen;

impl Widget for WelcomeScreen {
    fn render(self, area: Rect, buf: &mut Buffer) {
        let text = Text::from(vec![
            Line::from("rclone-triage"),
            Line::from("Forensic Cloud Triage Tool"),
            Line::from(""),
            Line::from("Press Enter to start"),
        ]);

        let paragraph = Paragraph::new(text)
            .style(Style::default().add_modifier(Modifier::BOLD))
            .alignment(Alignment::Center);

        paragraph.render(area, buf);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ratatui::buffer::Buffer;

    #[test]
    fn test_render() {
        let mut buf = Buffer::empty(Rect::new(0, 0, 60, 10));
        WelcomeScreen.render(Rect::new(0, 0, 60, 10), &mut buf);
    }
}
