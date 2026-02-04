//! Authentication screen

use ratatui::buffer::Buffer;
use ratatui::layout::Rect;
use ratatui::style::{Modifier, Style};
use ratatui::text::Line;
use ratatui::widgets::{Paragraph, Widget};

pub struct AuthScreen {
    pub provider_name: String,
    pub status: String,
}

impl AuthScreen {
    pub fn new(provider_name: impl Into<String>, status: impl Into<String>) -> Self {
        Self {
            provider_name: provider_name.into(),
            status: status.into(),
        }
    }
}

impl Widget for &AuthScreen {
    fn render(self, area: Rect, buf: &mut Buffer) {
        let mut lines = Vec::new();
        lines.push(Line::from(format!("Authenticating: {}", self.provider_name)));
        if !self.status.is_empty() {
            for line in self.status.lines() {
                lines.push(Line::from(line.to_string()));
            }
        }
        lines.push(Line::from(""));
        lines.push(Line::from(
            "Complete the authentication flow and return here.",
        ));
        let paragraph = Paragraph::new(lines).style(Style::default().add_modifier(Modifier::BOLD));
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
        let screen = AuthScreen::new("Google Drive", "Waiting for auth...");
        (&screen).render(Rect::new(0, 0, 60, 8), &mut buf);
    }
}
