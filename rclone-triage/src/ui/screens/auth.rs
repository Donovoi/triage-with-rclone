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
        let lines = vec![
            Line::from(format!("Authenticating: {}", self.provider_name)),
            Line::from(self.status.clone()),
            Line::from(""),
            Line::from("Browser window should open for OAuth."),
        ];
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
