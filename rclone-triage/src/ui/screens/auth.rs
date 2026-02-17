//! Authentication screen

use ratatui::buffer::Buffer;
use ratatui::layout::Rect;
use ratatui::style::{Color, Modifier, Style};
use ratatui::text::{Line, Span};
use ratatui::widgets::{Paragraph, Widget};

/// Bright green style for dynamic/working status messages.
fn status_style() -> Style {
    Style::default()
        .fg(Color::LightGreen)
        .add_modifier(Modifier::BOLD)
}

/// Default style for static instruction text.
fn static_style() -> Style {
    Style::default().add_modifier(Modifier::BOLD)
}

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
        lines.push(Line::from(vec![
            Span::styled("Authenticating: ", static_style()),
            Span::styled(&self.provider_name, status_style()),
        ]));
        if !self.status.is_empty() {
            for line in self.status.lines() {
                lines.push(Line::from(Span::styled(line.to_string(), status_style())));
            }
        }
        lines.push(Line::from(""));
        lines.push(Line::from(Span::styled(
            "Complete the authentication flow and return here.",
            static_style(),
        )));
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
        let screen = AuthScreen::new("Google Drive", "Waiting for auth...");
        (&screen).render(Rect::new(0, 0, 60, 8), &mut buf);
    }
}
