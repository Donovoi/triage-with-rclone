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

        // Detect the current phase from the status text to show the right header.
        let auth_done = self.status.starts_with("Testing connectivity")
            || self.status.starts_with("Listing files")
            || self.status.starts_with("Connectivity")
            || self.status.starts_with("Authentication succeeded")
            || self.status.starts_with("Found ")
            || self.status.starts_with("Exported ");

        if auth_done {
            lines.push(Line::from(vec![
                Span::styled("Authenticated: ", static_style()),
                Span::styled(&self.provider_name, status_style()),
            ]));
        } else {
            lines.push(Line::from(vec![
                Span::styled("Authenticating: ", static_style()),
                Span::styled(&self.provider_name, status_style()),
            ]));
        }

        if !self.status.is_empty() {
            for line in self.status.lines() {
                lines.push(Line::from(Span::styled(line.to_string(), status_style())));
            }
        }
        lines.push(Line::from(""));

        if !auth_done {
            lines.push(Line::from(Span::styled(
                "Complete the authentication flow and return here.",
                static_style(),
            )));
        }

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

    #[test]
    fn test_render_during_auth_shows_complete_instruction() {
        let buf_area = Rect::new(0, 0, 80, 10);
        let mut buf = Buffer::empty(buf_area);
        let screen = AuthScreen::new("Google Drive", "Opening browser...");
        (&screen).render(buf_area, &mut buf);

        let text: String = (0..buf_area.height)
            .map(|y| {
                (0..buf_area.width)
                    .map(|x| buf[(x, y)].symbol().chars().next().unwrap_or(' '))
                    .collect::<String>()
            })
            .collect::<Vec<_>>()
            .join("\n");

        assert!(text.contains("Authenticating:"), "Should show 'Authenticating:' during auth");
        assert!(text.contains("Complete the authentication"), "Should show completion instruction during auth");
    }

    #[test]
    fn test_render_after_auth_hides_complete_instruction() {
        let buf_area = Rect::new(0, 0, 80, 10);
        let mut buf = Buffer::empty(buf_area);
        let screen = AuthScreen::new("Google Drive", "Testing connectivity...");
        (&screen).render(buf_area, &mut buf);

        let text: String = (0..buf_area.height)
            .map(|y| {
                (0..buf_area.width)
                    .map(|x| buf[(x, y)].symbol().chars().next().unwrap_or(' '))
                    .collect::<String>()
            })
            .collect::<Vec<_>>()
            .join("\n");

        assert!(text.contains("Authenticated:"), "Should show 'Authenticated:' post-auth");
        assert!(!text.contains("Complete the authentication"), "Should NOT show completion instruction post-auth");
    }

    #[test]
    fn test_render_listing_failure_no_auth_prompt() {
        let buf_area = Rect::new(0, 0, 100, 10);
        let mut buf = Buffer::empty(buf_area);
        let screen = AuthScreen::new(
            "Google Drive",
            "Authentication succeeded, but listing failed: timeout",
        );
        (&screen).render(buf_area, &mut buf);

        let text: String = (0..buf_area.height)
            .map(|y| {
                (0..buf_area.width)
                    .map(|x| buf[(x, y)].symbol().chars().next().unwrap_or(' '))
                    .collect::<String>()
            })
            .collect::<Vec<_>>()
            .join("\n");

        assert!(text.contains("Authenticated:"), "Should show 'Authenticated:' when auth succeeded");
        assert!(!text.contains("Complete the authentication"), "Must NOT ask user to authenticate again");
    }
}
