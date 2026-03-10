//! Authentication screen

use ratatui::buffer::Buffer;
use ratatui::layout::Rect;
use ratatui::style::Style;
use ratatui::text::{Line, Span};
use ratatui::widgets::{Paragraph, Widget, Wrap};

use crate::ui::theme;
use crate::ui::widgets::{line_width, text_width};

const QR_HIDDEN_HINT: &str = "QR hidden at this window size — resize the terminal to view it.";
const COMPLETE_AUTH_HINT: &str = "Complete the authentication flow and return here.";

/// Bright green style for dynamic/working status messages.
fn status_style() -> Style {
    theme::hint_style()
}

/// Default style for static instruction text.
fn static_style() -> Style {
    theme::strong_style()
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

#[derive(Debug, Clone, PartialEq, Eq)]
enum StatusSegment {
    Text(String),
    QrBlock { label: String, lines: Vec<String> },
}

fn is_qr_label(line: &str) -> bool {
    matches!(line.trim(), "Scan this QR code:" | "WiFi QR:")
}

fn is_qr_art_line(line: &str) -> bool {
    !line.is_empty()
        && line
            .chars()
            .all(|ch| ch == ' ' || ('\u{2580}'..='\u{259F}').contains(&ch))
}

fn collect_status_segments(status: &str) -> Vec<StatusSegment> {
    let mut segments = Vec::new();
    let mut lines = status.lines().peekable();

    while let Some(line) = lines.next() {
        if is_qr_label(line) {
            let mut qr_lines = Vec::new();
            while let Some(next_line) = lines.peek() {
                if !is_qr_art_line(next_line) {
                    break;
                }
                qr_lines.push((*next_line).to_string());
                lines.next();
            }

            if !qr_lines.is_empty() {
                segments.push(StatusSegment::QrBlock {
                    label: line.to_string(),
                    lines: qr_lines,
                });
                continue;
            }
        }

        segments.push(StatusSegment::Text(line.to_string()));
    }

    segments
}

fn wrapped_line_height(width: usize, available_width: usize) -> usize {
    if available_width == 0 {
        return usize::MAX;
    }

    std::cmp::max(1, width.div_ceil(available_width))
}

impl Widget for &AuthScreen {
    fn render(self, area: Rect, buf: &mut Buffer) {
        // Detect the current phase from the status text to show the right header.
        let auth_done = self.status.starts_with("Testing connectivity")
            || self.status.starts_with("Listing files")
            || self.status.starts_with("Connectivity")
            || self.status.starts_with("Authenticated")
            || self.status.starts_with("Authentication succeeded")
            || self.status.starts_with("Found ")
            || self.status.starts_with("Exported ");

        let block = theme::panel_block("Authentication");
        let inner = block.inner(area);
        let inner_width = inner.width as usize;
        let inner_height = inner.height as usize;

        if inner_width == 0 || inner_height == 0 {
            Paragraph::new(Vec::<Line>::new())
                .block(block)
                .render(area, buf);
            return;
        }

        let header = if auth_done {
            Line::from(vec![
                Span::styled("Authenticated: ".to_string(), static_style()),
                Span::styled(self.provider_name.clone(), status_style()),
            ])
        } else {
            Line::from(vec![
                Span::styled("Authenticating: ".to_string(), static_style()),
                Span::styled(self.provider_name.clone(), status_style()),
            ])
        };

        let mut lines = vec![header.clone()];
        let mut used_height = wrapped_line_height(line_width(&header), inner_width);

        for segment in collect_status_segments(&self.status) {
            match segment {
                StatusSegment::Text(text) => {
                    lines.push(Line::from(Span::styled(text.clone(), status_style())));
                    used_height = used_height
                        .saturating_add(wrapped_line_height(text_width(&text), inner_width));
                }
                StatusSegment::QrBlock {
                    label,
                    lines: qr_lines,
                } => {
                    lines.push(Line::from(Span::styled(label.clone(), status_style())));
                    used_height = used_height
                        .saturating_add(wrapped_line_height(text_width(&label), inner_width));

                    let qr_width = qr_lines
                        .iter()
                        .map(|line| text_width(line))
                        .max()
                        .unwrap_or(0);
                    let qr_height = qr_lines.len();
                    let remaining_height = inner_height.saturating_sub(used_height);

                    if qr_width <= inner_width && qr_height <= remaining_height {
                        for qr_line in qr_lines {
                            lines.push(Line::from(Span::styled(qr_line, status_style())));
                        }
                        used_height = used_height.saturating_add(qr_height);
                    } else {
                        let hint_height =
                            wrapped_line_height(text_width(QR_HIDDEN_HINT), inner_width);
                        if hint_height <= remaining_height {
                            lines.push(Line::from(Span::styled(
                                QR_HIDDEN_HINT.to_string(),
                                static_style(),
                            )));
                            used_height = used_height.saturating_add(hint_height);
                        }
                    }
                }
            }
        }

        if !auth_done {
            let instruction_height =
                1 + wrapped_line_height(text_width(COMPLETE_AUTH_HINT), inner_width);
            if used_height.saturating_add(instruction_height) <= inner_height {
                lines.push(Line::from(""));
                lines.push(Line::from(Span::styled(
                    COMPLETE_AUTH_HINT.to_string(),
                    static_style(),
                )));
            }
        }

        let paragraph = Paragraph::new(lines)
            .block(block)
            .wrap(Wrap { trim: false });
        paragraph.render(area, buf);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::providers::mobile::render_qr_code;
    use ratatui::buffer::Buffer;

    fn rendered_text(buf: &Buffer, area: Rect) -> String {
        (0..area.height)
            .map(|y| {
                (0..area.width)
                    .map(|x| buf[(x, y)].symbol().chars().next().unwrap_or(' '))
                    .collect::<String>()
            })
            .collect::<Vec<_>>()
            .join("\n")
    }

    fn contains_qr_art(text: &str) -> bool {
        text.chars().any(|ch| matches!(ch, '▀' | '▄' | '█'))
    }

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

        let text = rendered_text(&buf, buf_area);

        assert!(
            text.contains("Authenticating:"),
            "Should show 'Authenticating:' during auth"
        );
        assert!(
            text.contains("Complete the authentication"),
            "Should show completion instruction during auth"
        );
    }

    #[test]
    fn test_render_after_auth_hides_complete_instruction() {
        let buf_area = Rect::new(0, 0, 80, 10);
        let mut buf = Buffer::empty(buf_area);
        let screen = AuthScreen::new("Google Drive", "Testing connectivity...");
        (&screen).render(buf_area, &mut buf);

        let text = rendered_text(&buf, buf_area);

        assert!(
            text.contains("Authenticated:"),
            "Should show 'Authenticated:' post-auth"
        );
        assert!(
            !text.contains("Complete the authentication"),
            "Should NOT show completion instruction post-auth"
        );
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

        let text = rendered_text(&buf, buf_area);

        assert!(
            text.contains("Authenticated:"),
            "Should show 'Authenticated:' when auth succeeded"
        );
        assert!(
            !text.contains("Complete the authentication"),
            "Must NOT ask user to authenticate again"
        );
    }

    #[test]
    fn test_render_shows_qr_when_it_fits() {
        let qr = render_qr_code("https://example.com/device-auth").unwrap();
        let status = format!(
            "Open on phone: https://example.com/device-auth\nScan this QR code:\n{}",
            qr
        );
        let buf_area = Rect::new(0, 0, 100, 40);
        let mut buf = Buffer::empty(buf_area);
        let screen = AuthScreen::new("Google Drive", status);
        (&screen).render(buf_area, &mut buf);

        let text = rendered_text(&buf, buf_area);

        assert!(text.contains("Scan this QR code:"));
        assert!(contains_qr_art(&text));
        assert!(!text.contains(QR_HIDDEN_HINT));
    }

    #[test]
    fn test_render_hides_qr_when_height_is_too_small() {
        let qr = render_qr_code("https://example.com/device-auth").unwrap();
        let status = format!(
            "Open on phone: https://example.com/device-auth\nScan this QR code:\n{}",
            qr
        );
        let buf_area = Rect::new(0, 0, 100, 10);
        let mut buf = Buffer::empty(buf_area);
        let screen = AuthScreen::new("Google Drive", status);
        (&screen).render(buf_area, &mut buf);

        let text = rendered_text(&buf, buf_area);

        assert!(text.contains("Scan this QR code:"));
        assert!(text.contains(QR_HIDDEN_HINT));
        assert!(!contains_qr_art(&text));
    }
}
