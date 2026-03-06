//! Listing-in-progress screen

use ratatui::buffer::Buffer;
use ratatui::layout::{Constraint, Direction, Layout, Rect};
use ratatui::style::{Color, Modifier, Style};
use ratatui::text::{Line, Span};
use ratatui::widgets::{Block, Borders, Gauge, Paragraph, Widget, Wrap};

pub struct ListingScreen {
    pub remote_name: String,
    pub count: usize,
    pub elapsed_secs: u64,
    pub status: String,
}

impl ListingScreen {
    pub fn new(remote_name: String, count: usize, elapsed_secs: u64, status: String) -> Self {
        Self {
            remote_name,
            count,
            elapsed_secs,
            status,
        }
    }
}

impl Widget for &ListingScreen {
    fn render(self, area: Rect, buf: &mut Buffer) {
        let chunks = Layout::default()
            .direction(Direction::Vertical)
            .constraints([
                Constraint::Length(3),
                Constraint::Length(3),
                Constraint::Min(3),
            ])
            .split(area);

        // Title with remote name
        let title_text = format!("Listing files from: {}", self.remote_name);
        let title = Paragraph::new(Line::from(Span::styled(
            title_text,
            Style::default()
                .fg(Color::White)
                .add_modifier(Modifier::BOLD),
        )))
        .block(Block::default().borders(Borders::ALL).title("File Listing"));
        title.render(chunks[0], buf);

        // Progress gauge (indeterminate — just show count)
        let elapsed = format_elapsed(self.elapsed_secs);
        let label = format!("{} files found  ({})", self.count, elapsed);
        let gauge = Gauge::default()
            .block(Block::default().borders(Borders::ALL).title("Progress"))
            .gauge_style(Style::default().fg(Color::LightCyan).bg(Color::DarkGray))
            .label(label)
            .ratio(pulse_ratio(self.elapsed_secs));
        gauge.render(chunks[1], buf);

        // Status / instructions
        let mut lines = Vec::new();
        if !self.status.is_empty() {
            lines.push(Line::from(Span::styled(
                &*self.status,
                Style::default().fg(Color::LightYellow),
            )));
            lines.push(Line::from(""));
        }
        lines.push(Line::from(Span::styled(
            "rclone is scanning the remote recursively...",
            Style::default().fg(Color::Gray),
        )));
        lines.push(Line::from(""));
        lines.push(Line::from(Span::styled(
            "Press Esc to cancel and return to config browser.",
            Style::default().fg(Color::LightGreen),
        )));

        let body = Paragraph::new(lines)
            .block(Block::default().borders(Borders::ALL).title("Status"))
            .wrap(Wrap { trim: true });
        body.render(chunks[2], buf);
    }
}

fn format_elapsed(secs: u64) -> String {
    if secs < 60 {
        format!("{}s", secs)
    } else {
        format!("{}m {}s", secs / 60, secs % 60)
    }
}

/// Return a pulsing ratio (0.0–1.0) based on elapsed seconds to animate the gauge.
fn pulse_ratio(secs: u64) -> f64 {
    // Oscillate between 0.1 and 0.9 on a ~4-second cycle
    let phase = (secs % 4) as f64 / 4.0;
    0.1 + 0.8 * (std::f64::consts::PI * phase).sin().abs()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_render_listing_screen() {
        let mut buf = Buffer::empty(Rect::new(0, 0, 80, 20));
        let screen = ListingScreen::new("gdrive".to_string(), 1234, 45, String::new());
        (&screen).render(Rect::new(0, 0, 80, 20), &mut buf);
    }

    #[test]
    fn test_format_elapsed() {
        assert_eq!(format_elapsed(0), "0s");
        assert_eq!(format_elapsed(59), "59s");
        assert_eq!(format_elapsed(60), "1m 0s");
        assert_eq!(format_elapsed(125), "2m 5s");
    }

    #[test]
    fn test_pulse_ratio_bounds() {
        for secs in 0..20 {
            let r = pulse_ratio(secs);
            assert!(
                (0.0..=1.0).contains(&r),
                "pulse_ratio({}) = {} out of range",
                secs,
                r
            );
        }
    }
}
