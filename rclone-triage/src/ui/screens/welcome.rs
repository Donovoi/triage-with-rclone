//! Welcome screen

use ratatui::buffer::Buffer;
use ratatui::layout::{Alignment, Rect};
use ratatui::style::{Color, Modifier, Style};
use ratatui::text::{Line, Span, Text};
use ratatui::widgets::{Paragraph, Widget};

pub struct WelcomeScreen;

const BANNER: &[&str] = &[
    r"        _                         _        _                  ",
    r"  _ __ | | ___ _ __   ___       | |_ _ __(_) __ _  __ _  ___ ",
    r" | '__|| |/ __| | _ \ / _ \ ___ | __| '__| |/ _` |/ _` |/ _ \",
    r" | |   | | (__| | | || (_) |___|| |_| |  | | (_| | (_| |  __/",
    r" |_|   |_|\___|_|_| | \___/      \__|_|  |_|\__,_|\__, |\___|",
    r"                    |_|                            |___/      ",
];

impl Widget for WelcomeScreen {
    fn render(self, area: Rect, buf: &mut Buffer) {
        let banner_style = Style::default()
            .fg(Color::Cyan)
            .add_modifier(Modifier::BOLD);
        let subtitle_style = Style::default()
            .fg(Color::White)
            .add_modifier(Modifier::BOLD);
        let hint_style = Style::default().fg(Color::DarkGray);
        let version = env!("CARGO_PKG_VERSION");

        let mut lines: Vec<Line<'_>> = Vec::new();

        // Vertical padding to center
        let total_content_height = BANNER.len() + 5; // banner + spacing + subtitle + version + hint
        let pad_top = area.height.saturating_sub(total_content_height as u16) / 2;
        for _ in 0..pad_top {
            lines.push(Line::from(""));
        }

        for row in BANNER {
            lines.push(Line::from(Span::styled(*row, banner_style)));
        }

        lines.push(Line::from(""));
        lines.push(Line::from(Span::styled(
            "Forensic Cloud Triage Tool",
            subtitle_style,
        )));
        lines.push(Line::from(Span::styled(
            format!("v{}", version),
            hint_style,
        )));
        lines.push(Line::from(""));
        lines.push(Line::from(Span::styled(
            "Press Enter to start",
            hint_style,
        )));

        let text = Text::from(lines);
        let paragraph = Paragraph::new(text).alignment(Alignment::Center);
        paragraph.render(area, buf);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ratatui::buffer::Buffer;

    #[test]
    fn test_render() {
        let mut buf = Buffer::empty(Rect::new(0, 0, 80, 20));
        WelcomeScreen.render(Rect::new(0, 0, 80, 20), &mut buf);
    }

    #[test]
    fn test_banner_lines_consistent_width() {
        let max_width = BANNER.iter().map(|l| l.len()).max().unwrap_or(0);
        for line in BANNER {
            assert!(
                line.len() <= max_width + 2,
                "banner line too wide: {:?}",
                line
            );
        }
    }
}
