//! Shared TUI theme and light animation helpers.

use ratatui::style::{Color, Modifier, Style};
use ratatui::text::{Line, Span};
use ratatui::widgets::{Block, Borders};

pub fn surface_bg() -> Color {
    Color::Rgb(14, 18, 28)
}

pub fn panel_bg() -> Color {
    Color::Rgb(21, 28, 43)
}

pub fn selection_bg() -> Color {
    Color::Rgb(42, 55, 84)
}

pub fn text_primary() -> Color {
    Color::Rgb(236, 241, 255)
}

pub fn text_muted() -> Color {
    Color::Rgb(142, 156, 196)
}

pub fn accent_cyan() -> Color {
    Color::Rgb(88, 214, 255)
}

pub fn accent_blue() -> Color {
    Color::Rgb(122, 162, 255)
}

pub fn accent_green() -> Color {
    Color::Rgb(111, 230, 171)
}

pub fn accent_yellow() -> Color {
    Color::Rgb(255, 218, 103)
}

pub fn accent_pink() -> Color {
    Color::Rgb(255, 121, 198)
}

pub fn accent_red() -> Color {
    Color::Rgb(255, 122, 122)
}

pub fn panel_border_style() -> Style {
    Style::default().fg(accent_cyan())
}

pub fn panel_title_style() -> Style {
    Style::default()
        .fg(accent_pink())
        .add_modifier(Modifier::BOLD)
}

pub fn panel_block(title: impl Into<String>) -> Block<'static> {
    Block::default()
        .title(Line::from(Span::styled(title.into(), panel_title_style())))
        .borders(Borders::ALL)
        .border_style(panel_border_style())
}

pub fn list_style() -> Style {
    Style::default().fg(text_primary()).bg(panel_bg())
}

pub fn list_highlight_style() -> Style {
    Style::default()
        .fg(Color::White)
        .bg(selection_bg())
        .add_modifier(Modifier::BOLD)
}

pub fn strong_style() -> Style {
    Style::default()
        .fg(text_primary())
        .add_modifier(Modifier::BOLD)
}

pub fn muted_style() -> Style {
    Style::default().fg(text_muted())
}

pub fn info_style() -> Style {
    Style::default().fg(accent_blue())
}

pub fn success_style() -> Style {
    Style::default().fg(accent_green())
}

pub fn warning_style() -> Style {
    Style::default()
        .fg(accent_yellow())
        .add_modifier(Modifier::BOLD)
}

pub fn error_style() -> Style {
    Style::default()
        .fg(accent_red())
        .add_modifier(Modifier::BOLD)
}

pub fn hint_style() -> Style {
    Style::default()
        .fg(accent_green())
        .add_modifier(Modifier::BOLD)
}

pub fn progress_style() -> Style {
    Style::default().fg(accent_green()).bg(selection_bg())
}

pub fn menu_badge_style(tag: &str) -> Style {
    let color = match tag {
        "AUTH" => accent_blue(),
        "LIST" => accent_cyan(),
        "XFER" => accent_green(),
        "MOUNT" => accent_yellow(),
        "SSO" => accent_pink(),
        "MOB" => accent_green(),
        "TOOLS" => accent_pink(),
        "EXIT" => accent_red(),
        _ => accent_blue(),
    };

    Style::default().fg(color).add_modifier(Modifier::BOLD)
}

pub fn list_highlight_symbol(frame: u64) -> &'static str {
    match (frame / 2) % 4 {
        0 => "> ",
        1 => "» ",
        2 => "▸ ",
        _ => "▶ ",
    }
}

pub fn banner_activity(frame: u64) -> &'static str {
    const FRAMES: [&str; 8] = [
        "[·    ]",
        "[··   ]",
        "[···  ]",
        "[ ··· ]",
        "[  ···]",
        "[   ··]",
        "[    ·]",
        "[   ··]",
    ];

    FRAMES[frame as usize % FRAMES.len()]
}

pub fn footer_spinner(frame: u64) -> &'static str {
    const FRAMES: [&str; 4] = ["-", "\\", "|", "/"];
    FRAMES[frame as usize % FRAMES.len()]
}
