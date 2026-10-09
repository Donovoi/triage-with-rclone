//! Prompt helpers for collecting text input inside the TUI.

use anyhow::Result;
use crossterm::event::{self, Event, KeyCode, KeyEventKind};
use ratatui::layout::Rect;
use ratatui::widgets::{Block, Borders, Clear, Paragraph, Wrap};
use ratatui::{Frame, Terminal};
use std::time::Duration;

use crate::ui::{layout::centered_rect, render::render_state, App};

fn render_prompt_overlay(frame: &mut Frame, overlay: Rect, title: &str, content: &str) {
    // Paragraph only overwrites its text; erase the underlying screen inside
    // the modal so short and empty lines cannot retain background content.
    frame.render_widget(Clear, overlay);
    let modal = Paragraph::new(content)
        .block(Block::default().title(title).borders(Borders::ALL))
        .wrap(Wrap { trim: false });
    frame.render_widget(modal, overlay);
}

/// Prompt for a single line of input without leaving the TUI.
///
/// Returns `Ok(None)` if the user cancels with Esc.
pub(crate) fn prompt_text_in_tui<
    B: ratatui::backend::Backend<Error: std::error::Error + Send + Sync + 'static>,
>(
    app: &mut App,
    terminal: &mut Terminal<B>,
    title: &str,
    hint: &str,
) -> Result<Option<String>> {
    let mut input = String::new();

    loop {
        if app.shutdown.load(std::sync::atomic::Ordering::Relaxed) {
            return Ok(None);
        }
        terminal.draw(|f| {
            render_state(f, app);

            let area = f.area();
            let overlay = centered_rect(80, 40, area);
            let max_display_chars = 512usize;
            let total_chars = input.chars().count();
            let display = if input.is_empty() {
                "<empty>".to_string()
            } else if total_chars <= max_display_chars {
                input.clone()
            } else {
                let tail: String = input
                    .chars()
                    .rev()
                    .take(max_display_chars)
                    .collect::<Vec<_>>()
                    .into_iter()
                    .rev()
                    .collect();
                format!("...{}", tail)
            };

            let content = format!(
                "{}\n\n> {}\n\nLen: {} char(s)\n\nEnter submit | Esc cancel | Backspace delete | Ctrl+U clear | Ctrl+W delete word",
                hint, display, total_chars
            );
            render_prompt_overlay(f, overlay, title, &content);
        })?;

        if !event::poll(Duration::from_millis(200))? {
            continue;
        }

        match event::read()? {
            Event::Key(key) => {
                if !matches!(key.kind, KeyEventKind::Press) {
                    continue;
                }
                match key.code {
                    KeyCode::Char('c')
                        if key
                            .modifiers
                            .contains(crossterm::event::KeyModifiers::CONTROL) =>
                    {
                        app.shutdown
                            .store(true, std::sync::atomic::Ordering::Relaxed);
                        return Ok(None);
                    }
                    KeyCode::Esc => return Ok(None),
                    KeyCode::Enter => return Ok(Some(input.trim().to_string())),
                    KeyCode::Backspace => {
                        input.pop();
                    }
                    KeyCode::Char('u')
                        if key
                            .modifiers
                            .contains(crossterm::event::KeyModifiers::CONTROL) =>
                    {
                        input.clear();
                    }
                    KeyCode::Char('w')
                        if key
                            .modifiers
                            .contains(crossterm::event::KeyModifiers::CONTROL) =>
                    {
                        // Delete the last "word" (simple ASCII whitespace heuristic).
                        while matches!(input.chars().last(), Some(c) if c.is_whitespace()) {
                            input.pop();
                        }
                        while matches!(input.chars().last(), Some(c) if !c.is_whitespace()) {
                            input.pop();
                        }
                    }
                    KeyCode::Char(c) => {
                        input.push(c);
                    }
                    _ => {}
                }
            }
            Event::Paste(paste) => {
                // Normalize newlines: this is a single-line prompt (callers can split on whitespace).
                for c in paste.chars() {
                    match c {
                        '\r' | '\n' => input.push(' '),
                        _ => input.push(c),
                    }
                }
            }
            _ => {}
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ratatui::backend::TestBackend;
    use ratatui::style::{Color, Modifier, Style};
    use ratatui::text::Line;

    #[test]
    fn prompt_clears_background_cells_and_styles_only_inside_overlay() {
        let mut terminal = Terminal::new(TestBackend::new(120, 34)).unwrap();
        let background_style = Style::default()
            .fg(Color::Red)
            .bg(Color::Blue)
            .add_modifier(Modifier::BOLD);
        let content = "Enter remote name.\n\nDefault: http\n\nEnter submit | Esc cancel\n\n> <empty>\n\nLen: 0 char(s)\n\nEnter submit | Esc cancel | Backspace delete | Ctrl+U clear | Ctrl+W delete word";
        terminal
            .draw(|frame| {
                let background =
                    Paragraph::new(vec![Line::from("x".repeat(120)); 34]).style(background_style);
                frame.render_widget(background, frame.area());
                let overlay = centered_rect(80, 40, frame.area());
                assert_eq!(overlay, Rect::new(12, 10, 96, 14));
                render_prompt_overlay(frame, overlay, "Remote Name", content);
            })
            .unwrap();

        let buffer = terminal.backend().buffer();
        let expected_lines = [
            "Enter remote name.",
            "",
            "Default: http",
            "",
            "Enter submit | Esc cancel",
            "",
            "> <empty>",
            "",
            "Len: 0 char(s)",
            "",
            "Enter submit | Esc cancel | Backspace delete | Ctrl+U clear | Ctrl+W delete word",
            "",
        ];
        for (row, expected) in expected_lines.into_iter().enumerate() {
            let actual: String = (13..107)
                .map(|x| buffer[(x, 11 + row as u16)].symbol())
                .collect();
            assert_eq!(actual, format!("{expected:<94}"));
        }
        for y in 0..34 {
            for x in 0..120 {
                let cell = &buffer[(x, y)];
                if (12..108).contains(&x) && (10..24).contains(&y) {
                    assert_eq!(cell.fg, Color::Reset);
                    assert_eq!(cell.bg, Color::Reset);
                    assert_eq!(cell.modifier, Modifier::empty());
                } else {
                    assert_eq!(cell.symbol(), "x");
                    assert_eq!(cell.fg, Color::Red);
                    assert_eq!(cell.bg, Color::Blue);
                    assert_eq!(cell.modifier, Modifier::BOLD);
                }
            }
        }
    }
}
