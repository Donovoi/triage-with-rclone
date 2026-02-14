//! Prompt helpers for collecting text input inside the TUI.

use anyhow::Result;
use crossterm::event::{self, Event, KeyCode, KeyEventKind};
use ratatui::widgets::{Block, Borders, Paragraph, Wrap};
use ratatui::Terminal;
use std::time::Duration;

use crate::ui::{layout::centered_rect, render::render_state, App};

/// Prompt for a single line of input without leaving the TUI.
///
/// Returns `Ok(None)` if the user cancels with Esc.
pub(crate) fn prompt_text_in_tui<B: ratatui::backend::Backend>(
    app: &mut App,
    terminal: &mut Terminal<B>,
    title: &str,
    hint: &str,
) -> Result<Option<String>> {
    let mut input = String::new();

    loop {
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
            let modal = Paragraph::new(content)
                .block(Block::default().title(title).borders(Borders::ALL))
                .wrap(Wrap { trim: false });
            f.render_widget(modal, overlay);
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
                    KeyCode::Esc => return Ok(None),
                    KeyCode::Enter => return Ok(Some(input.trim().to_string())),
                    KeyCode::Backspace => {
                        input.pop();
                    }
                    KeyCode::Char('u')
                        if key.modifiers.contains(crossterm::event::KeyModifiers::CONTROL) =>
                    {
                        input.clear();
                    }
                    KeyCode::Char('w')
                        if key.modifiers.contains(crossterm::event::KeyModifiers::CONTROL) =>
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

