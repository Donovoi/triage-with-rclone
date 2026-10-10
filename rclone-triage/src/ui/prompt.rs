//! Prompt helpers for collecting text input inside the TUI.

use anyhow::Result;
use crossterm::event::{self, Event, KeyCode, KeyEventKind, KeyModifiers};
use ratatui::layout::Rect;
use ratatui::widgets::{Block, Borders, Clear, Paragraph, Wrap};
use ratatui::{Frame, Terminal};
use std::time::Duration;

use crate::ui::{layout::centered_rect, render::render_state, App};

#[derive(Debug, PartialEq, Eq)]
enum PromptAction {
    Continue,
    Ignored,
    Submit,
    Cancel,
    Shutdown,
}

fn append_paste(input: &mut String, text: &str) {
    input.extend(text.chars().filter_map(|c| match c {
        '\r' | '\n' | '\t' => Some(' '),
        c if c.is_control() => None,
        c => Some(c),
    }));
}

fn handle_prompt_event(
    input: &mut String,
    event: Event,
    read_clipboard: impl FnOnce() -> Result<String>,
) -> Result<PromptAction> {
    match event {
        Event::Paste(text) => append_paste(input, &text),
        Event::Key(key) if key.kind == KeyEventKind::Press => {
            let control = key.modifiers.contains(KeyModifiers::CONTROL);
            let alt = key.modifiers.contains(KeyModifiers::ALT);
            match key.code {
                KeyCode::Char('v' | 'V') if control && !alt => {
                    append_paste(input, &read_clipboard()?);
                }
                KeyCode::Insert if key.modifiers == KeyModifiers::SHIFT => {
                    append_paste(input, &read_clipboard()?);
                }
                KeyCode::Char('c' | 'C') if control && !alt => {
                    return Ok(PromptAction::Shutdown);
                }
                KeyCode::Esc => return Ok(PromptAction::Cancel),
                KeyCode::Enter => return Ok(PromptAction::Submit),
                KeyCode::Backspace => {
                    input.pop();
                }
                KeyCode::Char('u' | 'U') if control && !alt => input.clear(),
                KeyCode::Char('w' | 'W') if control && !alt => {
                    while matches!(input.chars().last(), Some(c) if c.is_whitespace()) {
                        input.pop();
                    }
                    while matches!(input.chars().last(), Some(c) if !c.is_whitespace()) {
                        input.pop();
                    }
                }
                KeyCode::Char(c)
                    if ((!control && !alt) || (control && alt && !c.is_ascii()))
                        && !c.is_control() =>
                {
                    input.push(c)
                }
                _ => return Ok(PromptAction::Ignored),
            }
        }
        _ => return Ok(PromptAction::Ignored),
    }
    Ok(PromptAction::Continue)
}

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
    let mut paste_failed = false;

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

            let paste_help = if paste_failed {
                "Paste unavailable. Copy text again or use your terminal's Paste command."
            } else if cfg!(windows) {
                "Ctrl+V / Shift+Insert paste | Ctrl+U clear | Ctrl+W delete word"
            } else {
                "Use terminal Paste | Ctrl+U clear | Ctrl+W delete word"
            };
            let content = format!(
                "{}\n\n{}\n> {}\nLen: {} char(s)",
                hint, paste_help, display, total_chars
            );
            render_prompt_overlay(f, overlay, title, &content);
        })?;

        if !event::poll(Duration::from_millis(200))? {
            continue;
        }

        match handle_prompt_event(&mut input, event::read()?, super::clipboard::read_text) {
            Ok(PromptAction::Continue) => paste_failed = false,
            Ok(PromptAction::Ignored) => {}
            Ok(PromptAction::Submit) => return Ok(Some(input.trim().to_string())),
            Ok(PromptAction::Cancel) => return Ok(None),
            Ok(PromptAction::Shutdown) => {
                app.shutdown
                    .store(true, std::sync::atomic::Ordering::Relaxed);
                return Ok(None);
            }
            Err(_) => paste_failed = true,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crossterm::event::KeyEvent;
    use ratatui::backend::TestBackend;
    use ratatui::style::{Color, Modifier, Style};
    use ratatui::text::Line;

    #[test]
    fn paste_shortcuts_append_clipboard_text_without_submitting() {
        for (code, modifiers) in [
            (KeyCode::Char('v'), KeyModifiers::CONTROL),
            (
                KeyCode::Char('V'),
                KeyModifiers::CONTROL | KeyModifiers::SHIFT,
            ),
            (KeyCode::Insert, KeyModifiers::SHIFT),
        ] {
            let mut input = "prefix:".to_string();
            let mut reads = 0;
            let action = handle_prompt_event(
                &mut input,
                Event::Key(KeyEvent::new(code, modifiers)),
                || {
                    reads += 1;
                    Ok("synthetic-client-🦀\r\n\t\0\u{1b}".into())
                },
            )
            .unwrap();
            assert_eq!(action, PromptAction::Continue);
            assert_eq!(input, "prefix:synthetic-client-🦀   ");
            assert_eq!(reads, 1);
        }
    }

    #[test]
    fn failed_clipboard_read_preserves_the_entire_input() {
        let mut input = "keep-this".to_string();
        let result = handle_prompt_event(
            &mut input,
            Event::Key(KeyEvent::new(KeyCode::Char('v'), KeyModifiers::CONTROL)),
            || anyhow::bail!("synthetic clipboard failure"),
        );
        assert!(result.is_err());
        assert_eq!(input, "keep-this");
    }

    #[test]
    fn bracketed_paste_does_not_read_the_system_clipboard_or_submit_newlines() {
        let mut input = String::new();
        let action = handle_prompt_event(
            &mut input,
            Event::Paste("hello\nworld\u{1b}".into()),
            || panic!("Terminal paste must not read the system clipboard"),
        )
        .unwrap();
        assert_eq!(action, PromptAction::Continue);
        assert_eq!(input, "hello world");
    }

    #[test]
    fn paste_release_and_repeat_events_do_not_duplicate_credentials() {
        for kind in [KeyEventKind::Release, KeyEventKind::Repeat] {
            let mut key = KeyEvent::new(KeyCode::Char('v'), KeyModifiers::CONTROL);
            key.kind = kind;
            let mut input = "existing".to_string();
            assert_eq!(
                handle_prompt_event(&mut input, Event::Key(key), || {
                    panic!("Only an explicit key press may read the clipboard")
                })
                .unwrap(),
                PromptAction::Ignored
            );
            assert_eq!(input, "existing");
        }
    }

    #[test]
    fn typing_and_editing_shortcuts_never_read_the_clipboard() {
        let mut input = "first word".to_string();
        for (code, modifiers, expected) in [
            (KeyCode::Char('w'), KeyModifiers::CONTROL, "first "),
            (KeyCode::Char('v'), KeyModifiers::NONE, "first v"),
            (
                KeyCode::Char('é'),
                KeyModifiers::CONTROL | KeyModifiers::ALT,
                "first vé",
            ),
            (KeyCode::Backspace, KeyModifiers::NONE, "first v"),
            (KeyCode::Char('u'), KeyModifiers::CONTROL, ""),
            (KeyCode::Char('a'), KeyModifiers::CONTROL, ""),
        ] {
            handle_prompt_event(
                &mut input,
                Event::Key(KeyEvent::new(code, modifiers)),
                || panic!("Typing and editing must not read the clipboard"),
            )
            .unwrap();
            assert_eq!(input, expected);
        }
    }

    #[test]
    fn submit_cancel_and_shutdown_keep_their_existing_meaning() {
        for (code, modifiers, expected) in [
            (KeyCode::Enter, KeyModifiers::NONE, PromptAction::Submit),
            (KeyCode::Esc, KeyModifiers::NONE, PromptAction::Cancel),
            (
                KeyCode::Char('c'),
                KeyModifiers::CONTROL,
                PromptAction::Shutdown,
            ),
        ] {
            let mut input = "value".to_string();
            assert_eq!(
                handle_prompt_event(
                    &mut input,
                    Event::Key(KeyEvent::new(code, modifiers)),
                    || { panic!("Submit and cancel must not read the clipboard") }
                )
                .unwrap(),
                expected
            );
            assert_eq!(input, "value");
        }
    }

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
