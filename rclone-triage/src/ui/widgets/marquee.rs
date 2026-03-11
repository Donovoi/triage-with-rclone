//! Wrapping helpers for long UI lines.

use std::collections::VecDeque;

use ratatui::style::Style;
use ratatui::text::{Line, Span};
use unicode_width::{UnicodeWidthChar, UnicodeWidthStr};

#[derive(Debug, Clone)]
pub struct MarqueeSegment {
    pub text: String,
    pub style: Style,
}

impl MarqueeSegment {
    pub fn new(text: impl Into<String>, style: Style) -> Self {
        Self {
            text: text.into(),
            style,
        }
    }
}

pub fn line_width(line: &Line<'_>) -> usize {
    line.spans
        .iter()
        .map(|span| UnicodeWidthStr::width(span.content.as_ref()))
        .sum()
}

pub fn text_width(text: &str) -> usize {
    UnicodeWidthStr::width(text)
}

pub fn marquee_text_line(
    text: impl Into<String>,
    style: Style,
    _available_width: u16,
    _frame: u64,
) -> Line<'static> {
    Line::from(Span::styled(text.into(), style))
}

pub fn marquee_line(
    prefix: Vec<Span<'static>>,
    content: Vec<MarqueeSegment>,
    _available_width: u16,
    _frame: u64,
) -> Line<'static> {
    let mut spans = prefix;
    spans.extend(
        content
            .into_iter()
            .map(|segment| Span::styled(segment.text, segment.style)),
    );
    Line::from(spans)
}

pub fn wrap_text_lines(
    text: impl Into<String>,
    style: Style,
    available_width: u16,
) -> Vec<Line<'static>> {
    wrap_line(
        Vec::new(),
        vec![MarqueeSegment::new(text, style)],
        available_width,
    )
}

pub fn wrap_line(
    prefix: Vec<Span<'static>>,
    content: Vec<MarqueeSegment>,
    available_width: u16,
) -> Vec<Line<'static>> {
    let available_width = available_width as usize;
    if available_width == 0 {
        return Vec::new();
    }

    let prefix_width: usize = prefix
        .iter()
        .map(|span| UnicodeWidthStr::width(span.content.as_ref()))
        .sum();

    if prefix.is_empty() || prefix_width >= available_width {
        let mut tokens = tokenize_spans(prefix);
        tokens.extend(tokenize_segments(content));
        return wrap_tokens(tokens, available_width, Vec::new(), 0, 0);
    }

    wrap_tokens(
        tokenize_segments(content),
        available_width,
        prefix,
        prefix_width,
        prefix_width,
    )
}

#[derive(Debug, Clone)]
struct StyledToken {
    text: String,
    style: Style,
    is_whitespace: bool,
}

fn tokenize_spans(spans: Vec<Span<'static>>) -> VecDeque<StyledToken> {
    spans
        .into_iter()
        .flat_map(|span| tokenize_text(span.content.as_ref(), span.style))
        .collect()
}

fn tokenize_segments(segments: Vec<MarqueeSegment>) -> VecDeque<StyledToken> {
    segments
        .into_iter()
        .flat_map(|segment| tokenize_text(&segment.text, segment.style))
        .collect()
}

fn tokenize_text(text: &str, style: Style) -> Vec<StyledToken> {
    let mut tokens = Vec::new();
    let mut current = String::new();
    let mut current_is_whitespace = None;

    for ch in text.chars() {
        let is_whitespace = ch.is_whitespace();

        if current_is_whitespace == Some(is_whitespace) {
            current.push(ch);
            continue;
        }

        if !current.is_empty() {
            tokens.push(StyledToken {
                text: std::mem::take(&mut current),
                style,
                is_whitespace: current_is_whitespace.unwrap_or(false),
            });
        }

        current.push(ch);
        current_is_whitespace = Some(is_whitespace);
    }

    if !current.is_empty() {
        tokens.push(StyledToken {
            text: current,
            style,
            is_whitespace: current_is_whitespace.unwrap_or(false),
        });
    }

    tokens
}

fn wrap_tokens(
    mut tokens: VecDeque<StyledToken>,
    available_width: usize,
    mut current_spans: Vec<Span<'static>>,
    mut current_width: usize,
    continuation_indent_width: usize,
) -> Vec<Line<'static>> {
    let continuation_indent = if continuation_indent_width > 0 {
        Some(" ".repeat(continuation_indent_width))
    } else {
        None
    };
    let mut lines = Vec::new();
    let mut line_has_text = false;

    while let Some(mut token) = tokens.pop_front() {
        if token.text.is_empty() {
            continue;
        }

        if token.is_whitespace {
            if !line_has_text {
                continue;
            }

            let width = text_width(&token.text);
            if current_width + width <= available_width {
                current_width += width;
                current_spans.push(Span::styled(token.text, token.style));
            } else {
                push_line(&mut lines, &mut current_spans);
                start_new_line(
                    &mut current_spans,
                    &mut current_width,
                    continuation_indent.as_deref(),
                );
                line_has_text = false;
            }

            continue;
        }

        loop {
            let remaining_width = available_width.saturating_sub(current_width);
            let token_width = text_width(&token.text);

            if token_width <= remaining_width {
                current_width += token_width;
                current_spans.push(Span::styled(token.text, token.style));
                line_has_text = true;
                break;
            }

            if line_has_text {
                push_line(&mut lines, &mut current_spans);
                start_new_line(
                    &mut current_spans,
                    &mut current_width,
                    continuation_indent.as_deref(),
                );
                line_has_text = false;
                continue;
            }

            if remaining_width == 0 {
                push_line(&mut lines, &mut current_spans);
                start_new_line(
                    &mut current_spans,
                    &mut current_width,
                    continuation_indent.as_deref(),
                );
                continue;
            }

            let (head, tail) = split_text_to_width(&token.text, remaining_width);
            current_width += text_width(&head);
            current_spans.push(Span::styled(head, token.style));
            line_has_text = true;

            if tail.is_empty() {
                break;
            }

            token.text = tail;
            push_line(&mut lines, &mut current_spans);
            start_new_line(
                &mut current_spans,
                &mut current_width,
                continuation_indent.as_deref(),
            );
            line_has_text = false;
        }
    }

    if has_non_space_content(&current_spans) {
        lines.push(Line::from(current_spans));
    }

    if lines.is_empty() {
        vec![Line::default()]
    } else {
        lines
    }
}

fn start_new_line(
    current_spans: &mut Vec<Span<'static>>,
    current_width: &mut usize,
    continuation_indent: Option<&str>,
) {
    current_spans.clear();

    if let Some(indent) = continuation_indent {
        *current_width = text_width(indent);
        current_spans.push(Span::raw(indent.to_string()));
    } else {
        *current_width = 0;
    }
}

fn push_line(lines: &mut Vec<Line<'static>>, current_spans: &mut Vec<Span<'static>>) {
    if has_non_space_content(current_spans) {
        lines.push(Line::from(std::mem::take(current_spans)));
    } else {
        current_spans.clear();
    }
}

fn has_non_space_content(spans: &[Span<'static>]) -> bool {
    spans
        .iter()
        .any(|span| span.content.chars().any(|ch| !ch.is_whitespace()))
}

fn split_text_to_width(text: &str, max_width: usize) -> (String, String) {
    if max_width == 0 {
        return (String::new(), text.to_string());
    }

    let mut used_width = 0;
    let mut split_idx = 0;

    for (idx, ch) in text.char_indices() {
        let width = UnicodeWidthChar::width(ch).unwrap_or(0);

        if width == 0 {
            split_idx = idx + ch.len_utf8();
            continue;
        }

        if used_width + width > max_width {
            if split_idx == 0 {
                split_idx = idx + ch.len_utf8();
            }

            return (text[..split_idx].to_string(), text[split_idx..].to_string());
        }

        used_width += width;
        split_idx = idx + ch.len_utf8();
    }

    (text.to_string(), String::new())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn line_text(line: &Line<'_>) -> String {
        line.spans
            .iter()
            .map(|span| span.content.as_ref())
            .collect::<String>()
    }

    #[test]
    fn test_marquee_text_line_keeps_full_text() {
        let line = marquee_text_line("short", Style::default(), 20, 0);
        assert_eq!(line_text(&line), "short");
    }

    #[test]
    fn test_marquee_line_keeps_full_text() {
        let line = marquee_line(
            vec![Span::raw("[x] ")],
            vec![MarqueeSegment::new("abcdefghij", Style::default())],
            8,
            0,
        );

        assert_eq!(line_text(&line), "[x] abcdefghij");
    }

    #[test]
    fn test_wrap_text_lines_wraps_long_text() {
        let lines = wrap_text_lines("abcdefghij", Style::default(), 5);
        let texts = lines.iter().map(line_text).collect::<Vec<_>>();

        assert_eq!(texts, vec!["abcde", "fghij"]);
    }

    #[test]
    fn test_wrap_line_preserves_prefix() {
        let lines = wrap_line(
            vec![Span::raw("[x] ")],
            vec![MarqueeSegment::new("abcdefghij", Style::default())],
            8,
        );
        let texts = lines.iter().map(line_text).collect::<Vec<_>>();

        assert_eq!(texts, vec!["[x] abcd", "    efgh", "    ij"]);
    }
}
