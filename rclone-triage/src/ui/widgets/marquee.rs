//! Helpers for horizontally animating long UI lines.

use ratatui::style::Style;
use ratatui::text::{Line, Span};
use unicode_width::{UnicodeWidthChar, UnicodeWidthStr};

const MARQUEE_STEP_FRAMES: u64 = 2;
const MARQUEE_START_PAUSE_STEPS: u64 = 8;
const MARQUEE_END_PAUSE_STEPS: u64 = 8;

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
    available_width: u16,
    frame: u64,
) -> Line<'static> {
    marquee_line(
        Vec::new(),
        vec![MarqueeSegment::new(text, style)],
        available_width,
        frame,
    )
}

pub fn marquee_line(
    prefix: Vec<Span<'static>>,
    content: Vec<MarqueeSegment>,
    available_width: u16,
    frame: u64,
) -> Line<'static> {
    let available_width = available_width as usize;
    if available_width == 0 {
        return Line::default();
    }

    let prefix_width: usize = prefix
        .iter()
        .map(|span| UnicodeWidthStr::width(span.content.as_ref()))
        .sum();

    if prefix_width >= available_width {
        return Line::from(prefix);
    }

    let content_width: usize = content.iter().map(|segment| text_width(&segment.text)).sum();
    let remaining_width = available_width - prefix_width;

    let mut spans = prefix;
    if content_width <= remaining_width {
        spans.extend(
            content
                .into_iter()
                .map(|segment| Span::styled(segment.text, segment.style)),
        );
        return Line::from(spans);
    }

    let offset = marquee_offset(content_width, remaining_width, frame);
    spans.extend(slice_segments(&content, offset, remaining_width));
    Line::from(spans)
}

fn marquee_offset(content_width: usize, visible_width: usize, frame: u64) -> usize {
    let max_offset = content_width.saturating_sub(visible_width);
    if max_offset == 0 {
        return 0;
    }

    let tick = frame / MARQUEE_STEP_FRAMES;
    let cycle = MARQUEE_START_PAUSE_STEPS + max_offset as u64 + MARQUEE_END_PAUSE_STEPS;
    let phase = tick % cycle;

    if phase < MARQUEE_START_PAUSE_STEPS {
        0
    } else if phase < MARQUEE_START_PAUSE_STEPS + max_offset as u64 {
        (phase - MARQUEE_START_PAUSE_STEPS + 1) as usize
    } else {
        max_offset
    }
}

fn slice_segments(
    segments: &[MarqueeSegment],
    offset: usize,
    visible_width: usize,
) -> Vec<Span<'static>> {
    let mut remaining_offset = offset;
    let mut remaining_width = visible_width;
    let mut result = Vec::new();

    for segment in segments {
        if remaining_width == 0 {
            break;
        }

        let segment_width = text_width(&segment.text);
        if segment_width == 0 {
            continue;
        }
        if remaining_offset >= segment_width {
            remaining_offset -= segment_width;
            continue;
        }

        let visible = slice_text(&segment.text, remaining_offset, remaining_width);
        remaining_offset = 0;
        if !visible.is_empty() {
            remaining_width = remaining_width.saturating_sub(text_width(&visible));
            result.push(Span::styled(visible, segment.style));
        }
    }

    result
}

fn slice_text(text: &str, offset: usize, visible_width: usize) -> String {
    let mut skipped = 0;
    let mut used = 0;
    let mut output = String::new();

    for ch in text.chars() {
        let width = UnicodeWidthChar::width(ch).unwrap_or(0);

        if width == 0 {
            if !output.is_empty() {
                output.push(ch);
            }
            continue;
        }

        if skipped + width <= offset {
            skipped += width;
            continue;
        }

        if used + width > visible_width {
            break;
        }

        output.push(ch);
        used += width;
    }

    output
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_short_text_is_not_marqueed() {
        let line = marquee_text_line("short", Style::default(), 20, 0);
        let text = line
            .spans
            .iter()
            .map(|span| span.content.as_ref())
            .collect::<String>();

        assert_eq!(text, "short");
    }

    #[test]
    fn test_long_text_scrolls_right_to_left() {
        let early = marquee_text_line("abcdefghij", Style::default(), 5, 0);
        let later = marquee_text_line(
            "abcdefghij",
            Style::default(),
            5,
            MARQUEE_STEP_FRAMES * MARQUEE_START_PAUSE_STEPS,
        );

        let early_text = early
            .spans
            .iter()
            .map(|span| span.content.as_ref())
            .collect::<String>();
        let later_text = later
            .spans
            .iter()
            .map(|span| span.content.as_ref())
            .collect::<String>();

        assert_eq!(early_text, "abcde");
        assert_eq!(later_text, "bcdef");
    }

    #[test]
    fn test_marquee_line_preserves_prefix() {
        let line = marquee_line(
            vec![Span::raw("[x] ")],
            vec![MarqueeSegment::new("abcdefghij", Style::default())],
            8,
            MARQUEE_STEP_FRAMES * MARQUEE_START_PAUSE_STEPS,
        );
        let text = line
            .spans
            .iter()
            .map(|span| span.content.as_ref())
            .collect::<String>();

        assert_eq!(text, "[x] bcde");
    }
}
