//! Session input form widget

use ratatui::buffer::Buffer;
use ratatui::layout::Rect;
use ratatui::style::{Modifier, Style};
use ratatui::text::Line;
use ratatui::widgets::{Block, Borders, Paragraph, Widget};

/// Session input form widget
#[derive(Debug, Clone)]
pub struct SessionInputForm {
    pub session_name: String,
}

impl SessionInputForm {
    pub fn new() -> Self {
        Self {
            session_name: String::new(),
        }
    }

    pub fn set_session_name(&mut self, value: impl Into<String>) {
        self.session_name = value.into();
    }
}

impl Widget for &SessionInputForm {
    fn render(self, area: Rect, buf: &mut Buffer) {
        let block = Block::default()
            .title("Session Setup")
            .borders(Borders::ALL);
        let inner = block.inner(area);
        block.render(area, buf);

        let display_name = if self.session_name.is_empty() {
            "(leave blank for auto-generated name)".to_string()
        } else {
            self.session_name.clone()
        };

        let para = Paragraph::new(Line::from(format!("Session Name: {}", display_name)))
            .style(Style::default().add_modifier(Modifier::BOLD))
            .block(Block::default().borders(Borders::ALL));

        para.render(inner, buf);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ratatui::buffer::Buffer;

    #[test]
    fn test_session_input_render() {
        let mut buf = Buffer::empty(Rect::new(0, 0, 50, 10));
        let mut form = SessionInputForm::new();
        form.set_session_name("my-session");

        (&form).render(Rect::new(0, 0, 50, 10), &mut buf);
    }
}
