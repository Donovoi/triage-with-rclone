use ratatui::layout::Rect;
use ratatui::text::{Line, Span};
use ratatui::widgets::{Block, Borders, Paragraph, Wrap};
use ratatui::Frame;

#[derive(Debug, Clone)]
pub struct ModeConfirmScreen {
    pub title: String,
    pub description: String,
    pub note: String,
}

impl ModeConfirmScreen {
    pub fn new(title: String, description: String) -> Self {
        Self {
            title,
            description,
            note: "Press Enter to continue or Backspace to go back.".to_string(),
        }
    }

    pub fn render(&self, frame: &mut Frame, area: Rect) {
        let block = Block::default().title("Mode Confirmation").borders(Borders::ALL);
        let lines = vec![
            Line::from(vec![Span::styled("Selected mode: ", ratatui::style::Style::default())]),
            Line::from(self.title.as_str()),
            Line::from(""),
            Line::from(self.description.as_str()),
            Line::from(""),
            Line::from(self.note.as_str()),
        ];
        let paragraph = Paragraph::new(lines)
            .block(block)
            .wrap(Wrap { trim: true });
        frame.render_widget(paragraph, area);
    }
}

