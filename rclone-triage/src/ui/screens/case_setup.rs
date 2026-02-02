//! Session setup screen

use ratatui::buffer::Buffer;
use ratatui::layout::Rect;
use ratatui::widgets::Widget;

use crate::ui::widgets::SessionInputForm;

pub struct CaseSetupScreen {
    pub form: SessionInputForm,
}

impl CaseSetupScreen {
    pub fn new() -> Self {
        Self {
            form: SessionInputForm::new(),
        }
    }
}

impl Widget for &CaseSetupScreen {
    fn render(self, area: Rect, buf: &mut Buffer) {
        (&self.form).render(area, buf);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ratatui::buffer::Buffer;

    #[test]
    fn test_render() {
        let mut buf = Buffer::empty(Rect::new(0, 0, 60, 10));
        let screen = CaseSetupScreen::new();
        (&screen).render(Rect::new(0, 0, 60, 10), &mut buf);
    }
}
