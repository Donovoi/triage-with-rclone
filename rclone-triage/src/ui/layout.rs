//! UI layout helpers

use ratatui::layout::{Constraint, Direction, Layout, Rect};

/// Layout regions used by the application
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct AppLayout {
    pub header: Rect,
    pub sidebar: Rect,
    pub main: Rect,
    pub footer: Rect,
}

/// Build the standard application layout
pub fn build_layout(area: Rect) -> AppLayout {
    let vertical = Layout::default()
        .direction(Direction::Vertical)
        .constraints([
            Constraint::Length(3),
            Constraint::Min(0),
            Constraint::Length(2),
        ])
        .split(area);

    let body = vertical[1];

    let horizontal = Layout::default()
        .direction(Direction::Horizontal)
        .constraints([Constraint::Percentage(30), Constraint::Percentage(70)])
        .split(body);

    AppLayout {
        header: vertical[0],
        sidebar: horizontal[0],
        main: horizontal[1],
        footer: vertical[2],
    }
}

/// Return a centered rectangle within `area` at the given percentage size.
pub(crate) fn centered_rect(percent_x: u16, percent_y: u16, area: Rect) -> Rect {
    let popup_layout = Layout::default()
        .direction(Direction::Vertical)
        .constraints([
            Constraint::Percentage((100 - percent_y) / 2),
            Constraint::Percentage(percent_y),
            Constraint::Percentage((100 - percent_y) / 2),
        ])
        .split(area);

    let vertical = popup_layout[1];
    let horizontal_layout = Layout::default()
        .direction(Direction::Horizontal)
        .constraints([
            Constraint::Percentage((100 - percent_x) / 2),
            Constraint::Percentage(percent_x),
            Constraint::Percentage((100 - percent_x) / 2),
        ])
        .split(vertical);

    horizontal_layout[1]
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_layout_dimensions() {
        let area = Rect::new(0, 0, 80, 24);
        let layout = build_layout(area);

        assert_eq!(layout.header.height, 3);
        assert_eq!(layout.footer.height, 2);
        assert_eq!(layout.sidebar.width + layout.main.width, 80);
    }
}
