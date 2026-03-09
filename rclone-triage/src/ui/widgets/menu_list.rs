//! Main menu list widget

use ratatui::buffer::Buffer;
use ratatui::layout::Rect;
use ratatui::text::{Line, Span};
use ratatui::widgets::{Block, Borders, List, ListItem, ListState, StatefulWidget, Widget};

use crate::ui::theme;
use crate::ui::widgets::{marquee_line, marquee_text_line, text_width, MarqueeSegment};

/// Main menu list widget
#[derive(Debug, Clone)]
pub struct MenuList {
    pub items: Vec<String>,
    pub selected: usize,
    pub title: String,
    pub animation_frame: u64,
}

impl MenuList {
    pub fn new(items: Vec<String>) -> Self {
        Self {
            items,
            selected: 0,
            title: "rclone-triage // mission menu".to_string(),
            animation_frame: 0,
        }
    }
}

impl Widget for &MenuList {
    fn render(self, area: Rect, buf: &mut Buffer) {
        let highlight_symbol = theme::list_highlight_symbol(self.animation_frame);
        let highlight_width = text_width(highlight_symbol) as u16;
        let inner_width = area.width.saturating_sub(2);
        let list_items = self
            .items
            .iter()
            .enumerate()
            .map(|(idx, item)| {
                let available_width = inner_width.saturating_sub(if idx == self.selected {
                    highlight_width
                } else {
                    0
                });
                ListItem::new(format_menu_item(item, available_width, self.animation_frame))
            })
            .collect::<Vec<_>>();

        let list = List::new(list_items)
            .block(
                Block::default()
                    .title(Line::from(Span::styled(
                        self.title.clone(),
                        theme::panel_title_style(),
                    )))
                    .borders(Borders::ALL)
                    .border_style(theme::panel_border_style()),
            )
            .style(theme::list_style())
            .highlight_style(theme::list_highlight_style())
            .highlight_symbol(highlight_symbol);

        let mut state = ListState::default();
        if !self.items.is_empty() {
            state.select(Some(self.selected));
        }

        StatefulWidget::render(list, area, buf, &mut state);
    }
}

fn format_menu_item(item: &str, available_width: u16, frame: u64) -> Line<'static> {
    if let Some((tag, label)) = split_tagged_label(item) {
        marquee_line(
            vec![
                Span::styled(format!("[{}]", tag), theme::menu_badge_style(tag)),
                Span::raw(" "),
            ],
            vec![MarqueeSegment::new(label, theme::strong_style())],
            available_width,
            frame,
        )
    } else {
        marquee_text_line(item, theme::strong_style(), available_width, frame)
    }
}

fn split_tagged_label(item: &str) -> Option<(&str, &str)> {
    let rest = item.strip_prefix('[')?;
    let (tag, label) = rest.split_once(']')?;
    Some((tag, label.trim_start()))
}

#[cfg(test)]
mod tests {
    use super::*;
    use ratatui::buffer::Buffer;

    #[test]
    fn test_menu_list_render() {
        let mut buf = Buffer::empty(Rect::new(0, 0, 40, 10));
        let list = MenuList::new(vec![
            "Authenticate".to_string(),
            "Retrieve list".to_string(),
        ]);

        (&list).render(Rect::new(0, 0, 40, 10), &mut buf);
    }

    #[test]
    fn test_format_menu_item_with_badge() {
        let line = format_menu_item("[AUTH] Browser authentication", 80, 0);
        let text = line
            .spans
            .iter()
            .map(|span| span.content.as_ref())
            .collect::<String>();

        assert!(text.contains("[AUTH]"));
        assert!(text.contains("Browser authentication"));
    }
}
