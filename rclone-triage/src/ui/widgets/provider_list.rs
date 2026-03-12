//! Provider list widget

use ratatui::buffer::Buffer;
use ratatui::layout::Rect;
use ratatui::text::{Line, Span, Text};
use ratatui::widgets::{Block, Borders, List, ListItem, ListState, StatefulWidget, Widget};

use crate::ui::theme;
use crate::ui::widgets::{text_width, wrap_line, StyledSegment};

/// Provider list widget
#[derive(Debug, Clone)]
pub struct ProviderList {
    pub providers: Vec<String>,
    pub checked: Vec<bool>,
    pub selected: usize,
    pub animation_frame: u64,
}

impl ProviderList {
    pub fn new(providers: Vec<String>, checked: Vec<bool>, selected: usize) -> Self {
        Self {
            providers,
            checked,
            selected,
            animation_frame: 0,
        }
    }

    pub fn select_next(&mut self) {
        if !self.providers.is_empty() {
            self.selected = (self.selected + 1) % self.providers.len();
        }
    }

    pub fn select_previous(&mut self) {
        if !self.providers.is_empty() {
            if self.selected == 0 {
                self.selected = self.providers.len() - 1;
            } else {
                self.selected -= 1;
            }
        }
    }
}

impl Widget for &ProviderList {
    fn render(self, area: Rect, buf: &mut Buffer) {
        let highlight_symbol = theme::list_highlight_symbol(self.animation_frame);
        let highlight_width = text_width(highlight_symbol) as u16;
        let inner_width = area.width.saturating_sub(2);
        let items: Vec<ListItem> = self
            .providers
            .iter()
            .enumerate()
            .map(|(idx, p)| {
                let checked = self.checked.get(idx).copied().unwrap_or(false);
                let prefix = if checked { "[x] " } else { "[ ] " };
                let prefix_style = if checked {
                    theme::success_style()
                } else {
                    theme::muted_style()
                };
                let available_width = inner_width.saturating_sub(if idx == self.selected {
                    highlight_width
                } else {
                    0
                });
                ListItem::new(Text::from(wrap_line(
                    vec![Span::styled(prefix, prefix_style)],
                    vec![StyledSegment::new(p, theme::strong_style())],
                    available_width,
                )))
            })
            .collect();

        let title = if self.providers.is_empty() {
            "Providers".to_string()
        } else {
            format!("Providers ({})", self.providers.len())
        };
        let list = List::new(items)
            .block(
                Block::default()
                    .title(Line::from(Span::styled(title, theme::panel_title_style())))
                    .borders(Borders::ALL)
                    .border_style(theme::panel_border_style()),
            )
            .style(theme::list_style())
            .highlight_style(theme::list_highlight_style())
            .highlight_symbol(highlight_symbol);

        let mut state = ListState::default();
        if !self.providers.is_empty() {
            state.select(Some(self.selected));
        }

        StatefulWidget::render(list, area, buf, &mut state);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ratatui::buffer::Buffer;

    #[test]
    fn test_provider_list_render() {
        let mut buf = Buffer::empty(Rect::new(0, 0, 40, 10));
        let list = ProviderList::new(
            vec!["Google Drive".to_string(), "OneDrive".to_string()],
            vec![true, false],
            0,
        );

        (&list).render(Rect::new(0, 0, 40, 10), &mut buf);
    }
}
