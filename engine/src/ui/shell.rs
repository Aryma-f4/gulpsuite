use eframe::egui::{pos2, Align, FontId, Layout, Rect, Sense, Ui, UiBuilder, Vec2};

use crate::project::SavedLayout;
use crate::ui::drawers::{self, DrawerState};
use crate::ui::reference::{burp_2026_3_3, ReferenceSpec};
use crate::ui::theme::Theme;
use crate::workspace::Workspace;

pub use crate::ui::drawers::DrawerKind;

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum ShellCommand {
    SelectTool(usize),
    SelectView(usize),
    OpenSettings,
    OpenSearch,
    OpenConsole,
    OpenBrowser,
    ToggleDrawer(DrawerKind),
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ToolOverflow {
    pub visible_tools: Vec<usize>,
    pub utility_buttons: usize,
    pub overflowed: bool,
}

#[derive(Clone, Debug, PartialEq)]
pub struct SuiteShell {
    pub active_tool: usize,
    pub active_view: usize,
    pub event_log: DrawerState,
    pub all_issues: DrawerState,
    pub detail_detached: bool,
}

impl Default for SuiteShell {
    fn default() -> Self {
        let mut shell = Self {
            active_tool: 0,
            active_view: 0,
            event_log: DrawerState::default(),
            all_issues: DrawerState::default(),
            detail_detached: false,
        };
        shell.restore_layout(&SavedLayout::default());
        shell
    }
}

impl SuiteShell {
    pub fn layout(&self) -> SavedLayout {
        SavedLayout {
            active_tool: self.active_tool,
            active_view: self.active_view,
            event_log: self.event_log.layout(),
            all_issues: self.all_issues.layout(),
            detail_detached: self.detail_detached,
        }
    }

    pub fn restore_layout(&mut self, layout: &SavedLayout) {
        self.active_tool = layout.active_tool;
        self.active_view = layout.active_view;
        self.event_log = DrawerState::from_layout(&layout.event_log);
        self.all_issues = DrawerState::from_layout(&layout.all_issues);
        self.detail_detached = layout.detail_detached;
    }

    pub fn sync_selection(&mut self, tool: usize, view: usize) {
        self.active_tool = tool;
        self.active_view = view;
    }

    pub fn toggle_drawer(&mut self, kind: DrawerKind) {
        let drawer = match kind {
            DrawerKind::EventLog => &mut self.event_log,
            DrawerKind::AllIssues => &mut self.all_issues,
        };
        drawer.open = !drawer.open;
    }

    pub fn drawer_height(&self) -> f32 {
        [
            self.event_log.open.then_some(self.event_log.height),
            self.all_issues.open.then_some(self.all_issues.height),
        ]
        .into_iter()
        .flatten()
        .sum()
    }

    pub fn draw_top(
        &mut self,
        ui: &mut Ui,
        theme: &Theme,
        tools: &[&str],
        views: &[&str],
    ) -> Vec<ShellCommand> {
        let reference = burp_2026_3_3();
        let mut commands = self.draw_tool_row(ui, theme, tools, reference);
        if views.len() > 1 && self.active_tool != crate::ui::app::SUITE {
            commands.extend(self.draw_view_row(ui, theme, views, reference));
        }
        commands
    }

    pub fn draw_drawer(
        &mut self,
        ui: &mut Ui,
        kind: DrawerKind,
        workspace: &Workspace,
        theme: &Theme,
    ) {
        let state = match kind {
            DrawerKind::EventLog => &mut self.event_log,
            DrawerKind::AllIssues => &mut self.all_issues,
        };
        drawers::draw_drawer(ui, kind, state, workspace, theme);
    }

    pub fn draw_bottom(
        &mut self,
        ui: &mut Ui,
        theme: &Theme,
        workspace: &Workspace,
        status: &str,
        memory: &str,
        memory_ratio: f32,
    ) -> Vec<ShellCommand> {
        let height = burp_2026_3_3().shell.status_height;
        let (rect, _) =
            ui.allocate_exact_size(Vec2::new(ui.available_width(), height), Sense::hover());
        let painter = ui.painter_at(rect);
        painter.rect_filled(rect, 0.0, theme.color("ui.background.2"));
        painter.line_segment(
            [rect.left_top(), rect.right_top()],
            eframe::egui::Stroke::new(1.0, theme.color("ui.border.1")),
        );
        let mut commands = Vec::new();
        let baseline = rect.center().y;
        let idle = theme.color("ui.icon.default");
        let accent = theme.color("ui.icon.link");

        let event_text = format!("Event log ({})", workspace.events.len());
        let event_width = text_width(&event_text);
        let event_rect = Rect::from_min_size(
            pos2(rect.min.x + 12.0, rect.min.y),
            Vec2::new(event_width, rect.height()),
        );
        painter.text(
            pos2(event_rect.min.x, baseline),
            eframe::egui::Align2::LEFT_CENTER,
            &event_text,
            FontId::proportional(11.0),
            if self.event_log.open { accent } else { idle },
        );
        if ui
            .interact(event_rect, ui.id().with("event-log-drawer"), Sense::click())
            .clicked()
        {
            self.toggle_drawer(DrawerKind::EventLog);
            commands.push(ShellCommand::ToggleDrawer(DrawerKind::EventLog));
        }

        let dot_x = event_rect.max.x + 10.0;
        painter.circle_filled(pos2(dot_x, baseline), 2.5, accent);
        let issues_text = format!("All issues ({})", workspace.issues.len());
        let issues_rect = Rect::from_min_size(
            pos2(dot_x + 10.0, rect.min.y),
            Vec2::new(text_width(&issues_text), rect.height()),
        );
        painter.text(
            pos2(issues_rect.min.x, baseline),
            eframe::egui::Align2::LEFT_CENTER,
            &issues_text,
            FontId::proportional(11.0),
            if self.all_issues.open { accent } else { idle },
        );
        if ui
            .interact(
                issues_rect,
                ui.id().with("all-issues-drawer"),
                Sense::click(),
            )
            .clicked()
        {
            self.toggle_drawer(DrawerKind::AllIssues);
            commands.push(ShellCommand::ToggleDrawer(DrawerKind::AllIssues));
        }

        let memory_width = text_width(memory);
        let memory_x = rect.max.x - 178.0 - memory_width;
        painter.text(
            pos2(memory_x, baseline),
            eframe::egui::Align2::LEFT_CENTER,
            memory,
            FontId::proportional(11.0),
            idle,
        );
        let track = Rect::from_min_size(
            pos2(memory_x + memory_width + 10.0, baseline - 2.0),
            Vec2::new(70.0, 4.0),
        );
        painter.rect_filled(track, 2.0, theme.color("ui.background.4"));
        painter.rect_filled(
            Rect::from_min_size(
                track.min,
                Vec2::new(track.width() * memory_ratio.clamp(0.0, 1.0), track.height()),
            ),
            2.0,
            accent,
        );
        let settings_rect =
            Rect::from_center_size(pos2(rect.max.x - 24.0, baseline), Vec2::new(28.0, 24.0));
        let settings = ui.interact(
            settings_rect,
            ui.id().with("status-settings"),
            Sense::click(),
        );
        painter.text(
            settings_rect.center(),
            eframe::egui::Align2::CENTER_CENTER,
            "⋮",
            FontId::proportional(16.0),
            if settings.hovered() { accent } else { idle },
        );
        if settings.clicked() {
            commands.push(ShellCommand::OpenSettings);
        }

        let status_x = issues_rect.max.x + 14.0;
        if memory_x - status_x > 40.0 {
            painter.text(
                pos2(status_x, baseline),
                eframe::egui::Align2::LEFT_CENTER,
                status,
                FontId::proportional(11.0),
                theme.color("ui.text.body"),
            );
        }
        commands
    }

    fn draw_tool_row(
        &mut self,
        ui: &mut Ui,
        theme: &Theme,
        tools: &[&str],
        reference: &ReferenceSpec,
    ) -> Vec<ShellCommand> {
        let height = reference.shell.tool_row_height;
        let (rect, _) =
            ui.allocate_exact_size(Vec2::new(ui.available_width(), height), Sense::hover());
        let painter = ui.painter_at(rect);
        painter.rect_filled(rect, 0.0, theme.color("ui.background.1"));
        let overflow = tool_overflow(rect.width(), self.active_tool, tools);
        let mut commands = Vec::new();
        let mut x = rect.min.x + 16.0;
        for index in overflow.visible_tools.iter().copied() {
            let label = tools[index];
            let width = text_width(label);
            let tab = Rect::from_min_max(
                pos2(x - 10.0, rect.min.y),
                pos2(x + width + 10.0, rect.max.y),
            );
            if index == self.active_tool {
                painter.rect_filled(tab, 0.0, theme.color("ui.background.2"));
                painter.rect_filled(
                    Rect::from_min_max(pos2(tab.min.x, tab.max.y - 3.0), tab.max),
                    0.0,
                    theme.color("ui.icon.link"),
                );
            }
            painter.text(
                pos2(x, rect.center().y - 1.0),
                eframe::egui::Align2::LEFT_CENTER,
                label,
                FontId::proportional(11.5),
                theme.color("ui.text.body"),
            );
            if ui
                .interact(tab, ui.id().with(("shell-tool", index)), Sense::click())
                .clicked()
            {
                self.active_tool = index;
                self.active_view = 0;
                commands.push(ShellCommand::SelectTool(index));
            }
            x += width + 28.0;
        }

        if overflow.overflowed {
            let hidden: Vec<_> = (0..tools.len())
                .filter(|index| !overflow.visible_tools.contains(index))
                .collect();
            let overflow_rect = Rect::from_min_size(
                pos2(x - 6.0, rect.min.y + 2.0),
                Vec2::new(28.0, rect.height() - 4.0),
            );
            let mut menu = ui.new_child(
                UiBuilder::new()
                    .max_rect(overflow_rect)
                    .layout(Layout::top_down(Align::LEFT))
                    .id_salt("tool-overflow"),
            );
            menu.menu_button("»", |ui| {
                for index in hidden {
                    if ui.button(tools[index]).clicked() {
                        self.active_tool = index;
                        self.active_view = 0;
                        commands.push(ShellCommand::SelectTool(index));
                        ui.close();
                    }
                }
            });
        }

        let utilities = [
            (
                crate::ui::icons::Glyph::Globe,
                ShellCommand::OpenBrowser,
                "Browser",
            ),
            (
                crate::ui::icons::Glyph::Terminal,
                ShellCommand::OpenConsole,
                "Browser console",
            ),
            (
                crate::ui::icons::Glyph::Search,
                ShellCommand::OpenSearch,
                "Search",
            ),
            (
                crate::ui::icons::Glyph::Gear,
                ShellCommand::OpenSettings,
                "Settings",
            ),
        ];
        let utility_x = rect.max.x - 104.0;
        for (index, (glyph, command, tooltip)) in utilities.into_iter().enumerate() {
            let area = Rect::from_center_size(
                pos2(utility_x + index as f32 * 24.0, rect.center().y),
                Vec2::splat(18.0),
            );
            crate::ui::icons::paint(&painter, area, theme.color("ui.icon.default"), glyph);
            let response =
                ui.interact(area, ui.id().with(("shell-utility", index)), Sense::click());
            if response.clicked() {
                commands.push(command);
            }
            if response.hovered() {
                response.show_tooltip_text(tooltip);
            }
        }
        painter.line_segment(
            [rect.left_bottom(), rect.right_bottom()],
            eframe::egui::Stroke::new(1.0, theme.color("ui.border.1")),
        );
        commands
    }

    fn draw_view_row(
        &mut self,
        ui: &mut Ui,
        theme: &Theme,
        views: &[&str],
        reference: &ReferenceSpec,
    ) -> Vec<ShellCommand> {
        let (rect, _) = ui.allocate_exact_size(
            Vec2::new(ui.available_width(), reference.shell.sub_row_height),
            Sense::hover(),
        );
        let painter = ui.painter_at(rect);
        painter.rect_filled(rect, 0.0, theme.color("ui.background.2"));
        let mut commands = Vec::new();
        let mut x = rect.min.x + 16.0;
        for (index, label) in views.iter().enumerate() {
            let width = text_width(label);
            let tab = Rect::from_min_max(
                pos2(x - 10.0, rect.min.y),
                pos2(x + width + 10.0, rect.max.y),
            );
            painter.text(
                pos2(x, rect.center().y - 1.0),
                eframe::egui::Align2::LEFT_CENTER,
                *label,
                FontId::proportional(11.5),
                theme.color("ui.text.body"),
            );
            if index == self.active_view {
                painter.rect_filled(
                    Rect::from_min_max(pos2(tab.min.x, tab.max.y - 3.0), tab.max),
                    0.0,
                    theme.color("ui.icon.link"),
                );
            }
            if ui
                .interact(tab, ui.id().with(("shell-view", index)), Sense::click())
                .clicked()
            {
                self.active_view = index;
                commands.push(ShellCommand::SelectView(index));
            }
            x += width + 28.0;
        }
        painter.line_segment(
            [rect.left_bottom(), rect.right_bottom()],
            eframe::egui::Stroke::new(1.0, theme.color("ui.border.1")),
        );
        commands
    }
}

pub fn tool_overflow(width: f32, selected: usize, tools: &[&str]) -> ToolOverflow {
    const UTILITY_WIDTH: f32 = 124.0;
    const OVERFLOW_WIDTH: f32 = 36.0;
    let full_width: f32 = 16.0
        + tools
            .iter()
            .map(|label| text_width(label) + 28.0)
            .sum::<f32>()
        + UTILITY_WIDTH;
    if full_width <= width {
        return ToolOverflow {
            visible_tools: (0..tools.len()).collect(),
            utility_buttons: 4,
            overflowed: false,
        };
    }

    let budget = (width - UTILITY_WIDTH - OVERFLOW_WIDTH - 16.0).max(1.0);
    let mut used = 0.0;
    let mut visible = Vec::new();
    for (index, label) in tools.iter().enumerate() {
        let tab = text_width(label) + 28.0;
        if used + tab > budget {
            break;
        }
        visible.push(index);
        used += tab;
    }
    let selected = selected.min(tools.len().saturating_sub(1));
    if !visible.contains(&selected) {
        if visible.is_empty() {
            visible.push(selected);
        } else {
            *visible.last_mut().expect("visible tool") = selected;
            visible.sort_unstable();
            visible.dedup();
        }
    }
    ToolOverflow {
        visible_tools: visible,
        utility_buttons: 4,
        overflowed: true,
    }
}

fn text_width(text: &str) -> f32 {
    text.chars().count() as f32 * 6.2
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::project::SavedLayout;

    #[test]
    fn drawers_open_and_close_independently() {
        let mut shell = SuiteShell::default();
        shell.toggle_drawer(DrawerKind::EventLog);
        assert!(shell.event_log.open);
        assert!(!shell.all_issues.open);
        shell.toggle_drawer(DrawerKind::AllIssues);
        assert!(shell.event_log.open);
        assert!(shell.all_issues.open);
        shell.toggle_drawer(DrawerKind::EventLog);
        assert!(!shell.event_log.open);
        assert!(shell.all_issues.open);
    }

    #[test]
    fn saved_layout_restores_drawer_selection() {
        let mut layout = SavedLayout::default();
        layout.event_log.open = true;
        layout.event_log.selected = Some(8);
        let mut shell = SuiteShell::default();
        shell.restore_layout(&layout);
        assert!(shell.event_log.open);
        assert_eq!(shell.event_log.selected, Some(8));
        assert_eq!(shell.layout(), layout);
    }

    #[test]
    fn overflow_always_keeps_selected_tool_and_four_utilities() {
        for width in [1440.0, 900.0, 640.0] {
            for selected in [0, 6, 12] {
                let layout = tool_overflow(width, selected, &crate::ui::app::TOOLS);
                assert!(layout.visible_tools.contains(&selected));
                assert_eq!(layout.utility_buttons, 4);
                assert!(!layout.visible_tools.is_empty());
            }
        }
        assert_eq!(
            tool_overflow(1440.0, 12, &crate::ui::app::TOOLS)
                .visible_tools
                .len(),
            crate::ui::app::TOOLS.len()
        );
        assert!(tool_overflow(640.0, 12, &crate::ui::app::TOOLS).overflowed);
    }
}
