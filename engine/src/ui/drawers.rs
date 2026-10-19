use std::collections::BTreeSet;

use eframe::egui::{Align, Frame, Layout, RichText, Sense, Ui, UiBuilder, Vec2};

use crate::project::{DrawerLayout, MAX_DRAWER_HEIGHT, MIN_DRAWER_HEIGHT};
use crate::ui::theme::Theme;
use crate::workspace::{EventLevel, EventStore, IssueSeverity, IssueStore, Workspace};

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum DrawerKind {
    EventLog,
    AllIssues,
}

#[derive(Clone, Debug, PartialEq)]
pub struct DrawerState {
    pub open: bool,
    pub height: f32,
    pub selected: Option<u64>,
    pub search: String,
    pub filters: BTreeSet<String>,
    pub split_ratio: f32,
}

impl Default for DrawerState {
    fn default() -> Self {
        Self::from_layout(&DrawerLayout::default())
    }
}

impl DrawerState {
    pub fn from_layout(layout: &DrawerLayout) -> Self {
        Self {
            open: layout.open,
            height: layout.height.clamp(MIN_DRAWER_HEIGHT, MAX_DRAWER_HEIGHT),
            selected: layout.selected,
            search: layout.search.clone(),
            filters: layout.filters.iter().cloned().collect(),
            split_ratio: layout.split_ratio.clamp(0.2, 0.8),
        }
    }

    pub fn layout(&self) -> DrawerLayout {
        DrawerLayout {
            open: self.open,
            height: self.height,
            selected: self.selected,
            search: self.search.clone(),
            filters: self.filters.iter().cloned().collect(),
            split_ratio: self.split_ratio,
        }
    }

    pub fn resize(&mut self, height: f32) {
        self.height = if height.is_finite() {
            height.clamp(MIN_DRAWER_HEIGHT, MAX_DRAWER_HEIGHT)
        } else {
            crate::project::DEFAULT_DRAWER_HEIGHT
        };
    }

    pub fn clear_filters(&mut self) {
        self.search.clear();
        self.filters.clear();
    }

    pub fn filtered_events(&self, events: &EventStore) -> Vec<u64> {
        let needle = self.search.trim().to_lowercase();
        events
            .iter()
            .filter(|event| {
                self.filters.is_empty() || self.filters.contains(event_level_name(event.level))
            })
            .filter(|event| {
                needle.is_empty()
                    || event.source.to_lowercase().contains(&needle)
                    || event.message.to_lowercase().contains(&needle)
            })
            .map(|event| event.id.0)
            .collect()
    }

    pub fn filtered_issues(&self, issues: &IssueStore) -> Vec<u64> {
        let needle = self.search.trim().to_lowercase();
        issues
            .iter()
            .filter(|issue| {
                self.filters.is_empty()
                    || self.filters.contains(issue_severity_name(issue.severity))
            })
            .filter(|issue| {
                needle.is_empty()
                    || issue.name.to_lowercase().contains(&needle)
                    || issue.url.to_lowercase().contains(&needle)
                    || issue.evidence.to_lowercase().contains(&needle)
            })
            .map(|issue| issue.id.0)
            .collect()
    }
}

pub fn draw_drawer(
    ui: &mut Ui,
    kind: DrawerKind,
    state: &mut DrawerState,
    workspace: &Workspace,
    theme: &Theme,
) {
    let (_, drag) = ui.allocate_exact_size(Vec2::new(ui.available_width(), 5.0), Sense::drag());
    if drag.dragged() {
        state.resize(state.height - drag.drag_delta().y);
    }

    let content_height = (state.height - 5.0).max(0.0);
    let (rect, _) = ui.allocate_exact_size(
        Vec2::new(ui.available_width(), content_height),
        Sense::hover(),
    );
    let mut child = ui.new_child(
        UiBuilder::new()
            .max_rect(rect)
            .layout(Layout::top_down(Align::LEFT))
            .id_salt(("bottom-drawer", kind)),
    );
    Frame::NONE
        .fill(theme.color("ui.background.2"))
        .stroke(eframe::egui::Stroke::new(1.0, theme.color("ui.border.1")))
        .inner_margin(8.0)
        .show(&mut child, |ui| {
            ui.horizontal(|ui| {
                ui.label(
                    RichText::new(match kind {
                        DrawerKind::EventLog => "Event log",
                        DrawerKind::AllIssues => "All issues",
                    })
                    .strong(),
                );
                ui.add(
                    eframe::egui::TextEdit::singleline(&mut state.search)
                        .hint_text("Search")
                        .desired_width(180.0),
                );
                for filter in filter_names(kind) {
                    let mut enabled = state.filters.contains(*filter);
                    if ui.checkbox(&mut enabled, *filter).changed() {
                        if enabled {
                            state.filters.insert(filter.to_string());
                        } else {
                            state.filters.remove(*filter);
                        }
                    }
                }
                if ui.button("Clear filters").clicked() {
                    state.clear_filters();
                }
                ui.with_layout(Layout::right_to_left(Align::Center), |ui| {
                    if ui.button("Close").clicked() {
                        state.open = false;
                    }
                });
            });
            ui.separator();

            match kind {
                DrawerKind::EventLog => draw_events(ui, state, workspace, theme),
                DrawerKind::AllIssues => draw_issues(ui, state, workspace, theme),
            }
        });
}

fn draw_events(ui: &mut Ui, state: &mut DrawerState, workspace: &Workspace, theme: &Theme) {
    let ids = state.filtered_events(&workspace.events);
    if ids.is_empty() {
        empty_state(ui, "No events match the current filters.", theme);
        return;
    }
    ui.columns(2, |columns| {
        eframe::egui::ScrollArea::vertical().show(&mut columns[0], |ui| {
            for id in &ids {
                if let Some(event) = workspace.events.iter().find(|event| event.id.0 == *id) {
                    let selected = state.selected == Some(*id);
                    if ui
                        .selectable_label(
                            selected,
                            format!(
                                "{}  {}  {}",
                                event_level_name(event.level),
                                event.source,
                                event.message
                            ),
                        )
                        .clicked()
                    {
                        state.selected = Some(*id);
                    }
                }
            }
        });
        if let Some(event) = state
            .selected
            .and_then(|id| workspace.events.iter().find(|event| event.id.0 == id))
        {
            columns[1].label(RichText::new(&event.source).strong());
            columns[1].label(event_level_name(event.level));
            columns[1].separator();
            columns[1].label(&event.message);
            if let Some(task) = event.task_id {
                columns[1].label(format!("Task {}", task.0));
            }
        } else {
            empty_state(&mut columns[1], "Select an event to inspect it.", theme);
        }
    });
}

fn draw_issues(ui: &mut Ui, state: &mut DrawerState, workspace: &Workspace, theme: &Theme) {
    let ids = state.filtered_issues(&workspace.issues);
    if ids.is_empty() {
        empty_state(ui, "No issues match the current filters.", theme);
        return;
    }
    ui.columns(2, |columns| {
        eframe::egui::ScrollArea::vertical().show(&mut columns[0], |ui| {
            for id in &ids {
                if let Some(issue) = workspace.issues.iter().find(|issue| issue.id.0 == *id) {
                    let selected = state.selected == Some(*id);
                    if ui
                        .selectable_label(
                            selected,
                            format!(
                                "{}  {}  {}",
                                issue_severity_name(issue.severity),
                                issue.name,
                                issue.url
                            ),
                        )
                        .clicked()
                    {
                        state.selected = Some(*id);
                    }
                }
            }
        });
        if let Some(issue) = state
            .selected
            .and_then(|id| workspace.issues.iter().find(|issue| issue.id.0 == id))
        {
            columns[1].label(RichText::new(&issue.name).strong());
            columns[1].label(format!(
                "{} severity · {} confidence",
                issue_severity_name(issue.severity),
                issue.confidence
            ));
            columns[1].label(RichText::new(&issue.url).monospace());
            if let Some(parameter) = &issue.parameter {
                columns[1].label(format!("Parameter: {parameter}"));
            }
            columns[1].separator();
            columns[1].label(&issue.evidence);
        } else {
            empty_state(&mut columns[1], "Select an issue to inspect it.", theme);
        }
    });
}

fn empty_state(ui: &mut Ui, message: &str, theme: &Theme) {
    ui.centered_and_justified(|ui| {
        ui.label(RichText::new(message).color(theme.color("ui.icon.default")));
    });
}

fn filter_names(kind: DrawerKind) -> &'static [&'static str] {
    match kind {
        DrawerKind::EventLog => &["Debug", "Info", "Warning", "Error", "Critical"],
        DrawerKind::AllIssues => &["Info", "Low", "Medium", "High"],
    }
}

fn event_level_name(level: EventLevel) -> &'static str {
    match level {
        EventLevel::Debug => "Debug",
        EventLevel::Info => "Info",
        EventLevel::Warning => "Warning",
        EventLevel::Error => "Error",
        EventLevel::Critical => "Critical",
    }
}

fn issue_severity_name(severity: IssueSeverity) -> &'static str {
    match severity {
        IssueSeverity::Info => "Info",
        IssueSeverity::Low => "Low",
        IssueSeverity::Medium => "Medium",
        IssueSeverity::High => "High",
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::project::{MAX_DRAWER_HEIGHT, MIN_DRAWER_HEIGHT};
    use crate::workspace::{EventLevel, EventStore, TaskId};

    #[test]
    fn drawer_height_is_clamped() {
        let mut drawer = DrawerState::default();
        drawer.resize(20.0);
        assert_eq!(drawer.height, MIN_DRAWER_HEIGHT);
        drawer.resize(2_000.0);
        assert_eq!(drawer.height, MAX_DRAWER_HEIGHT);
    }

    #[test]
    fn zero_result_filter_preserves_selection_and_clear_restores_rows() {
        let mut events = EventStore::default();
        let id = events.push(1, EventLevel::Info, "Proxy", "captured", Some(TaskId(1)));
        let mut drawer = DrawerState::default();
        drawer.selected = Some(id.0);
        drawer.search = "not-present".into();
        assert!(drawer.filtered_events(&events).is_empty());
        assert_eq!(drawer.selected, Some(id.0));
        drawer.clear_filters();
        assert_eq!(drawer.filtered_events(&events), vec![id.0]);
        assert_eq!(drawer.selected, Some(id.0));
    }
}
