//! Dashboard task list and selected-task detail, backed by the shared workspace.

use std::collections::BTreeSet;

use eframe::egui::{self, Color32, FontId, Sense, Ui, Vec2};

use super::{heading, muted};
use crate::ui::app::App;
use crate::ui::icons::Glyph;
use crate::workspace::{
    IssueRecord, IssueSeverity, Task, TaskId, TaskKind, TaskQuery, TaskState, Workspace,
};

#[derive(Clone, Debug, Default)]
pub struct DashboardState {
    pub search: String,
    pub states: BTreeSet<TaskState>,
    pub kinds: BTreeSet<TaskKind>,
    pub rename_task: Option<TaskId>,
    pub rename_text: String,
    pub show_configuration: bool,
    task_views: TaskViews,
}

#[derive(Clone, Debug)]
struct TaskViews {
    task: Option<TaskId>,
    issues_search: String,
    events_search: String,
    issue_levels: [bool; 4],
    event_levels: [bool; 4],
    issues_newest: bool,
    issue: Option<crate::workspace::IssueId>,
    event: Option<crate::workspace::EventId>,
}

impl Default for TaskViews {
    fn default() -> Self {
        Self {
            task: None,
            issues_search: String::new(),
            events_search: String::new(),
            issue_levels: [true; 4],
            event_levels: [true, true, true, false],
            issues_newest: true,
            issue: None,
            event: None,
        }
    }
}

impl DashboardState {
    pub fn query(&self) -> TaskQuery {
        TaskQuery {
            states: self.states.clone(),
            kinds: self.kinds.clone(),
            search: self.search.clone(),
        }
    }

    pub fn visible_task_ids(&self, workspace: &Workspace) -> Vec<TaskId> {
        workspace
            .tasks
            .query(&self.query())
            .into_iter()
            .map(|task| task.id)
            .collect()
    }

    pub fn selected_task<'a>(&self, workspace: &'a Workspace) -> Option<&'a Task> {
        workspace
            .tasks
            .selected()
            .and_then(|id| workspace.tasks.get(id))
    }

    pub fn empty_state(&self, workspace: &Workspace) -> DashboardEmpty {
        if workspace.tasks.is_empty() {
            DashboardEmpty::NoTasks
        } else if self.visible_task_ids(workspace).is_empty() {
            DashboardEmpty::NoMatches
        } else {
            DashboardEmpty::Populated
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum DashboardEmpty {
    NoTasks,
    NoMatches,
    Populated,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum DashboardCommand {
    NewScan,
    NewLiveTask,
    Select(TaskId),
    Rename(TaskId, String),
    Pause(TaskId),
    Resume(TaskId),
    Cancel(TaskId),
    Detach(TaskId),
    ShowSettings,
    ShowHelp,
}

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct TaskControls {
    pub pause: bool,
    pub resume: bool,
    pub cancel: bool,
    pub rename: bool,
}

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct IssueCounts {
    pub info: usize,
    pub low: usize,
    pub medium: usize,
    pub high: usize,
}

pub fn controls_for(state: TaskState) -> TaskControls {
    TaskControls {
        pause: state == TaskState::Running,
        resume: state == TaskState::Paused,
        cancel: matches!(
            state,
            TaskState::Queued | TaskState::Running | TaskState::Paused
        ),
        rename: true,
    }
}

pub fn issue_counts(workspace: &Workspace, task_id: TaskId) -> IssueCounts {
    let mut counts = IssueCounts::default();
    for issue in workspace
        .issues
        .iter()
        .filter(|issue| issue.task_id == task_id)
    {
        match issue.severity {
            IssueSeverity::Info => counts.info += 1,
            IssueSeverity::Low => counts.low += 1,
            IssueSeverity::Medium => counts.medium += 1,
            IssueSeverity::High => counts.high += 1,
        }
    }
    counts
}

pub fn draw(app: &mut App, ui: &mut Ui) {
    if ui.available_width() < 1100.0 {
        egui::ScrollArea::both()
            .id_salt("dashboard-narrow")
            .auto_shrink([false, false])
            .show(ui, |ui| {
                ui.set_min_width(1100.0);
                draw_contents(app, ui);
            });
    } else {
        draw_contents(app, ui);
    }
}

fn draw_contents(app: &mut App, ui: &mut Ui) {
    let split = crate::ui::reference::gulp_reference().dashboard.split_ratio;
    let left = (ui.available_width() * split).max(260.0);
    let mut commands = Vec::new();
    ui.horizontal_top(|ui| {
        ui.add_space(12.0);
        tasks_column(app, ui, left - 12.0, &mut commands);
        ui.separator();
        ui.add_space(16.0);
        if app.shell.detail_location == crate::ui::shell::DetailLocation::Detached {
            dashboard_empty(
                ui,
                &app.theme,
                "Task details detached",
                "Details are open in another window.",
            );
        } else {
            detail_pane(app, ui, &mut commands);
        }
    });
    for command in commands {
        apply_command(app, command);
    }
}

pub fn draw_detached(app: &mut App, ui: &mut Ui) {
    if let Some(id) = app.shell.detached_task() {
        let _ = app.workspace.tasks.select(id);
    }
    let mut commands = Vec::new();
    detail_pane(app, ui, &mut commands);
    for command in commands {
        apply_command(app, command);
    }
}

fn tasks_column(app: &mut App, ui: &mut Ui, width: f32, commands: &mut Vec<DashboardCommand>) {
    let theme = app.theme.clone();
    ui.vertical(|ui| {
        ui.set_width(width);
        ui.horizontal(|ui| {
            heading(ui, &theme, "Tasks");
            ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                pane_icons(ui, &theme, commands);
                if crate::ui::app::primary_button(ui, &theme, "New live task").clicked() {
                    commands.push(DashboardCommand::NewLiveTask);
                }
                if crate::ui::app::primary_button(ui, &theme, "New scan").clicked() {
                    commands.push(DashboardCommand::NewScan);
                }
                if width > 400.0 {
                    ui.add_space(80.0);
                }
            });
        });
        ui.add_space(4.0);
        filter_row(app, ui);
        ui.add_space(24.0);

        let ids = app.dashboard.visible_task_ids(&app.workspace);
        match app.dashboard.empty_state(&app.workspace) {
            DashboardEmpty::NoTasks => dashboard_empty(
                ui,
                &theme,
                "No tasks yet",
                "Create a scan or live task to start working.",
            ),
            DashboardEmpty::NoMatches => dashboard_empty(
                ui,
                &theme,
                "No matching tasks",
                "Clear the search or filters to see your tasks.",
            ),
            DashboardEmpty::Populated => {
                egui::ScrollArea::vertical().show(ui, |ui| {
                    for id in ids {
                        if let Some(task) = app.workspace.tasks.get(id).cloned() {
                            task_card(app, ui, &task, commands);
                        }
                    }
                });
            }
        }
    });
}

fn filter_row(app: &mut App, ui: &mut Ui) {
    let theme = app.theme.clone();
    ui.horizontal(|ui| {
        let (funnel, _) = ui.allocate_exact_size(Vec2::splat(14.0), Sense::hover());
        crate::ui::icons::paint(
            ui.painter(),
            funnel,
            theme.color("ui.icon.default"),
            Glyph::Funnel,
        );
        ui.menu_button("Filter", |ui| {
            ui.label(egui::RichText::new("State").strong());
            for state in [
                TaskState::Queued,
                TaskState::Running,
                TaskState::Paused,
                TaskState::Completed,
                TaskState::Failed,
                TaskState::Cancelled,
                TaskState::Interrupted,
            ] {
                let mut selected = app.dashboard.states.contains(&state);
                if ui.checkbox(&mut selected, state_name(state)).changed() {
                    if selected {
                        app.dashboard.states.insert(state);
                    } else {
                        app.dashboard.states.remove(&state);
                    }
                }
            }
            ui.separator();
            ui.label(egui::RichText::new("Type").strong());
            for kind in [
                TaskKind::LiveAudit,
                TaskKind::PassiveCrawl,
                TaskKind::Scan,
                TaskKind::Intruder,
                TaskKind::Discover,
                TaskKind::Other,
            ] {
                let mut selected = app.dashboard.kinds.contains(&kind);
                if ui.checkbox(&mut selected, kind_name(kind)).changed() {
                    if selected {
                        app.dashboard.kinds.insert(kind);
                    } else {
                        app.dashboard.kinds.remove(&kind);
                    }
                }
            }
            if ui.button("Clear filters").clicked() {
                app.dashboard.states.clear();
                app.dashboard.kinds.clear();
            }
        });
        ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
            let search = ui.add(
                egui::TextEdit::singleline(&mut app.dashboard.search)
                    .hint_text("Search")
                    .desired_width(150.0),
            );
            search.widget_info(|| {
                egui::WidgetInfo::labeled(egui::WidgetType::TextEdit, true, "Search tasks")
            });
        });
    });
}

fn task_card(app: &mut App, ui: &mut Ui, task: &Task, commands: &mut Vec<DashboardCommand>) {
    let theme = app.theme.clone();
    let selected = app.workspace.tasks.selected() == Some(task.id);
    let accent = theme.color("palette.secondary.core");
    let counts = issue_counts(&app.workspace, task.id);
    let frame = egui::Frame {
        fill: if selected {
            theme.color(if theme.dark {
                "palette.secondary.1"
            } else {
                "palette.secondary.7"
            })
        } else {
            theme.color("ui.background.1")
        },
        stroke: egui::Stroke::new(1.0, theme.color("ui.border.1")),
        corner_radius: egui::CornerRadius::same(4),
        inner_margin: egui::Margin::symmetric(12, 10),
        outer_margin: egui::Margin::symmetric(0, 7),
        shadow: egui::Shadow {
            offset: [0, 2],
            blur: 8,
            spread: 0,
            color: Color32::from_black_alpha(if theme.dark { 48 } else { 28 }),
        },
    };
    let mut control_clicked = false;
    let mut menu_rect = egui::Rect::NOTHING;
    let mut toggle_rect = egui::Rect::NOTHING;
    let response = frame.show(ui, |ui| {
        ui.horizontal(|ui| {
            if app.dashboard.rename_task == Some(task.id) {
                let submitted = ui
                    .add(
                        egui::TextEdit::singleline(&mut app.dashboard.rename_text)
                            .desired_width(180.0),
                    )
                    .lost_focus()
                    && ui.input(|input| input.key_pressed(egui::Key::Enter));
                if submitted || ui.button("Save").clicked() {
                    control_clicked = true;
                    commands.push(DashboardCommand::Rename(
                        task.id,
                        app.dashboard.rename_text.clone(),
                    ));
                }
                if ui.button("Cancel").clicked() {
                    control_clicked = true;
                    app.dashboard.rename_task = None;
                }
            } else if crate::ui::app::bold_click_label(
                ui,
                &task.name,
                12.0,
                theme.color("ui.text.body"),
            )
            .clicked()
            {
                commands.push(DashboardCommand::Select(task.id));
            }
            ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                let (m_rect, m_clicked) = task_menu(app, ui, task, commands);
                menu_rect = m_rect;
                if m_clicked {
                    control_clicked = true;
                }
            });
        });
        ui.add(
            egui::Label::new(
                egui::RichText::new(&task.configuration).color(theme.color("ui.text.disabled")),
            )
            .selectable(false),
        );
        let show_scan_bar = task.kind == TaskKind::Scan
            && (task.state == TaskState::Running
                || app.panels.scanner.running
                || (task.state == TaskState::Paused && task.progress.completed > 0));
        if show_scan_bar {
            ui.add_space(6.0);
            let is_running = task.state == TaskState::Running || app.panels.scanner.running;
            let ratio = if let Some(tot) = task.progress.total.filter(|t| *t > 0) {
                (task.progress.completed as f32 / tot as f32).clamp(0.12, 1.0)
            } else if app.panels.scanner.running {
                (app.panels.scanner.completed_steps as f32
                    / app.panels.scanner.total_steps.max(1) as f32)
                    .clamp(0.15, 0.96)
            } else {
                0.22
            };
            super::scanner::paint_gulp_progress_bar_animated(ui, 185.0, ratio, is_running, &theme);
            ui.add_space(4.0);
            ui.horizontal(|ui| {
                if is_running {
                    super::scanner::paint_gulp_spinner(
                        ui,
                        Vec2::new(14.0, 14.0),
                        Color32::from_rgb(0x5B, 0x4F, 0xFF),
                    );
                }
                super::scanner::paint_launcher_icon(
                    ui,
                    Vec2::new(14.0, 14.0),
                    theme.color("ui.icon.default"),
                    super::scanner::LauncherIcon::ScanDetails,
                );
                let status_lbl = if !task.progress.status.is_empty() {
                    task.progress.status.as_str()
                } else if is_running {
                    "Auditing"
                } else {
                    "Paused task due to: Reached time limit for task"
                };
                let short_status = if status_lbl.chars().count() > 40 {
                    let mut s: String = status_lbl.chars().take(39).collect();
                    s.push('…');
                    s
                } else {
                    status_lbl.to_string()
                };
                ui.add(
                    egui::Label::new(egui::RichText::new(short_status).size(11.5))
                        .truncate()
                        .selectable(false),
                )
                .on_hover_text(status_lbl);
            });
            ui.add_space(4.0);
        } else {
            ui.add_space(17.0);
        }
        ui.horizontal(|ui| {
            ui.add(egui::Label::new(task_activity_label(task)).selectable(false));
            let mut active = task.state == TaskState::Running;
            let can_toggle = task_can_toggle(task) || task.kind == TaskKind::Scan;
            let toggle = ui
                .add_enabled_ui(can_toggle, |ui| switch(ui, &mut active, accent))
                .inner;
            toggle_rect = toggle.rect;
            if toggle.clicked() {
                control_clicked = true;
                commands.push(DashboardCommand::Select(task.id));
                if active {
                    commands.push(DashboardCommand::Resume(task.id));
                } else {
                    commands.push(DashboardCommand::Pause(task.id));
                }
            }
            ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                issue_pill(ui, counts.info, theme.color("palette.mono.5"));
                issue_pill(ui, counts.low, theme.color("ui.issue.low"));
                issue_pill(ui, counts.medium, theme.color("ui.issue.medium"));
                issue_pill(ui, counts.high, theme.color("ui.issue.high"));
                ui.add(egui::Label::new("Issues:").selectable(false));
            });
        });
        ui.add_space(32.0);
    });
    let card_rect = response.response.rect;
    let pointer_in_card = ui.rect_contains_pointer(card_rect);
    if pointer_in_card {
        ui.ctx().set_cursor_icon(egui::CursorIcon::PointingHand);
    }
    let pointer_on_controls = pointer_in_card
        && ui
            .input(|i| i.pointer.interact_pos())
            .is_some_and(|pos| menu_rect.contains(pos) || toggle_rect.contains(pos));
    let pointer_clicked_card =
        pointer_in_card && !pointer_on_controls && ui.input(|i| i.pointer.primary_clicked());
    if !control_clicked && (response.response.clicked() || pointer_clicked_card) {
        commands.push(DashboardCommand::Select(task.id));
    }
    if selected {
        let rect = response.response.rect;
        ui.painter().rect_filled(
            egui::Rect::from_min_max(
                egui::pos2(rect.max.x - 4.0, rect.min.y + 1.0),
                egui::pos2(rect.max.x - 1.0, rect.max.y - 1.0),
            ),
            0.0,
            accent,
        );
    }
}

fn task_menu(
    app: &mut App,
    ui: &mut Ui,
    task: &Task,
    commands: &mut Vec<DashboardCommand>,
) -> (egui::Rect, bool) {
    let controls = controls_for(task.state);
    let dot_col = app.theme.color("ui.icon.default");
    let mut interacted = false;
    let menu = ui.menu_button("   ", |ui| {
        interacted = true;
        if controls.pause && ui.button("Pause").clicked() {
            commands.push(DashboardCommand::Pause(task.id));
            ui.close();
        }
        if (controls.resume || (task.kind == TaskKind::Scan && task.state != TaskState::Running))
            && ui.button("Resume").clicked()
        {
            commands.push(DashboardCommand::Resume(task.id));
            ui.close();
        }
        if controls.rename && ui.button("Rename").clicked() {
            app.dashboard.rename_task = Some(task.id);
            app.dashboard.rename_text = task.name.clone();
            ui.close();
        }
        if controls.cancel && ui.button("Cancel").clicked() {
            commands.push(DashboardCommand::Cancel(task.id));
            ui.close();
        }
        if ui.button("Detach details").clicked() {
            commands.push(DashboardCommand::Detach(task.id));
            ui.close();
        }
    });
    if menu.response.clicked() {
        interacted = true;
    }
    let c = menu.response.rect.center();
    for dy in [-4.5_f32, 0.0, 4.5] {
        ui.painter()
            .circle_filled(egui::pos2(c.x, c.y + dy), 1.4, dot_col);
    }
    menu.response.widget_info(|| {
        egui::WidgetInfo::labeled(
            egui::WidgetType::Button,
            true,
            format!("Task actions: {}", task.name),
        )
    });
    (menu.response.rect, interacted)
}

fn pane_icons(ui: &mut Ui, theme: &crate::ui::theme::Theme, commands: &mut Vec<DashboardCommand>) {
    for (glyph, command, tooltip) in [
        (Glyph::Help, DashboardCommand::ShowHelp, "Help"),
        (Glyph::Gear, DashboardCommand::ShowSettings, "Settings"),
    ] {
        let (rect, response) = ui.allocate_exact_size(Vec2::splat(16.0), Sense::click());
        crate::ui::icons::paint(ui.painter(), rect, theme.color("ui.icon.default"), glyph);
        if response.clicked() {
            commands.push(command);
        }
        response.on_hover_text(tooltip);
        ui.allocate_space(Vec2::new(4.0, 0.0));
    }
}

fn detail_pane(app: &mut App, ui: &mut Ui, commands: &mut Vec<DashboardCommand>) {
    let Some(task) = app.dashboard.selected_task(&app.workspace).cloned() else {
        dashboard_empty(
            ui,
            &app.theme,
            "No task selected",
            "Select a task on the left to inspect its details.",
        );
        return;
    };
    if app.dashboard.task_views.task != Some(task.id) {
        app.dashboard.task_views = TaskViews { task: Some(task.id), ..Default::default() };
    }
    let theme = app.theme.clone();
    ui.vertical(|ui| {
        ui.horizontal(|ui| {
            heading(ui, &theme, &task.name);
            let (star_rect, star_resp) =
                ui.allocate_exact_size(Vec2::splat(13.0), Sense::click());
            crate::ui::icons::paint(
                ui.painter(),
                star_rect,
                theme.color("icon.link"),
                Glyph::Star,
            );
            let rate = ui.add(
                egui::Button::new(
                    egui::RichText::new("Rate this at GitHub")
                        .color(theme.color("icon.link"))
                        .underline(),
                )
                .frame(false),
            );
            rate.widget_info(|| {
                egui::WidgetInfo::labeled(egui::WidgetType::Button, true, "Rate this at GitHub")
            });
            if star_resp.clicked()
                || rate
                    .on_hover_text("Enjoying Gulpsuite? Star https://github.com/Aryma-f4/gulpsuite on GitHub!")
                    .clicked()
            {
                ui.ctx().open_url(egui::OpenUrl::new_tab(
                    "https://github.com/Aryma-f4/gulpsuite",
                ));
                app.status =
                    "Opened https://github.com/Aryma-f4/gulpsuite — Star Gulpsuite on GitHub!"
                        .into();
            }
            ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                if app.shell.detail_location != crate::ui::shell::DetailLocation::Detached
                    && ui.button("Detach").clicked()
                {
                    commands.push(DashboardCommand::Detach(task.id));
                }
                pane_icons(ui, &theme, commands);
            });
        });
        ui.add_space(45.0);
        app.tab_row(
            ui,
            crate::ui::app::TOOL_VIEWS[crate::ui::app::SUITE],
            false,
            30.0,
        );
        match app.view {
            0 => summary(app, ui, &task),
            1 => audit_items(app, ui, &task),
            2 => draw_task_issues(app, ui, &task),
            3 => event_log(app, ui, &task),
            4 => logger(app, ui, &task),
            _ => audit_log(app, ui, &task),
        }
        if app.dashboard.show_configuration {
            let mut open = true;
            egui::Window::new("Task configuration")
                .open(&mut open)
                .resizable(false)
                .show(ui.ctx(), |ui| {
                    ui.label(format!("Task: {}", task.name));
                    ui.label(format!("Type: {}", kind_name(task.kind)));
                    ui.label(format!("Scope: {}", task_scope(&task)));
                    ui.label(format!("Configuration: {}", task.configuration));
                    ui.label(format!("State: {}", state_name(task.state)));
                });
            app.dashboard.show_configuration = open;
        }
    });
}

fn summary(app: &mut App, ui: &mut Ui, task: &Task) {
    let theme = app.theme.clone();
    let available = ui.available_height().max(420.0);
    let card = egui::Frame {
        fill: if theme.dark {
            theme.color("ui.background.2")
        } else {
            Color32::from_rgb(248, 248, 248)
        },
        stroke: egui::Stroke::NONE,
        corner_radius: egui::CornerRadius::same(4),
        inner_margin: egui::Margin::symmetric(18, 16),
        outer_margin: egui::Margin::symmetric(0, 8),
        shadow: egui::Shadow::NONE,
    };
    ui.columns(2, |columns| {
        card.show(&mut columns[0], |ui| {
            ui.set_min_height((available - 36.0).max(300.0));
            ui.horizontal(|ui| {
                let (icon, _) = ui.allocate_exact_size(Vec2::splat(14.0), Sense::hover());
                crate::ui::icons::paint(
                    ui.painter(),
                    icon,
                    theme.color("ui.icon.warning"),
                    Glyph::Warning,
                );
                heading(ui, &theme, "Most serious vulnerabilities found (live)");
                ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                    if ui
                        .link(egui::RichText::new("View all").color(theme.color("icon.link")))
                        .clicked()
                    {
                        app.view = 2;
                    }
                });
            });
            ui.separator();
            ui.add_space(5.0);
            issue_table(app, ui, task.id);
        });
        card.show(&mut columns[1], |ui| {
            ui.set_min_height((available * 0.60).max(260.0));
            ui.horizontal(|ui| {
                let (icon, _) = ui.allocate_exact_size(Vec2::splat(14.0), Sense::hover());
                crate::ui::icons::paint(
                    ui.painter(),
                    icon,
                    theme.color("ui.icon.default"),
                    Glyph::Gear,
                );
                heading(ui, &theme, "Task configuration");
                ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                    if ui
                        .link(
                            egui::RichText::new("View configuration")
                                .color(theme.color("icon.link")),
                        )
                        .clicked()
                    {
                        app.dashboard.show_configuration = true;
                    }
                });
            });
            ui.separator();
            egui::Grid::new(("task-configuration", task.id.0))
                .num_columns(2)
                .spacing([24.0, 9.0])
                .show(ui, |ui| {
                    ui.label(egui::RichText::new("Task type:").strong());
                    ui.label(kind_name(task.kind));
                    ui.end_row();
                    ui.label(egui::RichText::new("Scope:").strong());
                    ui.label(task_scope(task));
                    ui.end_row();
                    ui.label(egui::RichText::new("Configuration:").strong());
                    ui.label(&task.configuration);
                    ui.end_row();
                    ui.label(egui::RichText::new(task_activity_label(task)).strong());
                    let mut active = task.state == TaskState::Running;
                    let can_toggle = task_can_toggle(task) || task.kind == TaskKind::Scan;
                    let toggle = ui
                        .add_enabled_ui(can_toggle, |ui| {
                            switch(ui, &mut active, theme.color("palette.secondary.core"))
                        })
                        .inner;
                    if toggle.clicked() {
                        let command = if active {
                            DashboardCommand::Resume(task.id)
                        } else {
                            DashboardCommand::Pause(task.id)
                        };
                        apply_command(app, command);
                    }
                    ui.end_row();
                });
            ui.add_space(42.0);
            ui.horizontal(|ui| {
                let (icon, _) = ui.allocate_exact_size(Vec2::splat(14.0), Sense::hover());
                crate::ui::icons::paint(
                    ui.painter(),
                    icon,
                    theme.color("ui.icon.default"),
                    Glyph::Clock,
                );
                heading(ui, &theme, "Task progress");
            });
            ui.separator();
            let is_running = task.kind == TaskKind::Scan
                && (task.state == TaskState::Running || app.panels.scanner.running);
            if is_running {
                let ratio = if let Some(tot) = task.progress.total.filter(|t| *t > 0) {
                    (task.progress.completed as f32 / tot as f32).clamp(0.12, 1.0)
                } else {
                    (app.panels.scanner.completed_steps as f32
                        / app.panels.scanner.total_steps.max(1) as f32)
                        .clamp(0.15, 0.96)
                };
                ui.horizontal(|ui| {
                    super::scanner::paint_gulp_spinner(
                        ui,
                        Vec2::new(14.0, 14.0),
                        Color32::from_rgb(0x5B, 0x4F, 0xFF),
                    );
                    super::scanner::paint_launcher_icon(
                        ui,
                        Vec2::new(14.0, 14.0),
                        theme.color("ui.icon.default"),
                        super::scanner::LauncherIcon::ScanDetails,
                    );
                    super::scanner::paint_gulp_progress_bar_animated(
                        ui,
                        150.0,
                        ratio,
                        true,
                        &theme,
                    );
                    let pct = (ratio * 100.0).round() as u32;
                    ui.label(egui::RichText::new(format!("{pct:>2}%")).monospace().strong());
                    let status_lbl = if !task.progress.status.is_empty() {
                        task.progress.status.as_str()
                    } else {
                        "Auditing"
                    };
                    let short_status = if status_lbl.chars().count() > 26 {
                        let mut s: String = status_lbl.chars().take(25).collect();
                        s.push('…');
                        s
                    } else {
                        status_lbl.to_string()
                    };
                    ui.add(
                        egui::Label::new(egui::RichText::new(short_status).size(11.5).strong())
                            .truncate(),
                    )
                    .on_hover_text(status_lbl);
                });
                ui.add_space(6.0);
            }
            egui::Grid::new(("task-progress", task.id.0))
                .num_columns(4)
                .spacing([18.0, 8.0])
                .show(ui, |ui| {
                    ui.label(egui::RichText::new("Total audit items:").strong());
                    ui.label(
                        task.progress
                            .total
                            .unwrap_or(task.progress.completed)
                            .to_string(),
                    );
                    ui.label(egui::RichText::new("Requests:").strong());
                    ui.label("—");
                    ui.end_row();
                    ui.label(egui::RichText::new("Audit items pending:").strong());
                    ui.label(
                        task.progress
                            .total
                            .map(|total| total.saturating_sub(task.progress.completed).to_string())
                            .unwrap_or_else(|| "—".into()),
                    );
                    ui.label(egui::RichText::new("Network errors:").strong());
                    ui.label("—");
                    ui.end_row();
                    ui.label(egui::RichText::new("Audit items in progress:").strong());
                    ui.label("—");
                    ui.end_row();
                    ui.label(egui::RichText::new("Audit items completed:").strong());
                    ui.label(task.progress.completed.to_string());
                    ui.end_row();
                });
        });
        card.show(&mut columns[1], |ui| {
            let log_card_h = (available * 0.34).max(140.0);
            ui.set_min_height(log_card_h);
            ui.horizontal(|ui| {
                let (icon, _) = ui.allocate_exact_size(Vec2::splat(14.0), Sense::hover());
                crate::ui::icons::paint(
                    ui.painter(),
                    icon,
                    theme.color("ui.icon.default"),
                    Glyph::Clock,
                );
                heading(ui, &theme, "Task log");
            });
            ui.separator();
            let mut events: Vec<_> = app
                .workspace
                .events
                .iter()
                .filter(|event| event.task_id == Some(task.id))
                .collect();
            if events.is_empty() {
                events = app.workspace.events.iter().collect();
            }
            if events.is_empty() {
                muted(ui, &theme, "No task events yet.");
            } else {
                let scroll_h = (log_card_h - 38.0).max(90.0);
                egui::ScrollArea::vertical()
                    .id_salt(("dashboard-task-log-scroll", task.id.0))
                    .max_height(scroll_h)
                    .auto_shrink([false, false])
                    .show(ui, |ui| {
                        for event in events.iter().rev() {
                            ui.label(format!("{}  {}", event.source, event.message));
                        }
                    });
            }
        });
    });
}

fn issue_table(app: &mut App, ui: &mut Ui, task_id: TaskId) {
    let theme = app.theme.clone();
    let issues = task_issues(&app.workspace, task_id);
    egui::Frame::new()
        .stroke(egui::Stroke::new(1.0_f32, theme.color("ui.border.1")))
        .show(ui, |ui| {
            ui.set_min_height(ui.available_height().max(300.0) - 28.0);
            let total_w = ui.available_width().max(260.0);
            let w_type = total_w * 0.54;
            let w_host = total_w * 0.28;
            let w_time = (total_w - w_type - w_host).max(56.0);
            let body_fg = theme.color("ui.text.body");

            let (hdr_r, _) = ui.allocate_exact_size(Vec2::new(total_w, 28.0), Sense::hover());
            ui.painter()
                .rect_filled(hdr_r, 0.0, theme.color("ui.background.3"));
            for (hx, cw, label) in [
                (hdr_r.left(), w_type, "Issue type"),
                (hdr_r.left() + w_type, w_host, "Host"),
                (hdr_r.left() + w_type + w_host, w_time, "Time (UTC)"),
            ] {
                let cr = egui::Rect::from_min_size(egui::pos2(hx, hdr_r.top()), Vec2::new(cw, 28.0));
                let clip_p = ui
                    .painter()
                    .with_clip_rect(cr.shrink2(egui::vec2(4.0, 0.0)).intersect(ui.clip_rect()));
                clip_p.text(
                    egui::pos2(cr.left() + 10.0, cr.center().y),
                    egui::Align2::LEFT_CENTER,
                    label,
                    FontId::proportional(12.0),
                    body_fg,
                );
            }
            if issues.is_empty() {
                ui.add_space((ui.available_height() * 0.35).max(80.0));
                ui.vertical_centered(|ui| {
                    if !super::dashboard_icons::paint(ui, theme.dark, "no-search-results", 106.0) {
                        empty_illustration(ui, theme.color("palette.secondary.core"));
                    }
                    ui.add_space(24.0);
                    ui.label(egui::RichText::new("No issues to show").strong().size(20.0));
                    ui.add_space(20.0);
                    muted(
                        ui,
                        &theme,
                        "Any issues found during the audit will be displayed here.",
                    );
                });
            } else {
                let mut jump_to_issue: Option<String> = None;
                let scroll_h = (ui.available_height() - 12.0).max(180.0);
                egui::ScrollArea::vertical()
                    .id_salt(("dashboard-summary-issues-scroll", task_id.0))
                    .max_height(scroll_h)
                    .auto_shrink([false, false])
                    .show(ui, |ui| {
                        ui.spacing_mut().item_spacing.y = 0.0;
                        let row_w = ui.available_width().max(240.0);
                        let rw_type = row_w * 0.54;
                        let rw_host = row_w * 0.28;
                        let rw_time = (row_w - rw_type - rw_host).max(52.0);
                        for issue in issues.into_iter().take(128) {
                            let sev_icon = match issue.severity {
                                IssueSeverity::High => super::scanner::LauncherIcon::IssueHigh,
                                IssueSeverity::Medium => super::scanner::LauncherIcon::IssueMedium,
                                IssueSeverity::Low => super::scanner::LauncherIcon::IssueLow,
                                IssueSeverity::Info => super::scanner::LauncherIcon::IssueInfo,
                            };
                            let host = issue
                                .url
                                .split_once("://")
                                .map_or(issue.url.as_str(), |(_, rest)| rest)
                                .split('/')
                                .next()
                                .unwrap_or("");
                            let time_txt = issue_time(issue.observed_unix_ms);
                            let (row_rect, row_resp) =
                                ui.allocate_exact_size(Vec2::new(row_w, 24.0), Sense::click());
                            row_resp.widget_info(|| {
                                egui::WidgetInfo::labeled(
                                    egui::WidgetType::Button,
                                    true,
                                    &issue.name,
                                )
                            });
                            if row_resp.hovered() {
                                ui.painter().rect_filled(
                                    row_rect,
                                    0.0,
                                    theme.color("ui.background.2"),
                                );
                                ui.ctx().set_cursor_icon(egui::CursorIcon::PointingHand);
                            }

                            let c1 = egui::Rect::from_min_size(
                                row_rect.min,
                                Vec2::new(rw_type, row_rect.height()),
                            );
                            let ic_rect = egui::Rect::from_min_size(
                                egui::pos2(c1.left() + 10.0, c1.center().y - 7.0),
                                Vec2::new(14.0, 14.0),
                            );
                            super::scanner::paint_launcher_icon_in_rect(
                                ui.painter(),
                                ic_rect,
                                Color32::WHITE,
                                sev_icon,
                            );
                            ui.painter()
                                .with_clip_rect(
                                    c1.shrink2(egui::vec2(4.0, 0.0)).intersect(ui.clip_rect()),
                                )
                                .text(
                                    egui::pos2(c1.left() + 30.0, c1.center().y),
                                    egui::Align2::LEFT_CENTER,
                                    &issue.name,
                                    FontId::proportional(12.0),
                                    body_fg,
                                );

                            let c2 = egui::Rect::from_min_size(
                                egui::pos2(row_rect.left() + rw_type, row_rect.top()),
                                Vec2::new(rw_host, row_rect.height()),
                            );
                            ui.painter()
                                .with_clip_rect(
                                    c2.shrink2(egui::vec2(4.0, 0.0)).intersect(ui.clip_rect()),
                                )
                                .text(
                                    egui::pos2(c2.left() + 10.0, c2.center().y),
                                    egui::Align2::LEFT_CENTER,
                                    host,
                                    FontId::proportional(12.0),
                                    body_fg,
                                );

                            let c3 = egui::Rect::from_min_size(
                                egui::pos2(row_rect.left() + rw_type + rw_host, row_rect.top()),
                                Vec2::new(rw_time, row_rect.height()),
                            );
                            ui.painter()
                                .with_clip_rect(
                                    c3.shrink2(egui::vec2(4.0, 0.0)).intersect(ui.clip_rect()),
                                )
                                .text(
                                    egui::pos2(c3.left() + 10.0, c3.center().y),
                                    egui::Align2::LEFT_CENTER,
                                    &time_txt,
                                    FontId::proportional(12.0),
                                    body_fg,
                                );

                            if row_resp.clicked() {
                                jump_to_issue = Some(issue.name.clone());
                            }
                        }
                    });
                if let Some(target_name) = jump_to_issue {
                    if let Some(idx) = app
                        .workspace
                        .issues
                        .iter()
                        .position(|i| i.name == target_name)
                    {
                        app.panels.target_panel.selected_issue = Some(idx);
                    }
                    app.view = 2;
                }
            }
        });
}

fn audit_items(app: &App, ui: &mut Ui, task: &Task) {
    heading(ui, &app.theme, "Audit items");
    ui.horizontal_wrapped(|ui| {
        ui.label(format!("{} item(s) processed", task.progress.completed));
        if let Some(total) = task.progress.total {
            ui.label(format!("· {total} total item(s)"));
        }
        muted(ui, &app.theme, &task.progress.status);
    });
    ui.add_space(6.0);
    egui::ScrollArea::both()
        .id_salt("dashboard-audit-items-table")
        .max_height(320.0)
        .show(ui, |ui| {
            egui::Grid::new("dashboard-audit-items-grid")
                .num_columns(10)
                .min_col_width(58.0)
                .striped(true)
                .show(ui, |ui| {
                    for h in [
                        "#",
                        "Host",
                        "URL",
                        "Status",
                        "Passive phases",
                        "Active phases",
                        "JS phases",
                        "Issues",
                        "Requests",
                        "Insertion points",
                    ] {
                        ui.strong(h);
                    }
                    ui.end_row();
                    if app.panels.scanner.pages.is_empty() {
                        for (idx, tx) in app.log.iter().enumerate().take(25) {
                            let path_q = tx.path_and_query();
                            let ins_pts = if tx.has_params() { "4 / 4" } else { "1 / 1" };
                            let iss_count = app
                                .workspace
                                .issues
                                .iter()
                                .filter(|i| i.url == tx.target)
                                .count();
                            let host_full = tx.host_url();
                            let host_short = if host_full.chars().count() > 28 {
                                let mut s: String = host_full.chars().take(27).collect();
                                s.push('…');
                                s
                            } else {
                                host_full.clone()
                            };
                            let path_short = if path_q.chars().count() > 36 {
                                let mut s: String = path_q.chars().take(35).collect();
                                s.push('…');
                                s
                            } else {
                                path_q.clone()
                            };
                            ui.label((idx + 1).to_string());
                            ui.label(host_short).on_hover_text(&host_full);
                            ui.monospace(path_short).on_hover_text(&path_q);
                            ui.label("Finished");
                            ui.label("2 / 2");
                            ui.label("5 / 5");
                            ui.label("3 / 3");
                            ui.label(iss_count.to_string());
                            ui.label("1");
                            ui.label(ins_pts);
                            ui.end_row();
                        }
                    } else {
                        for (idx, (p_url, code)) in app.panels.scanner.pages.iter().enumerate() {
                            let host = p_url
                                .split_once("://")
                                .map(|(s, r)| {
                                    format!("{}://{}", s, r.split('/').next().unwrap_or(r))
                                })
                                .unwrap_or_else(|| p_url.clone());
                            let path = crate::scanner::http::path_of(p_url);
                            let iss_count = app
                                .panels
                                .scanner
                                .findings
                                .iter()
                                .filter(|f| &f.url == p_url)
                                .count();
                            let status_lbl = if app.panels.scanner.running {
                                "In progress"
                            } else {
                                "Finished"
                            };
                            let host_short = if host.chars().count() > 28 {
                                let mut s: String = host.chars().take(27).collect();
                                s.push('…');
                                s
                            } else {
                                host.clone()
                            };
                            let path_short = if path.chars().count() > 36 {
                                let mut s: String = path.chars().take(35).collect();
                                s.push('…');
                                s
                            } else {
                                path.clone()
                            };
                            ui.label((idx + 1).to_string());
                            ui.label(host_short).on_hover_text(&host);
                            ui.monospace(path_short).on_hover_text(&path);
                            ui.label(format!("{status_lbl} ({code})"));
                            ui.label("2 / 2");
                            ui.label(if app.panels.scanner.active_checks {
                                "5 / 5"
                            } else {
                                "0 / 5"
                            });
                            ui.label("3 / 3");
                            ui.label(iss_count.to_string());
                            ui.label("8");
                            ui.label(if p_url.contains('?') { "4 / 4" } else { "2 / 2" });
                            ui.end_row();
                        }
                    }
                });
        });
}

#[allow(dead_code)]
fn issues(app: &App, ui: &mut Ui, task: &Task) {
    heading(ui, &app.theme, "Issues");
    issue_table_readonly(app, ui, task.id);
}

#[allow(dead_code)]
fn issue_table_readonly(app: &App, ui: &mut Ui, task_id: TaskId) {
    let issues: Vec<_> = app
        .workspace
        .issues
        .iter()
        .filter(|issue| issue.task_id == task_id)
        .collect();
    if issues.is_empty() {
        muted(ui, &app.theme, "No issues reported for this task.");
        return;
    }
    egui::ScrollArea::vertical().show(ui, |ui| {
        for issue in issues {
            ui.label(format!(
                "{} · {} · {}",
                severity_name(issue.severity),
                issue.name,
                issue.url
            ));
        }
    });
}

fn dashboard_icon(ui: &mut Ui, theme: &crate::ui::theme::Theme, glyph: Glyph, size: f32) {
    let (rect, _) = ui.allocate_exact_size(Vec2::splat(size), Sense::hover());
    crate::ui::icons::paint(ui.painter(), rect, theme.color("ui.icon.default"), glyph);
}

fn audit_cell(
    ui: &Ui, cell: egui::Rect, id: impl std::hash::Hash, text: &str, fg: Color32, clickable: bool,
) -> egui::Response {
    let sense = if clickable { Sense::click() } else { Sense::hover() };
    let response = ui.interact(cell, ui.id().with(id), sense);
    response.widget_info(|| egui::WidgetInfo::labeled(
        if clickable { egui::WidgetType::Button } else { egui::WidgetType::Label },
        true, text,
    ));
    if ui.is_rect_visible(cell) {
        let mut job = egui::text::LayoutJob::simple_singleline(text.to_owned(), FontId::proportional(11.5), fg);
        job.wrap.max_width = (cell.width() - 10.0).max(1.0);
        job.wrap.max_rows = 1;
        job.wrap.break_anywhere = true;
        let galley = ui.fonts_mut(|font| font.layout_job(job));
        ui.painter_at(cell).galley(
            cell.left_center() + egui::vec2(5.0, -galley.size().y * 0.5), galley, fg,
        );
    }
    response.on_hover_text(text)
}

fn task_search(ui: &mut Ui, theme: &crate::ui::theme::Theme, value: &mut String, width: f32) {
    let field = ui.add(egui::TextEdit::singleline(value).hint_text("Search").desired_width(width)
        .margin(egui::Margin { left: 7, right: 22, top: 2, bottom: 2 }));
    crate::ui::icons::paint(ui.painter(),
        egui::Rect::from_center_size(field.rect.right_center() - egui::vec2(11.0, 0.0), Vec2::splat(12.0)),
        theme.color("ui.icon.default"), Glyph::Search);
}

fn task_search_tools(ui: &mut Ui, theme: &crate::ui::theme::Theme, value: &mut String) {
    ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
        ui.menu_button("⋮", |ui| {
            if ui.button("Clear search").clicked() { value.clear(); ui.close(); }
        }).response.on_hover_text("Table options");
        task_search(ui, theme, value, 124.0);
    });
}

fn task_table(
    ui: &mut Ui,
    theme: &crate::ui::theme::Theme,
    id: &'static str,
    columns: &[(&str, f32)],
    count: usize,
    height: f32,
    selected: Option<usize>,
    sort_first: Option<bool>,
    mut row_text: impl FnMut(usize) -> Vec<String>,
    empty: Option<(&str, &str)>,
) -> (Option<usize>, bool) {
    let visible_width = ui.available_width();
    let base_width = columns.iter().map(|(_, width)| *width).sum::<f32>();
    let width = visible_width.max(base_width);
    let fg = theme.color("ui.text.body");
    let stroke = egui::Stroke::new(1.0, theme.color("ui.border.1"));
    let mut clicked = None;
    let mut flip = false;
    egui::Frame::new().fill(theme.color("ui.background.1")).stroke(stroke).show(ui, |ui| {
        egui::ScrollArea::horizontal().id_salt((id, "width")).auto_shrink([false, false])
            .max_height(height).show(ui, |ui| {
            ui.spacing_mut().item_spacing.y = 0.0;
            let (head, _) = ui.allocate_exact_size(Vec2::new(width, 25.0), Sense::hover());
            ui.painter().rect_filled(head, 0.0, theme.color("ui.background.3"));
            let cell_rect = |row: egui::Rect, x: f32, size: f32|
                egui::Rect::from_min_size(egui::pos2(x, row.top()), Vec2::new(size, row.height()));
            let scale = width / base_width;
            let mut x = head.left();
            for (col, (label, basis)) in columns.iter().enumerate() {
                let size = basis * scale;
                let cell = cell_rect(head, x, size);
                let sortable = col == 0 && sort_first.is_some();
                if audit_cell(ui, cell, (id, "head", col), label, fg, sortable).clicked() && sortable {
                    flip = true;
                }
                if let Some(desc) = sort_first.filter(|_| col == 0) {
                    ui.painter().text(cell.right_center() - egui::vec2(7.0, 0.0),
                        egui::Align2::RIGHT_CENTER, if desc { "⌄" } else { "⌃" },
                        FontId::proportional(11.5), fg);
                }
                ui.painter().vline(cell.right(), head.y_range(), stroke);
                x += size;
            }
            ui.painter().hline(head.x_range(), head.bottom(), stroke);
            let body_h = (height - 25.0).max(40.0);
            if let Some((title, desc)) = empty.filter(|_| count == 0) {
                ui.allocate_ui_with_layout(Vec2::new(visible_width, body_h),
                    egui::Layout::top_down(egui::Align::Center), |ui| {
                        ui.set_min_size(Vec2::new(visible_width, body_h));
                        task_empty(ui, theme, title, desc);
                    });
            } else {
                egui::ScrollArea::vertical().id_salt((id, "rows"))
                    .max_height(body_h).auto_shrink([false, false])
                    .show_rows(ui, 20.0, count, |ui, rows| {
                        ui.set_min_width(width);
                        for r in rows {
                            let (row, _) = ui.allocate_exact_size(Vec2::new(width, 20.0), Sense::hover());
                            if selected == Some(r) || r % 2 != 0 {
                                ui.painter().rect_filled(row, 0.0, theme.color(
                                    if selected == Some(r) { "ui.background.6" } else { "ui.background.2" }));
                            }
                            let mut x = row.left();
                            for (col, (text, (_, basis))) in row_text(r).into_iter().zip(columns).enumerate() {
                                let size = basis * scale;
                                if audit_cell(ui, cell_rect(row, x, size), (id, r, col), &text, fg, true).clicked() {
                                    clicked = Some(r);
                                }
                                x += size;
                            }
                        }
                    });
            }
        });
    });
    (clicked, flip)
}

fn task_empty(ui: &mut Ui, theme: &crate::ui::theme::Theme, title: &str, desc: &str) {
    use egui::Stroke;
    let pad = (ui.available_height() * 0.29).min(ui.available_height() - 142.0).max(0.0);
    ui.add_space(pad);
    ui.vertical_centered(|ui| {
        if !super::dashboard_icons::paint(ui, theme.dark, "no-search-results", 106.0) {
            let (r, _) = ui.allocate_exact_size(Vec2::new(103.0, 73.0), Sense::hover());
            let p = ui.painter_at(r);
            let at = |x, y| r.min + egui::vec2(x, y);
            let blue = theme.color("palette.secondary.core");
            let paper = theme.color("palette.secondary.5");
            p.rect_filled(egui::Rect::from_min_size(r.min, egui::vec2(100.0, 66.0)), 6.0, paper);
            p.rect_filled(egui::Rect::from_min_size(r.min, egui::vec2(100.0, 10.0)), 4.0, blue);
            for (n, color) in [Color32::from_rgb(247, 72, 85), Color32::from_rgb(255, 132, 48),
                Color32::from_rgb(165, 199, 88)].into_iter().enumerate() {
                p.circle_filled(at(6.0 + n as f32 * 7.0, 5.0), 2.2, color);
            }
            p.circle_stroke(at(42.0, 39.0), 21.0, Stroke::new(4.5, blue));
            p.line_segment([at(57.0, 54.0), at(83.0, 68.0)], Stroke::new(8.0, blue));
            p.line_segment([at(36.0, 33.0), at(48.0, 45.0)], Stroke::new(4.0, blue));
            p.line_segment([at(48.0, 33.0), at(36.0, 45.0)], Stroke::new(4.0, blue));
        }
        ui.add_space(24.0);
        crate::ui::app::bold_text(ui, title, 16.0, theme.color("ui.text.header"));
        ui.add_space(16.0);
        ui.allocate_ui_with_layout(Vec2::new(ui.available_width().min(306.0), 0.0),
            egui::Layout::top_down(egui::Align::Center),
            |ui| { ui.label(egui::RichText::new(desc).size(12.0).color(theme.color("ui.text.body"))); });
    });
}

fn task_clock(millis: u64) -> String {
    let seconds = millis / 1_000 % 86_400;
    format!("{:02}:{:02}:{:02} UTC", seconds / 3600, seconds / 60 % 60, seconds % 60)
}

fn draw_task_issues(app: &mut App, ui: &mut Ui, task: &Task) {
    let state = &mut app.dashboard.task_views;
    let theme = &app.theme;
    egui::Frame::new().inner_margin(egui::Margin::symmetric(10, 14)).show(ui, |ui| {
        ui.horizontal(|ui| {
            dashboard_icon(ui, theme, Glyph::Funnel, 15.0);
            ui.menu_button("Filter", |ui| {
                for (name, enabled) in ["High", "Medium", "Low", "Info"].into_iter().zip(&mut state.issue_levels) {
                    ui.checkbox(enabled, name);
                }
            });
            task_search_tools(ui, theme, &mut state.issues_search);
        });
        ui.add_space(15.0);
        let search = state.issues_search.trim().to_lowercase();
        let mut rows: Vec<_> = app.workspace.issues.iter().filter(|issue| {
            let level = match issue.severity { IssueSeverity::High => 0, IssueSeverity::Medium => 1,
                IssueSeverity::Low => 2, IssueSeverity::Info => 3 };
            issue.task_id == task.id && state.issue_levels[level] &&
                (search.is_empty() || issue.name.to_lowercase().contains(&search) || issue.url.to_lowercase().contains(&search))
        }).collect();
        rows.sort_unstable_by_key(|issue| (issue.observed_unix_ms, issue.id.0));
        if state.issues_newest { rows.reverse(); }
        let selected = rows.iter().position(|issue| Some(issue.id) == state.issue);
        let available = ui.available_height();
        let height = if selected.is_some() { available * 0.55 } else { available - 4.0 };
        let (picked, flip) = task_table(ui, theme, "task-issues",
            &[("Time", 112.0), ("Source", 68.0), ("Issue type", 220.0), ("Host", 110.0),
                ("Path", 180.0), ("Insertion point", 120.0)],
            rows.len(), height.max(100.0), selected, Some(state.issues_newest),
            |i| {
                let issue = rows[i];
                let parsed = url::Url::parse(&issue.url).ok();
                let host = parsed.as_ref().and_then(|u| u.host_str()).unwrap_or("—");
                let path = parsed.as_ref().map_or(issue.url.as_str(), |u| u.path());
                vec![task_clock(issue.observed_unix_ms), kind_name(task.kind).into(),
                    issue.name.clone(), host.into(), path.into(),
                    issue.parameter.as_deref().unwrap_or("—").into()]
            },
            Some(("No issues to show", "Findings recorded for the selected task appear here.")));
        if flip { state.issues_newest = !state.issues_newest; }
        if let Some(pos) = picked { state.issue = Some(rows[pos].id); }
        if let Some(issue) = rows.iter().find(|issue| Some(issue.id) == state.issue) {
            ui.add_space(5.0);
            egui::ScrollArea::vertical().id_salt("task-issue-evidence").show(ui, |ui| {
                heading(ui, theme, &issue.name);
                ui.label(&issue.evidence);
            });
        }
    });
}

fn event_log(app: &mut App, ui: &mut Ui, task: &Task) {
    use crate::workspace::EventLevel;
    let state = &mut app.dashboard.task_views;
    let theme = &app.theme;
    egui::Frame::new().inner_margin(egui::Margin::symmetric(10, 14)).show(ui, |ui| {
        ui.horizontal_wrapped(|ui| {
            dashboard_icon(ui, theme, Glyph::Funnel, 15.0);
            ui.label("Filter");
            for (title, enabled) in ["Critical", "Error", "Info", "Debug"].into_iter().zip(&mut state.event_levels) {
                let pill = ui.add(egui::Button::new(title).selected(*enabled).corner_radius(10.0));
                if pill.on_hover_text(if title == "Error" { "Show warning and error events" } else { title }).clicked() {
                    *enabled = !*enabled;
                }
            }
            task_search_tools(ui, theme, &mut state.events_search);
        });
        ui.add_space(15.0);
        let level = |level| match level {
            EventLevel::Critical => (0, "Critical"),
            EventLevel::Error => (1, "Error"),
            EventLevel::Warning => (1, "Warning"),
            EventLevel::Info => (2, "Info"),
            EventLevel::Debug => (3, "Debug"),
        };
        let search = state.events_search.trim().to_lowercase();
        let rows: Vec<_> = app.workspace.events.iter().filter(|event| {
            event.task_id == Some(task.id) && state.event_levels[level(event.level).0] &&
                (search.is_empty() || event.message.to_lowercase().contains(&search) || event.source.to_lowercase().contains(&search))
        }).collect();
        if rows.is_empty() {
            task_empty(ui, theme, "No event log items to show", "The event log shows key task events, such as start times, alerts, and progress updates.");
            return;
        }
        let selected = rows.iter().position(|event| Some(event.id) == state.event);
        let height = ui.available_height() * if selected.is_some() { 0.65 } else { 0.97 };
        let (picked, _) = task_table(ui, theme, "task-events",
            &[("Time", 105.0), ("Level", 80.0), ("Source", 115.0), ("Message", 340.0)],
            rows.len(), height.max(100.0), selected, None,
            |i| { let event = rows[i]; vec![task_clock(event.timestamp_unix_ms),
                level(event.level).1.into(), event.source.clone(), event.message.clone()] }, None);
        if let Some(i) = picked { state.event = Some(rows[i].id); }
        if let Some(event) = rows.iter().find(|event| Some(event.id) == state.event) {
            ui.add_space(5.0);
            egui::ScrollArea::vertical().id_salt("task-event-message").show(ui, |ui| { ui.label(&event.message); });
        }
    });
}

fn logger(app: &mut App, ui: &mut Ui, task: &Task) {
    heading(ui, &app.theme, "Logger");
    muted(
        ui,
        &app.theme,
        &format!(
            "{} item(s) attributed to this task · {} total HTTP transaction(s) in Logger.",
            task.progress.completed,
            app.log.len()
        ),
    );
    ui.add_space(4.0);
    super::logger::draw_http_log(app, ui);
}

fn audit_log(app: &App, ui: &mut Ui, task: &Task) {
    heading(ui, &app.theme, "Audit log");
    let events: Vec<_> = app
        .workspace
        .events
        .iter()
        .filter(|event| event.task_id == Some(task.id))
        .filter(|event| {
            matches!(
                event.level,
                crate::workspace::EventLevel::Warning
                    | crate::workspace::EventLevel::Error
                    | crate::workspace::EventLevel::Critical
            )
        })
        .collect();
    if events.is_empty() {
        muted(ui, &app.theme, "No audit warnings or errors.");
    } else {
        let avail_h = (ui.available_height() - 16.0).max(160.0);
        egui::ScrollArea::vertical()
            .id_salt(("dashboard-audit-log-tab-scroll", task.id.0))
            .max_height(avail_h)
            .auto_shrink([false, false])
            .show(ui, |ui| {
                for event in events.into_iter().rev() {
                    ui.label(format!("{}  {}", event.source, event.message));
                }
            });
    }
}

fn apply_command(app: &mut App, command: DashboardCommand) {
    match command {
        DashboardCommand::NewScan => {
            if app.panels.scanner.seed == "http://127.0.0.1:8080/" {
                if let Some(latest) = app
                    .log
                    .iter()
                    .rev()
                    .find(|tx| {
                        tx.target.starts_with("http://") || tx.target.starts_with("https://")
                    })
                    .map(|tx| tx.target.clone())
                {
                    app.panels.scanner.seed = latest.clone();
                    app.panels.scanner.urls_to_scan = latest;
                }
            }
            app.panels.scanner.show_launcher = true;
            app.panels.scanner.launcher_tab = 0;
            app.status = "Opened New scan launcher".into();
        }
        DashboardCommand::NewLiveTask => {
            let id = app.workspace.tasks.create(
                TaskKind::LiveAudit,
                "Live audit from Proxy (all traffic)",
                "Audit checks - passive",
                now_ms(),
            );
            let _ = app.workspace.tasks.start(id);
            let _ = app.workspace.tasks.select(id);
            app.status = "New live audit task created".into();
        }
        DashboardCommand::Select(id) => {
            if let Err(error) = app.workspace.tasks.select(id) {
                app.status = error.to_string();
            }
        }
        DashboardCommand::Rename(id, name) => match app.workspace.tasks.rename(id, &name) {
            Ok(()) => {
                app.dashboard.rename_task = None;
                app.status = "Task renamed".into();
            }
            Err(error) => app.status = error.to_string(),
        },
        DashboardCommand::Pause(id) => {
            let is_scan = app
                .workspace
                .tasks
                .get(id)
                .is_some_and(|t| t.kind == TaskKind::Scan);
            match app.workspace.tasks.pause(id) {
                Ok(()) => {
                    if app.panels.intruder.task_id == Some(id) {
                        if let Some(control) = &app.panels.intruder.control {
                            control.pause();
                        }
                    }
                    if is_scan {
                        app.panels.scanner.running = false;
                        app.scanner_updates = None;
                    }
                    app.status = "Task paused".into();
                }
                Err(error) => app.status = error.to_string(),
            }
        }
        DashboardCommand::Resume(id) => {
            let scan_scope = app
                .workspace
                .tasks
                .get(id)
                .filter(|t| t.kind == TaskKind::Scan)
                .map(|t| t.scope.clone());
            match app.workspace.tasks.resume(id) {
                Ok(()) => {
                    if app.panels.intruder.task_id == Some(id) {
                        if let Some(control) = &app.panels.intruder.control {
                            control.resume();
                        }
                    }
                    if let Some(scope) = scan_scope {
                        if !scope.trim().is_empty() && scope.starts_with("http") {
                            app.panels.scanner.seed = scope.clone();
                            app.panels.scanner.urls_to_scan = scope;
                        }
                        if !app.panels.scanner.running {
                            super::scanner::start(app);
                        }
                    }
                    app.status = "Task resumed".into();
                }
                Err(_) if scan_scope.is_some() => {
                    // Restart a completed/cancelled scan task when its toggle switch is clicked
                    if let Some(scope) = scan_scope {
                        if !scope.trim().is_empty() && scope.starts_with("http") {
                            app.panels.scanner.seed = scope.clone();
                            app.panels.scanner.urls_to_scan = scope;
                        }
                    }
                    super::scanner::start(app);
                }
                Err(error) => app.status = error.to_string(),
            }
        }
        DashboardCommand::Cancel(id) => match app.workspace.tasks.cancel(id) {
            Ok(()) => {
                if app.panels.intruder.task_id == Some(id) {
                    if let Some(control) = &app.panels.intruder.control {
                        control.cancel();
                    }
                }
                if app
                    .workspace
                    .tasks
                    .get(id)
                    .is_some_and(|task| task.kind == TaskKind::Scan)
                {
                    app.panels.scanner.running = false;
                }
                app.status = "Task cancelled".into();
            }
            Err(error) => app.status = error.to_string(),
        },
        DashboardCommand::Detach(id) => {
            let _ = app.workspace.tasks.select(id);
            app.shell.detach(id);
            app.status = "Task details detached".into();
        }
        DashboardCommand::ShowSettings => app.show_settings = true,
        DashboardCommand::ShowHelp => {
            app.status = "Dashboard help: create, filter, select, and control tasks here".into()
        }
    }
}

fn dashboard_empty(ui: &mut Ui, theme: &crate::ui::theme::Theme, title: &str, message: &str) {
    ui.add_space(32.0);
    ui.vertical_centered(|ui| {
        empty_illustration(ui, theme.color("palette.secondary.core"));
        ui.label(egui::RichText::new(title).strong());
        ui.label(egui::RichText::new(message).color(theme.color("ui.text.disabled")));
    });
}

fn empty_illustration(ui: &mut Ui, colour: Color32) {
    let (rect, _) = ui.allocate_exact_size(Vec2::new(140.0, 84.0), Sense::hover());
    let painter = ui.painter_at(rect);
    for (dx, dy, angle) in [(-28.0, 4.0, -0.3_f32), (0.0, -14.0, 0.0), (28.0, 12.0, 0.3)] {
        let center = rect.center() + Vec2::new(dx, dy);
        let (sin, cos) = angle.sin_cos();
        let corner = |x: f32, y: f32| center + Vec2::new(x * cos - y * sin, x * sin + y * cos);
        painter.add(egui::Shape::convex_polygon(
            vec![
                corner(-18.0, -11.0),
                corner(18.0, -11.0),
                corner(18.0, 11.0),
                corner(-18.0, 11.0),
            ],
            colour,
            egui::Stroke::NONE,
        ));
        painter.line_segment(
            [corner(-19.0, 0.0), corner(19.0, 0.0)],
            egui::Stroke::new(2.0, Color32::WHITE),
        );
    }
}

fn switch(ui: &mut Ui, on: &mut bool, accent: Color32) -> egui::Response {
    let (rect, response) = ui.allocate_exact_size(Vec2::new(30.0, 16.0), Sense::click());
    if response.clicked() {
        *on = !*on;
    }
    let painter = ui.painter_at(rect);
    painter.rect_filled(
        rect,
        8.0,
        if *on {
            accent
        } else {
            ui.visuals().widgets.inactive.bg_fill
        },
    );
    let knob = if *on {
        egui::pos2(rect.max.x - 8.0, rect.center().y)
    } else {
        egui::pos2(rect.min.x + 8.0, rect.center().y)
    };
    painter.circle_filled(knob, 5.5, Color32::WHITE);
    response
}

fn issue_pill(ui: &mut Ui, count: usize, colour: Color32) {
    let text = count.to_string();
    let font = FontId::proportional(10.0);
    let galley = ui
        .painter()
        .layout_no_wrap(text.clone(), font.clone(), Color32::WHITE);
    let (rect, _) = ui.allocate_exact_size(Vec2::new(galley.size().x + 14.0, 16.0), Sense::hover());
    ui.painter().rect_filled(rect, 8.0, colour);
    ui.painter().text(
        rect.center(),
        egui::Align2::CENTER_CENTER,
        text,
        font,
        Color32::WHITE,
    );
}

fn state_name(state: TaskState) -> &'static str {
    match state {
        TaskState::Queued => "Queued",
        TaskState::Running => "Running",
        TaskState::Paused => "Paused",
        TaskState::Completed => "Completed",
        TaskState::Failed => "Failed",
        TaskState::Cancelled => "Cancelled",
        TaskState::Interrupted => "Interrupted",
    }
}

fn task_scope(task: &Task) -> &str {
    if matches!(task.kind, TaskKind::LiveAudit | TaskKind::PassiveCrawl) {
        "Proxy (all traffic)"
    } else if task.scope.trim().is_empty() {
        "Not specified"
    } else {
        &task.scope
    }
}

fn task_issues(workspace: &Workspace, task_id: TaskId) -> Vec<&IssueRecord> {
    let mut issues: Vec<_> = workspace
        .issues
        .iter()
        .filter(|issue| issue.task_id == task_id)
        .collect();
    issues.sort_by_key(|issue| std::cmp::Reverse((issue.severity, issue.observed_unix_ms)));
    issues
}

fn issue_time(unix_ms: u64) -> String {
    let seconds = unix_ms / 1000;
    format!(
        "{:02}:{:02}:{:02}",
        seconds / 3600 % 24,
        seconds / 60 % 60,
        seconds % 60
    )
}

fn task_activity_label(task: &Task) -> &'static str {
    if matches!(task.kind, TaskKind::LiveAudit | TaskKind::PassiveCrawl)
        && task.state == TaskState::Running
    {
        "Capturing"
    } else {
        state_name(task.state)
    }
}

fn task_can_toggle(task: &Task) -> bool {
    matches!(task.state, TaskState::Running | TaskState::Paused)
}

fn kind_name(kind: TaskKind) -> &'static str {
    match kind {
        TaskKind::PassiveCrawl => "Passive crawl",
        TaskKind::LiveAudit => "Live audit",
        TaskKind::Scan => "Scan",
        TaskKind::Intruder => "Intruder",
        TaskKind::Discover => "Discover",
        TaskKind::Other => "Other",
    }
}

fn severity_name(severity: IssueSeverity) -> &'static str {
    match severity {
        IssueSeverity::Info => "Info",
        IssueSeverity::Low => "Low",
        IssueSeverity::Medium => "Medium",
        IssueSeverity::High => "High",
    }
}

fn now_ms() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis() as u64
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::workspace::{IssueRecord, TaskManager};

    fn seeded() -> Workspace {
        Workspace {
            tasks: TaskManager::seed_proxy_tasks(),
            ..Workspace::default()
        }
    }

    #[test]
    fn seeded_ordering_is_live_audit_then_passive_crawl() {
        let workspace = seeded();
        let state = DashboardState::default();
        assert_eq!(
            state.visible_task_ids(&workspace),
            vec![TaskId(2), TaskId(1)]
        );
    }

    #[test]
    fn task_activity_reflects_kind_and_only_toggleable_states() {
        let mut workspace = seeded();
        let live = workspace.tasks.get(TaskId(2)).unwrap();
        assert_eq!(task_activity_label(live), "Capturing");
        assert!(task_can_toggle(live));
        let scan = workspace
            .tasks
            .create(TaskKind::Scan, "Scan", "example.test", 1);
        let queued = workspace.tasks.get(scan).unwrap();
        assert_eq!(task_activity_label(queued), "Queued");
        assert!(!task_can_toggle(queued));
        workspace.tasks.start(scan).unwrap();
        let running = workspace.tasks.get(scan).unwrap();
        assert_eq!(task_activity_label(running), "Running");
        assert!(task_can_toggle(running));
    }

    #[test]
    fn most_serious_issues_sort_severity_before_time_and_keep_task_identity() {
        let mut workspace = seeded();
        for (task, severity, name, time) in [
            (TaskId(2), IssueSeverity::Low, "new low", 10_000),
            (TaskId(2), IssueSeverity::High, "older high", 1_000),
            (TaskId(2), IssueSeverity::High, "newer high", 2_000),
            (TaskId(1), IssueSeverity::High, "other task", 20_000),
        ] {
            workspace.issues.upsert(IssueRecord::new(
                task,
                name,
                severity,
                "Certain",
                format!("https://example.test/{name}"),
                None,
                "",
                time,
            ));
        }
        let names: Vec<_> = task_issues(&workspace, TaskId(2))
            .iter()
            .map(|issue| issue.name.as_str())
            .collect();
        assert_eq!(names, ["newer high", "older high", "new low"]);
        assert_eq!(issue_time(3_661_000), "01:01:01");
    }

    #[test]
    fn search_and_filters_are_combined_and_persist() {
        let workspace = seeded();
        let mut state = DashboardState::default();
        state.search = "audit".into();
        state.kinds.insert(TaskKind::LiveAudit);
        assert_eq!(state.visible_task_ids(&workspace), vec![TaskId(2)]);
        assert_eq!(state.search, "audit");
        assert_eq!(state.visible_task_ids(&workspace), vec![TaskId(2)]);
        assert_eq!(
            state.search, "audit",
            "search must survive another frame/query"
        );
    }

    #[test]
    fn selected_task_details_come_from_workspace() {
        let workspace = seeded();
        let state = DashboardState::default();
        let detail = state.selected_task(&workspace).expect("selected task");
        assert_eq!(detail.id, TaskId(2));
        assert_eq!(detail.configuration, "Audit checks - passive");
    }

    #[test]
    fn live_issue_counters_are_scoped_to_the_task() {
        let mut workspace = seeded();
        for (index, severity) in [IssueSeverity::High, IssueSeverity::High, IssueSeverity::Low]
            .into_iter()
            .enumerate()
        {
            workspace.issues.upsert(IssueRecord::new(
                TaskId(2),
                "issue",
                severity,
                "Firm",
                "https://a.test/",
                None,
                format!("{severity:?}-{index}"),
                1,
            ));
        }
        let counts = issue_counts(&workspace, TaskId(2));
        assert_eq!(counts.high, 2);
        assert_eq!(counts.low, 1);
        assert_eq!(counts.medium, 0);
    }

    #[test]
    fn rename_validation_and_controls_follow_task_state() {
        let mut workspace = seeded();
        assert!(workspace.tasks.rename(TaskId(2), "   ").is_err());
        workspace.tasks.rename(TaskId(2), "renamed").unwrap();
        assert_eq!(workspace.tasks.get(TaskId(2)).unwrap().name, "renamed");
        let running = controls_for(TaskState::Running);
        assert!(running.pause && !running.resume && running.cancel);
        workspace.tasks.pause(TaskId(2)).unwrap();
        let paused = controls_for(TaskState::Paused);
        assert!(!paused.pause && paused.resume && paused.cancel);
        workspace.tasks.complete(TaskId(2)).unwrap();
        let completed = controls_for(TaskState::Completed);
        assert!(!completed.pause && !completed.resume && !completed.cancel);
    }

    #[test]
    fn empty_states_distinguish_no_tasks_from_zero_results() {
        let state = DashboardState::default();
        assert_eq!(
            state.empty_state(&Workspace::default()),
            DashboardEmpty::NoTasks
        );
        let workspace = seeded();
        let mut filtered = DashboardState::default();
        filtered.search = "nothing matches this".into();
        assert_eq!(filtered.empty_state(&workspace), DashboardEmpty::NoMatches);
        assert_eq!(state.empty_state(&workspace), DashboardEmpty::Populated);
    }
}
