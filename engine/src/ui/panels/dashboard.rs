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
    let split = crate::ui::reference::burp_2026_3_3().dashboard.split_ratio;
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
                    commands.push(DashboardCommand::Rename(
                        task.id,
                        app.dashboard.rename_text.clone(),
                    ));
                }
                if ui.button("Cancel").clicked() {
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
                task_menu(app, ui, task, commands);
            });
        });
        ui.label(egui::RichText::new(&task.configuration).color(theme.color("ui.text.disabled")));
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
            super::scanner::paint_burp_progress_bar_animated(ui, 185.0, ratio, is_running, &theme);
            ui.add_space(4.0);
            ui.horizontal(|ui| {
                if is_running {
                    super::scanner::paint_burp_spinner(
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
                    egui::Label::new(egui::RichText::new(short_status).size(11.5)).truncate(),
                )
                .on_hover_text(status_lbl);
            });
            ui.add_space(4.0);
        } else {
            ui.add_space(17.0);
        }
        ui.horizontal(|ui| {
            ui.label(task_activity_label(task));
            let mut active = task.state == TaskState::Running;
            let toggle = ui
                .add_enabled_ui(task_can_toggle(task), |ui| switch(ui, &mut active, accent))
                .inner;
            if toggle.clicked() {
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
                ui.label("Issues:");
            });
        });
        ui.add_space(32.0);
    });
    if response.response.clicked() {
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

fn task_menu(app: &mut App, ui: &mut Ui, task: &Task, commands: &mut Vec<DashboardCommand>) {
    let controls = controls_for(task.state);
    let dot_col = app.theme.color("ui.icon.default");
    let menu = ui.menu_button("   ", |ui| {
        if controls.pause && ui.button("Pause").clicked() {
            commands.push(DashboardCommand::Pause(task.id));
            ui.close();
        }
        if controls.resume && ui.button("Resume").clicked() {
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
    let theme = app.theme.clone();
    ui.vertical(|ui| {
        ui.horizontal(|ui| {
            let (icon, _) = ui.allocate_exact_size(Vec2::splat(14.0), Sense::hover());
            crate::ui::icons::paint(
                ui.painter(),
                icon,
                theme.color("ui.icon.default"),
                Glyph::Diamond,
            );
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
                    egui::RichText::new("Rate this scan")
                        .color(theme.color("icon.link"))
                        .underline(),
                )
                .frame(false),
            );
            rate.widget_info(|| {
                egui::WidgetInfo::labeled(egui::WidgetType::Button, true, "Rate this scan")
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
            2 => super::target::draw_issues_view(app, ui),
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
                    Glyph::Diamond,
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
                    let toggle = ui
                        .add_enabled_ui(task_can_toggle(task), |ui| {
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
                    super::scanner::paint_burp_spinner(
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
                    super::scanner::paint_burp_progress_bar_animated(
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

            egui::Frame::new()
                .fill(theme.color("ui.background.3"))
                .inner_margin(egui::Margin::symmetric(10, 7))
                .show(ui, |ui| {
                    ui.horizontal(|ui| {
                        ui.spacing_mut().item_spacing.x = 0.0;
                        ui.allocate_ui(Vec2::new(w_type, 18.0), |ui| {
                            ui.set_min_width(w_type);
                            ui.label(egui::RichText::new("Issue type").strong());
                        });
                        ui.allocate_ui(Vec2::new(w_host, 18.0), |ui| {
                            ui.set_min_width(w_host);
                            ui.label(egui::RichText::new("Host").strong());
                        });
                        ui.allocate_ui(Vec2::new(w_time, 18.0), |ui| {
                            ui.set_min_width(w_time);
                            ui.label(egui::RichText::new("Time (UTC)").strong());
                        });
                    });
                });
            if issues.is_empty() {
                ui.add_space((ui.available_height() * 0.35).max(80.0));
                ui.vertical_centered(|ui| {
                    empty_illustration(ui, theme.color("palette.secondary.core"));
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
                egui::Frame::new()
                    .inner_margin(egui::Margin::symmetric(10, 4))
                    .show(ui, |ui| {
                        egui::ScrollArea::vertical()
                            .id_salt(("dashboard-summary-issues-scroll", task_id.0))
                            .max_height(scroll_h)
                            .auto_shrink([false, false])
                            .show(ui, |ui| {
                                for issue in issues.into_iter().take(128) {
                                    let sev_icon = match issue.severity {
                                        IssueSeverity::High => {
                                            super::scanner::LauncherIcon::IssueHigh
                                        }
                                        IssueSeverity::Medium => {
                                            super::scanner::LauncherIcon::IssueMedium
                                        }
                                        IssueSeverity::Low => {
                                            super::scanner::LauncherIcon::IssueLow
                                        }
                                        IssueSeverity::Info => {
                                            super::scanner::LauncherIcon::IssueInfo
                                        }
                                    };
                                    let host = issue
                                        .url
                                        .split_once("://")
                                        .map_or(issue.url.as_str(), |(_, rest)| rest)
                                        .split('/')
                                        .next()
                                        .unwrap_or("");
                                    let time_txt = issue_time(issue.observed_unix_ms);
                                    ui.horizontal(|ui| {
                                        ui.spacing_mut().item_spacing.x = 0.0;
                                        let r1 = ui
                                            .allocate_ui(Vec2::new(w_type, 22.0), |ui| {
                                                ui.set_min_width(w_type);
                                                ui.horizontal(|ui| {
                                                    ui.spacing_mut().item_spacing.x = 6.0;
                                                    super::scanner::paint_launcher_icon(
                                                        ui,
                                                        Vec2::new(14.0, 14.0),
                                                        Color32::WHITE,
                                                        sev_icon,
                                                    );
                                                    ui.add(
                                                        egui::Label::new(
                                                            egui::RichText::new(&issue.name)
                                                                .size(12.0),
                                                        )
                                                        .truncate()
                                                        .sense(Sense::click()),
                                                    )
                                                })
                                                .inner
                                            })
                                            .inner;
                                        let r2 = ui
                                            .allocate_ui(Vec2::new(w_host, 22.0), |ui| {
                                                ui.set_min_width(w_host);
                                                ui.add(
                                                    egui::Label::new(
                                                        egui::RichText::new(host).size(12.0),
                                                    )
                                                    .truncate()
                                                    .sense(Sense::click()),
                                                )
                                            })
                                            .inner;
                                        let r3 = ui
                                            .allocate_ui(Vec2::new(w_time, 22.0), |ui| {
                                                ui.set_min_width(w_time);
                                                ui.add(
                                                    egui::Label::new(
                                                        egui::RichText::new(time_txt).size(12.0),
                                                    )
                                                    .truncate()
                                                    .sense(Sense::click()),
                                                )
                                            })
                                            .inner;
                                        if r1.clicked() || r2.clicked() || r3.clicked() {
                                            jump_to_issue = Some(issue.name.clone());
                                        }
                                    });
                                }
                            });
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

fn event_log(app: &App, ui: &mut Ui, task: &Task) {
    heading(ui, &app.theme, "Event log");
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
        muted(ui, &app.theme, "No events recorded for this task.");
        return;
    }
    let avail_h = (ui.available_height() - 16.0).max(160.0);
    egui::ScrollArea::vertical()
        .id_salt(("dashboard-event-log-tab-scroll", task.id.0))
        .max_height(avail_h)
        .auto_shrink([false, false])
        .show(ui, |ui| {
            for event in events.into_iter().rev() {
                ui.label(format!("{}  {}", event.source, event.message));
            }
        });
}

fn logger(app: &App, ui: &mut Ui, task: &Task) {
    heading(ui, &app.theme, "Logger");
    muted(
        ui,
        &app.theme,
        &format!(
            "{} item(s) attributed to this task.",
            task.progress.completed
        ),
    );
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
        DashboardCommand::Pause(id) => match app.workspace.tasks.pause(id) {
            Ok(()) => {
                if app.panels.intruder.task_id == Some(id) {
                    if let Some(control) = &app.panels.intruder.control {
                        control.pause();
                    }
                }
                app.status = "Task paused".into();
            }
            Err(error) => app.status = error.to_string(),
        },
        DashboardCommand::Resume(id) => match app.workspace.tasks.resume(id) {
            Ok(()) => {
                if app.panels.intruder.task_id == Some(id) {
                    if let Some(control) = &app.panels.intruder.control {
                        control.resume();
                    }
                }
                app.status = "Task resumed".into();
            }
            Err(error) => app.status = error.to_string(),
        },
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
