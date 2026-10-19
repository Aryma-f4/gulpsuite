use eframe::egui::Vec2;
use egui_kittest::{kittest::Queryable, Harness, OsThreshold, SnapshotOptions};
use gulpsuite::ui::app::App;
use gulpsuite::workspace::{EventLevel, IssueRecord, IssueSeverity, TaskId, TaskKind, TaskState};

fn harness(dark: bool, width: f32) -> Harness<'static, App> {
    let mut harness = Harness::builder()
        .with_size(Vec2::new(width, 790.0))
        .build_eframe(|cc| {
            let mut app = App::with_context(&cc.egui_ctx);
            app.set_dark(dark);
            let scan = app.workspace.tasks.create(
                TaskKind::Scan,
                "3. Scan of example.test",
                "example.test",
                1,
            );
            app.workspace.tasks.start(scan).unwrap();
            app.workspace.tasks.complete(scan).unwrap();
            for (severity, name) in [
                (IssueSeverity::High, "SQL injection"),
                (IssueSeverity::Medium, "Cross-site scripting"),
                (IssueSeverity::Low, "Missing security header"),
                (IssueSeverity::Info, "Technology disclosure"),
            ] {
                app.workspace.issues.upsert(IssueRecord::new(
                    TaskId(2),
                    name,
                    severity,
                    "Certain",
                    "https://example.test/",
                    None,
                    "Deterministic parity fixture",
                    1,
                ));
            }
            for level in [EventLevel::Info, EventLevel::Warning, EventLevel::Error] {
                app.workspace.events.push(
                    1,
                    level,
                    "Parity fixture",
                    "Task event",
                    Some(TaskId(2)),
                );
            }
            app.memory_text = "Memory: 64MB of 8.00GB".into();
            app.memory_checked = std::time::Instant::now();
            app
        });
    harness.run();
    harness
}

#[test]
fn dashboard_actions_change_task_state() {
    let mut harness = harness(true, 1440.0);
    assert_eq!(harness.state().workspace.tasks.len(), 3);
    harness.get_by_label("New live task").click();
    harness.run();
    assert_eq!(harness.state().workspace.tasks.len(), 4);
    assert!(harness
        .state()
        .workspace
        .tasks
        .iter()
        .any(|task| task.state == TaskState::Running));
}

#[test]
fn tool_tabs_are_accessible_and_switch_panels() {
    let mut harness = harness(true, 1440.0);
    harness.get_by_label("Target").click();
    harness.run();
    assert_eq!(harness.state().tool, gulpsuite::ui::app::TARGET);
    harness.get_by_label("Dashboard").click();
    harness.run();
    assert_eq!(harness.state().tool, gulpsuite::ui::app::SUITE);
}

#[test]
fn status_drawers_open_and_close_without_losing_selection() {
    let mut harness = harness(true, 1440.0);
    let selected = harness.state().workspace.tasks.selected();
    harness.get_by_label("Event log (3)").click();
    harness.run();
    assert!(harness.state().shell.event_log.open);
    harness.get_by_label("All issues (4)").click();
    harness.run();
    assert!(harness.state().shell.all_issues.open);
    harness.get_by_label("Event log (3)").click();
    harness.run();
    assert!(!harness.state().shell.event_log.open);
    assert_eq!(harness.state().workspace.tasks.selected(), selected);
}

#[test]
fn search_filters_tasks_and_clear_restores_them() {
    let mut harness = harness(true, 1440.0);
    let search = harness
        .query_by_label("Search tasks")
        .expect("task search has a label");
    search.click();
    search.type_text("unmatched phrase");
    harness.run();
    assert_eq!(harness.state().dashboard.search, "unmatched phrase");
    assert!(harness.query_by_label("No matching tasks").is_some());
    harness.state_mut().dashboard.search.clear();
    harness.run();
    assert!(harness.query_by_label("No matching tasks").is_none());
}

#[test]
fn state_filter_can_be_cleared() {
    let mut harness = harness(true, 1440.0);
    harness.get_by_label("Filter").click();
    harness.run();
    harness
        .get_by_role_and_label(eframe::egui::accesskit::Role::CheckBox, "Completed")
        .click();
    harness.run();
    assert!(harness
        .state()
        .dashboard
        .states
        .contains(&TaskState::Completed));
    harness.get_by_label("Filter").click();
    harness.run();
    harness.get_by_label("Clear filters").click();
    harness.run();
    assert!(harness.state().dashboard.states.is_empty());
}

#[test]
fn task_selection_and_pause_resume_work() {
    let mut harness = harness(true, 1440.0);
    harness.get_by_label("3. Scan of example.test").click();
    harness.run();
    assert_eq!(
        harness.state().workspace.tasks.selected(),
        Some(gulpsuite::workspace::TaskId(3))
    );

    let actions = "Task actions: 2. Live audit from Proxy (all traffic)";
    harness.get_by_label(actions).click();
    harness.run();
    harness.get_by_label("Pause").click();
    harness.run();
    assert_eq!(
        harness
            .state()
            .workspace
            .tasks
            .get(gulpsuite::workspace::TaskId(2))
            .unwrap()
            .state,
        TaskState::Paused
    );
    harness.get_by_label(actions).click();
    harness.run();
    harness.get_by_label("Resume").click();
    harness.run();
    assert_eq!(
        harness
            .state()
            .workspace
            .tasks
            .get(gulpsuite::workspace::TaskId(2))
            .unwrap()
            .state,
        TaskState::Running
    );
}

#[test]
fn detach_opens_detail_without_losing_task_identity() {
    let mut harness = harness(true, 1440.0);
    let selected = harness.state().workspace.tasks.selected();
    harness.get_by_label("Detach").click();
    harness.run();
    assert_eq!(
        harness.state().shell.detail_location,
        gulpsuite::ui::shell::DetailLocation::Detached
    );
    assert_eq!(harness.state().shell.detached_task(), selected);
    assert_eq!(harness.state().workspace.tasks.selected(), selected);
    if let Some(close) = harness.query_by_label("Close window") {
        close.click();
        harness.run();
        assert_eq!(
            harness.state().shell.detail_location,
            gulpsuite::ui::shell::DetailLocation::Attached
        );
    }
}

#[test]
fn shell_dashboard_snapshot_light() {
    snapshot(false, "shell-dashboard-light");
}

#[test]
fn shell_dashboard_snapshot_dark() {
    snapshot(true, "shell-dashboard-dark");
}

fn snapshot(dark: bool, name: &str) {
    let mut harness = harness(dark, 1440.0);
    harness.snapshot_options(
        name,
        &SnapshotOptions::new()
            .threshold(0.6)
            .failed_pixel_count_threshold(OsThreshold::new(10)),
    );
}

#[test]
fn narrow_shell_keeps_selected_tool_accessible() {
    let mut harness = harness(true, 640.0);
    harness.state_mut().tool = gulpsuite::ui::app::EXTENSIONS;
    harness.run();
    assert_eq!(
        harness.state().shell.active_tool,
        gulpsuite::ui::app::EXTENSIONS
    );
    assert!(harness.query_by_label("Extensions").is_some());
}
