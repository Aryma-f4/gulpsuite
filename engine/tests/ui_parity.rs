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

    // Clicking "New scan" opens the Gulpsuite Professional Scan Launcher modal window
    harness.get_by_label("New scan").click();
    harness.run();
    assert!(harness.state().panels.scanner.show_launcher);
    assert!(harness.query_by_label("Scan details").is_some());
    assert!(harness.query_by_label("Scan configuration").is_some());
    assert!(harness.query_by_label("Application login").is_some());
    assert!(harness.query_by_label("Resource pool").is_some());
    assert!(harness.query_by_label("Crawl and audit").is_some());
    assert!(harness.query_by_label("Audit selected items").is_some());
    assert!(harness.query_by_label("API-only scan").is_some());
    assert!(harness.query_by_label("URLs to scan").is_some());
    assert!(harness.query_by_label("Protocol settings").is_some());

    harness.get_by_label("Scan configuration").click();
    harness.run();
    assert!(harness.query_by_label("Use a preset scan mode").is_some());
    assert!(harness.query_by_label("Use a custom configuration").is_some());
    assert!(harness.query_by_label("Lightweight").is_some());
    assert!(harness.query_by_label("Fast").is_some());
    assert!(harness.query_by_label("Balanced").is_some());
    assert!(harness.query_by_label("Deep").is_some());
    harness.get_by_label("Lightweight").click();
    harness.run();
    assert_eq!(harness.state().panels.scanner.config_preset, 0);
    harness.get_by_label("Deep").click();
    harness.run();
    assert_eq!(harness.state().panels.scanner.config_preset, 3);
    assert!(harness
        .query_by_label("Remember my choice for future scans")
        .is_some());

    harness.get_by_label("Application login").click();
    harness.run();
    assert!(harness.query_by_label("Use login credentials").is_some());

    harness.get_by_label("Resource pool").click();
    harness.run();
    assert!(harness
        .query_by_label("Maximum concurrent requests:")
        .is_some());

    harness.get_by_label("Cancel").click();
    harness.run();
    assert!(!harness.state().panels.scanner.show_launcher);

    // Gulp Scanner reporting wizard (HTML & XML) + Create manual issue + BChecks & Nuclei templates
    assert_eq!(harness.state().panels.scanner.bchecks.len(), 6);
    let html_rep = gulpsuite::ui::panels::scanner::generate_scan_report(harness.state());
    assert!(html_rep.contains("Gulp Scanner Report"));
    assert!(html_rep.contains("SQL injection"));
    harness.state_mut().panels.scanner.report_format = 1;
    let xml_rep = gulpsuite::ui::panels::scanner::generate_scan_report(harness.state());
    assert!(xml_rep.contains("<issues gulpVersion=\"0.1.0\">"));
    assert!(xml_rep.contains("<serialNumber>1000</serialNumber>"));
    harness.state_mut().panels.scanner.report_format = 0;

    harness.state_mut().panels.scanner.show_report_wizard = true;
    harness.run();
    assert!(harness.query_by_label("Report title").is_some());
    assert!(harness.query_by_label("Issue organization").is_some());
    assert!(harness
        .query_by_label("Table of contents levels")
        .is_some());
    assert!(harness.query_by_label("Summary table").is_some());
    assert!(harness.query_by_label("Summary bar chart").is_some());
    harness.state_mut().panels.scanner.show_report_wizard = false;

    harness.state_mut().panels.scanner.show_manual_issue_modal = true;
    harness.run();
    assert!(harness.query_by_label("Create issue").is_some());
    harness.get_by_label("Create issue").click();
    harness.run();
    assert!(!harness.state().panels.scanner.show_manual_issue_modal);
    assert!(harness
        .state()
        .workspace
        .issues
        .iter()
        .any(|i| i.name == "Broken access control"));
}

#[test]
fn proxy_browser_action_reports_missing_bundle_without_starting_listener() {
    let mut harness = harness(true, 1440.0);
    harness.get_by_label("Proxy").click();
    harness.run();
    harness.get_by_label("Open browser").click();
    harness.run();
    assert!(harness.state().status.contains("Bundled Chromium is missing"));
    assert!(harness.state().listening.is_none());
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

#[test]
fn gulpsuite_dashboard_empty_snapshot_light() {
    let mut harness = Harness::builder()
        .with_size(Vec2::new(1440.0, 790.0))
        .build_eframe(|cc| {
            let mut app = App::with_context(&cc.egui_ctx);
            app.set_dark(false);
            app.memory_text = "Memory: 215.6MB of 2.00GB".into();
            app.memory_checked = std::time::Instant::now();
            app
        });
    harness.run();
    harness.snapshot_options(
        "gulpsuite-dashboard-empty-light",
        &SnapshotOptions::new()
            .threshold(0.6)
            .failed_pixel_count_threshold(OsThreshold::new(10)),
    );
}

#[test]
fn dashboard_reference_controls_remain_connected_to_real_task_data() {
    let mut harness = harness(false, 1440.0);
    for label in [
        "Rate this at GitHub",
        "View all",
        "View configuration",
        "Total audit items:",
        "Audit items completed:",
    ] {
        assert!(harness.query_by_label(label).is_some(), "missing {label}");
    }
    harness.get_by_label("View all").click();
    harness.run();
    assert_eq!(harness.state().view, 2);
}

#[test]
fn ai_wip_is_available_from_gulp_style_status_control() {
    let mut harness = harness(false, 1440.0);
    harness.get_by_label("Check for updates").click();
    harness.run();
    assert!(harness.state().show_update_modal);
    harness.state_mut().show_update_modal = false;
    harness.run();
    harness.get_by_label("AI assistant (WIP)").click();
    harness.run();
    assert_eq!(
        harness.state().wip.active(),
        Some(gulpsuite::ui::wip::WipFeature::Ai)
    );
}

#[test]
fn view_configuration_opens_the_selected_task_not_global_settings() {
    let mut harness = harness(false, 1440.0);
    harness.get_by_label("View configuration").click();
    harness.run();
    assert!(harness.state().dashboard.show_configuration);
    assert!(!harness.state().show_settings);
}

#[test]
fn intercept_toolbar_controls_the_proxy_even_when_the_queue_is_empty() {
    let mut harness = harness(false, 1440.0);
    harness.get_by_label("Proxy").click();
    harness.run();
    harness.get_by_label("Intercept is on").click();
    harness.run();
    assert!(!harness.state().proxy.intercepting());
    harness.get_by_label("Intercept is off").click();
    harness.run();
    assert!(harness.state().proxy.intercepting());
}

#[test]
fn send_to_intruder_preserves_target_and_request_without_starting_an_attack() {
    let mut harness = harness(false, 1440.0);
    harness.state_mut().tool = gulpsuite::ui::app::REPEATER;
    harness.state_mut().panels.repeater.active_mut().host = "https://example.test:8443".into();
    harness.state_mut().panels.repeater.active_mut().raw =
        "POST /x HTTP/1.1\r\nHost: example.test\r\n\r\nbody".into();
    harness.run();
    harness.get_by_label("Send to Intruder").click();
    harness.run();
    assert_eq!(harness.state().tool, gulpsuite::ui::app::INTRUDER);
    assert_eq!(
        harness.state().panels.intruder.host,
        "https://example.test:8443"
    );
    assert!(harness.state().panels.intruder.template.ends_with("body"));
    assert!(!harness.state().panels.intruder.running);
}

#[test]
fn held_https_send_to_intruder_keeps_tls_and_the_edited_service() {
    let mut harness = harness(false, 1440.0);
    harness.state_mut().tool = gulpsuite::ui::app::PROXY;
    let raw = "GET /edited?q=value HTTP/1.1\r\nHost: edited.test:9443\r\n\r\n";
    harness.state_mut().held.push(gulpsuite::proxy::HeldInfo {
        id: 42,
        kind: gulpsuite::proxy::HeldKind::Request,
        method: "GET".into(),
        target: "https://original.test:8443/original".into(),
        raw: raw.into(),
    });
    harness.run();
    harness.get_by_label("To Intruder").click();
    harness.run();
    assert_eq!(
        harness.state().panels.intruder.host,
        "https://edited.test:9443/edited?q=value"
    );
    assert!(harness.state().panels.intruder.template.contains("§value§"));
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

#[test]
fn target_proxy_organizer_logger_empty_states_and_intruder_subtabs_work() {
    let mut harness = harness(false, 1440.0);

    // Target: Site map URL/Crawl view toggle + empty state + live Issues tab
    harness.get_by_label("Target").click();
    harness.run();
    assert!(harness.query_by_label("Site map URL view is empty").is_some());
    assert!(harness.query_by_label("Learn more").is_some());
    assert!(harness.query_by_label("Open browser").is_some());
    harness.get_by_label("Crawl paths view").click();
    harness.run();
    assert!(harness
        .query_by_label("Site map crawl paths view is empty")
        .is_some());
    harness.get_by_label("Issues").click();
    harness.run();
    assert!(harness.query_by_label("SQL injection").is_some());

    // Proxy: Intercept, HTTP history, WebSockets history empty states
    harness.get_by_label("Proxy").click();
    harness.run();
    assert!(harness
        .query_by_label("Waiting for traffic to intercept")
        .is_some());
    harness.get_by_label("HTTP history").click();
    harness.run();
    assert!(harness.query_by_label("HTTP history is empty").is_some());
    harness.get_by_label("WebSockets history").click();
    harness.run();
    assert!(harness
        .query_by_label("WebSockets history is empty")
        .is_some());

    // Intruder: side-by-side Positions + Payloads / Resource pool / Settings side panel + Getting started
    harness.get_by_label("Intruder").click();
    harness.run();
    assert!(harness.query_by_label("Add §").is_some());
    assert!(harness.query_by_label("Clear §").is_some());
    assert!(harness.query_by_label("Auto §").is_some());
    assert!(harness.query_by_label("Start attack").is_some());
    harness.get_by_label("Payloads").click();
    harness.run();
    assert!(harness.query_by_label("Payload set 1").is_some());
    assert!(harness.query_by_label("Payload count:").is_some());
    assert!(harness.query_by_label("Request count:").is_some());
    assert!(harness.query_by_label("Add payload set").is_some());
    assert!(harness.query_by_label("Deduplicate").is_some());
    harness.get_by_label("Resource pool").click();
    harness.run();
    assert!(harness
        .query_by_label("Maximum concurrent requests")
        .is_some());
    harness.get_by_label("Attack settings").click();
    harness.run();
    assert!(harness.query_by_label("Grep - match").is_some());
    assert!(harness.query_by_label("Grep - extract").is_some());
    assert!(harness.query_by_label("Redirections").is_some());
    harness.get_by_label("? Getting started").click();
    harness.run();
    assert!(harness.query_by_label("Don't show this again").is_some());
    harness.get_by_label("Don't show this again").click();
    harness.run();

    // Logger: Capture filter bar + empty state
    harness.get_by_label("Logger").click();
    harness.run();
    assert!(harness.query_by_label("Logger is empty").is_some());
    assert!(harness.query_by_label("Logging on").is_some());

    // Organizer: persistent Collections sidebar + empty inbox + "+ New" saves Repeater request
    harness.get_by_label("Organizer").click();
    harness.run();
    assert!(harness.query_by_label("Collections").is_some());
    assert!(harness.query_by_label("Organizer inbox is empty").is_some());
    harness.get_by_label("+ New").click();
    harness.run();
    assert_eq!(harness.state().organizer.len(), 1);
    assert!(harness.query_by_label("Organizer inbox is empty").is_none());

    // Proxy settings: listener controls + CA export + portal URL
    harness.get_by_label("Proxy").click();
    harness.run();
    harness.get_by_label("Proxy settings").click();
    harness.run();
    assert!(harness.query_by_label("Proxy listeners").is_some());
    assert!(harness.query_by_label("CA certificate").is_some());
    assert!(harness.query_by_label("Copy CA PEM").is_some());
    assert!(harness.query_by_label("Copy SPKI pin").is_some());

    // Proxy HTTP history: in-scope and 4xx/5xx filtering
    harness.state_mut().panels.target_panel.scope = "allowed.test".into();
    for (target, status, host) in [
        ("https://allowed.test/ok", 200, "allowed.test"),
        ("https://allowed.test/fail", 500, "allowed.test"),
        ("https://outofscope.test/fail", 500, "outofscope.test"),
    ] {
        let state = harness.state_mut();
        gulpsuite::ui::app::retain(
            &mut state.log,
            gulpsuite::ui::app::Transaction {
                method: "GET".into(),
                target: target.into(),
                status,
                bytes: 42,
                host: host.into(),
                secure: true,
                request: format!("GET / HTTP/1.1\r\nHost: {host}\r\n\r\n"),
                response: format!("HTTP/1.1 {status} TEST\r\n\r\n"),
                truncated: false,
            },
            42,
            &mut state.log_version,
        );
    }
    harness.get_by_label("HTTP history").click();
    harness.run();
    assert!(harness.query_by_label("/ok").is_some());
    assert!(harness.query_by_label("https://outofscope.test").is_some());
    harness
        .get_by_role_and_label(eframe::egui::accesskit::Role::CheckBox, "In-scope only")
        .click();
    harness.run();
    assert!(harness.query_by_label("/ok").is_some());
    assert!(harness.query_by_label("https://outofscope.test").is_none());
    harness
        .get_by_role_and_label(eframe::egui::accesskit::Role::CheckBox, "4xx/5xx only")
        .click();
    harness.run();
    assert!(harness.query_by_label("/ok").is_none());
    assert!(harness.query_by_label("/fail").is_some());

    // Toggle Filter on -> Filter off restores unfiltered rows without clearing settings
    harness.get_by_label("Filter on").click();
    harness.run();
    assert!(harness.query_by_label("/ok").is_some());
    assert!(harness.query_by_label("https://outofscope.test").is_some());

    // Column sorting in HTTP history: Status -> Status ▲ -> Status ▼ -> Status
    harness.get_by_label("Status code").click();
    harness.run();
    assert_eq!(harness.state().panels.proxy_panel.sort_column, Some(6));
    assert!(harness.state().panels.proxy_panel.sort_ascending);
    assert!(harness.query_by_label("Status code ▲").is_some());
    harness.get_by_label("Status code ▲").click();
    harness.run();
    assert!(!harness.state().panels.proxy_panel.sort_ascending);
    assert!(harness.query_by_label("Status code ▼").is_some());

    // Filter settings modal window opens with Gulp Configure filter controls
    harness.get_by_label("Filter settings").click();
    harness.run();
    assert!(harness.query_by_label("Settings mode").is_some());
    assert!(harness.query_by_label("Bambda mode").is_some());
    assert!(harness.query_by_label("Filter by MIME type").is_some());
    assert!(harness.query_by_label("Filter by status code").is_some());
    assert!(harness
        .query_by_label("Filter by file extension")
        .is_some());
    assert!(harness.query_by_label("Show all").is_some());
    harness.get_by_label("Filter settings").click();
    harness.run();

    // Decoder: multi-layer Smart decode (URL-encoded Base64 -> "hello") + Text/Hex view
    harness.get_by_label("Decoder").click();
    harness.run();
    harness.state_mut().panels.decoder.input = "aGVsbG8%3D".into();
    harness.get_by_label("Smart decode").click();
    harness.run();
    assert_eq!(harness.state().panels.decoder.output, "hello");
    harness.get_by_label("Hex").click();
    harness.run();
    assert!(harness.state().panels.decoder.hex_view);

    // Comparer: Words and Bytes diff modes
    harness.get_by_label("Comparer").click();
    harness.run();
    harness.state_mut().panels.comparer.left = "one\ntwo".into();
    harness.state_mut().panels.comparer.right = "one\nthree".into();
    harness.get_by_label("Words").click();
    harness.run();
    assert!(!harness.state().panels.comparer.rows.is_empty());
    harness.get_by_label("Bytes").click();
    harness.run();
    assert!(harness.state().panels.comparer.byte_mode);

    // Sequencer: Live capture / Manual load / Sequencer settings sub-tabs
    harness.get_by_label("Sequencer").click();
    harness.run();
    assert!(harness
        .query_by_label("Select live capture request")
        .is_some());
    harness.get_by_label("Sequencer settings").click();
    harness.run();
    assert!(harness.query_by_label("Token handling").is_some());

    // Repeater: 50/50 Getting started screen when untouched, then active tab workspace
    harness.get_by_label("Repeater").click();
    harness.run();
    assert!(harness
        .query_by_label_contains("To get started, send a request to Repeater")
        .is_some());
    assert!(harness.query_by_label("Don't show this again").is_some());
    harness.get_by_label("Don't show this again").click();
    harness.state_mut().panels.repeater.active_mut().host = "http://origin.test".into();
    harness.state_mut().panels.repeater.active_mut().raw =
        "GET /login?user=alice&role=admin HTTP/1.1\r\nHost: origin.test\r\n\r\n".into();
    harness.state_mut().panels.repeater.active_mut().status = Some(302);
    harness.state_mut().panels.repeater.active_mut().elapsed_ms = 14;
    harness.state_mut().panels.repeater.active_mut().response =
        "HTTP/1.1 302 Found\r\nLocation: https://redirected.test:8443/login?step=2\r\n\r\n".into();
    harness.run();
    assert!(harness.query_by_label("Follow redirection").is_some());
    assert!(harness.query_by_label("History").is_some());
    assert!(harness.query_by_label("...").is_some());
    let api_eps = gulpsuite::ui::panels::scanner::parse_api_definition(
        r#"{"openapi":"3.0.0","paths":{"/api/items":{"get":{},"post":{}}}}"#,
        "https://api.example.test",
    );
    assert_eq!(api_eps.len(), 2);
    harness.get_by_label("Change method").click();
    harness.run();
    assert!(harness
        .state()
        .panels
        .repeater
        .active()
        .raw
        .starts_with("POST /login HTTP/1.1"));
    assert!(harness
        .state()
        .panels
        .repeater
        .active()
        .raw
        .ends_with("user=alice&role=admin"));
    let curl = gulpsuite::ui::app::Transaction::to_curl_command(
        "https://origin.test/login",
        &harness.state().panels.repeater.active().raw,
    );
    assert!(curl.contains("curl -i -s -k -X POST"));
    assert!(curl.contains("--data-raw 'user=alice&role=admin'"));

    // Engagement tools: Generate CSRF PoC
    let poc = gulpsuite::ui::app::Transaction::generate_csrf_poc(
        "https://origin.test/login",
        &harness.state().panels.repeater.active().raw,
        true,
    );
    assert!(poc.contains("<form action=\"https://origin.test/login\" method=\"POST\">"));
    assert!(poc.contains("<input type=\"hidden\" name=\"user\" value=\"alice\" />"));
    assert!(poc.contains("document.forms[0].submit();"));

    // Discover -> Try it out jumps to Extensions Bambda editor
    harness.get_by_label("Discover").click();
    harness.run();
    harness.get_by_label("Try it out").click();
    harness.run();
    assert_eq!(harness.state().tool, gulpsuite::ui::app::EXTENSIONS);

    // Collaborator: Payload generator + Copy to clipboard + Poll now
    harness.get_by_label("Collaborator").click();
    harness.run();
    assert!(harness.query_by_label("Payload generator").is_some());
    assert!(harness.query_by_label("Copy to clipboard").is_some());
    harness.get_by_label("Poll now").click();
    harness.run();

    // Multi-category Settings window + Top menu bar + Proxy settings 9 sections
    harness.state_mut().show_settings = true;
    harness.state_mut().show_menu_bar = true;
    harness.run();
    assert!(harness.query_by_label("Suite › Project files").is_some());
    assert!(harness.query_by_label("Tools › Intruder").is_some());
    assert!(harness.query_by_label("Project › Scope, Tasks & Logging").is_some());
    assert!(harness.query_by_label("Sessions › Cookie jar & Handling").is_some());
    assert!(harness.query_by_label("Network › Connections, HTTP & TLS").is_some());
    harness.get_by_label("Tools › Intruder").click();
    harness.run();
    assert!(harness.query_by_label("Intruder configuration").is_some());
    harness.get_by_label("Tools › Proxy").click();
    harness.run();
    assert!(harness.query_by_label("Proxy listeners").is_some());
    assert!(harness
        .query_by_label("Request and response interception rules")
        .is_some());
    assert!(harness
        .query_by_label("WebSocket interception rules")
        .is_some());
    assert!(harness.query_by_label("Response modification rules").is_some());
    assert!(harness
        .query_by_label("HTTP and WebSocket match and replace rules")
        .is_some());
    assert!(harness.query_by_label("TLS pass through").is_some());
    assert!(harness.query_by_label("Miscellaneous").is_some());
}

#[test]
fn native_setup_wizard_steps_through_welcome_and_directory_screens() {
    use gulpsuite::installer::{SetupStep, SetupWizard};
    let mut harness = Harness::builder()
        .with_size(Vec2::new(680.0, 440.0))
        .build_eframe(|_cc| SetupWizard::default());
    harness.run();
    assert_eq!(harness.state().step, SetupStep::Welcome);
    assert!(harness
        .query_by_label("Welcome to the Gulpsuite 0.1.0 Setup Wizard")
        .is_some());
    harness.get_by_label("Next >").click();
    harness.run();
    assert_eq!(harness.state().step, SetupStep::Directory);
    assert!(harness
        .query_by_label("Select Destination Directory")
        .is_some());
    assert!(harness.query_by_label("Install").is_some());

    // Verify compact responsive mode at narrow window dimensions (480x340)
    let mut compact_harness = Harness::builder()
        .with_size(Vec2::new(480.0, 340.0))
        .build_eframe(|_cc| SetupWizard::default());
    compact_harness.run();
    assert!(compact_harness.query_by_label("Next >").is_some());
    compact_harness.get_by_label("Next >").click();
    compact_harness.run();
    assert!(compact_harness.query_by_label("Install").is_some());
    assert!(compact_harness.query_by_label("< Back").is_some());
}

fn right_click(harness: &mut Harness<'_, App>, pos: eframe::egui::Pos2) {
    harness
        .input_mut()
        .events
        .push(eframe::egui::Event::PointerMoved(pos));
    harness
        .input_mut()
        .events
        .push(eframe::egui::Event::PointerButton {
            pos,
            button: eframe::egui::PointerButton::Secondary,
            pressed: true,
            modifiers: eframe::egui::Modifiers::NONE,
        });
    harness.step();
    harness
        .input_mut()
        .events
        .push(eframe::egui::Event::PointerButton {
            pos,
            button: eframe::egui::PointerButton::Secondary,
            pressed: false,
            modifiers: eframe::egui::Modifiers::NONE,
        });
    harness.step();
}

#[test]
fn context_menu_persists_across_frames_on_tables_and_message_panes() {
    let mut harness = harness(false, 1440.0);
    harness
        .state_mut()
        .log
        .push_back(gulpsuite::ui::app::Transaction {
            method: "GET".into(),
            target: "https://example.com/api/items?id=1".into(),
            status: 200,
            bytes: 42,
            host: "example.com".into(),
            secure: true,
            request: "GET /api/items?id=1 HTTP/1.1\r\nHost: example.com\r\n\r\n".into(),
            response: "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\n\r\n{\"ok\":true}"
                .into(),
            truncated: false,
        });
    harness.state_mut().log_version += 1;
    harness.get_by_label("Proxy").click();
    harness.run();
    harness.get_by_label("HTTP history").click();
    harness.run();

    // Right-click a row in Proxy -> HTTP history and step multiple subsequent frames;
    // the context menu must remain open after the initial secondary_clicked() frame.
    let row_pos = harness.get_by_label("https://example.com").rect().center();
    right_click(&mut harness, row_pos);
    harness.step();
    harness.step();
    harness.step();
    assert!(
        harness.query_by_label("Send to Repeater").is_some(),
        "Context menu must stay open across subsequent frames"
    );
    assert!(harness.query_by_label("Send to Intruder").is_some());
    assert!(harness.query_by_label("Send to Organizer").is_some());
    assert!(harness.query_by_label("Add to scope").is_some());
    assert!(harness.query_by_label("Exclude from scope").is_some());
    assert!(harness.query_by_label("Copy as curl command").is_some());
    assert!(harness
        .query_by_label("Record an issue › Create an issue")
        .is_some());
    assert!(harness.query_by_label("Report issues…").is_some());

    // Clicking "Send to Repeater" on a later frame must execute the action and switch tools.
    harness.get_by_label("Send to Repeater").click();
    harness.run();
    assert_eq!(harness.state().tool, gulpsuite::ui::app::REPEATER);

    // Switch back to Proxy -> HTTP history, and right-click inside the Request message viewer
    // (including in the blank space below the HTTP headers); verify its context menu opens
    // and persists across multiple subsequent frames.
    harness.get_by_label("Proxy").click();
    harness.run();
    harness.get_by_label("HTTP history").click();
    harness.run();
    let msg_rect = harness
        .get_by_label_contains("GET /api/items?id=1 HTTP/1.1")
        .rect();
    let blank_space_pos = eframe::egui::pos2(msg_rect.min.x + 120.0, msg_rect.max.y + 40.0);
    right_click(&mut harness, blank_space_pos);
    harness.step();
    harness.step();
    harness.step();
    assert!(
        harness.query_by_label("Send to Repeater").is_some(),
        "Message pane right-click context menu must open on blank space and stay open across frames"
    );
    assert!(harness.query_by_label("Request in browser").is_some());

    // Verify block-selection ("block") + Add § / Clear § in Intruder AND right-click on blocked selection
    harness.get_by_label("Intruder").click();
    harness.state_mut().panels.intruder.template =
        "POST /login HTTP/1.1\r\nHost: example.com\r\n\r\nuser=carlos&pass=secret".into();
    harness.run();
    // Simulate blocking "carlos" (char range 48..54) in the Intruder Positions editor
    let tmpl = harness.state().panels.intruder.template.clone();
    let start_idx = tmpl.find("carlos").unwrap();
    let end_idx = start_idx + "carlos".len();
    gulpsuite::ui::panels::record_message_selection(
        "intruder-positions-edit",
        start_idx..end_idx,
        &tmpl,
    );
    harness.run();
    harness.get_by_label("Add §").click();
    harness.run();
    assert!(
        harness.state().panels.intruder.template.contains("user=§carlos§&pass=secret"),
        "Add § must wrap the blocked selection in §...§: {}",
        harness.state().panels.intruder.template
    );

    // Right-click in the Intruder request editor while a selection is active;
    // verify "Copy selection" and "Send selection to Decoder" appear and persist across frames.
    let tmpl2 = harness.state().panels.intruder.template.clone();
    let sec_byte_start = tmpl2.find("secret").unwrap();
    let sec_char_start = tmpl2[..sec_byte_start].chars().count();
    let sec_char_end = sec_char_start + "secret".chars().count();
    gulpsuite::ui::panels::record_message_selection(
        "intruder-positions-edit",
        sec_char_start..sec_char_end,
        &tmpl2,
    );
    let add_btn_rect = harness.get_by_label("Add §").rect();
    right_click(
        &mut harness,
        eframe::egui::pos2(add_btn_rect.min.x + 60.0, add_btn_rect.max.y + 40.0),
    );
    harness.step();
    harness.step();
    assert!(
        harness.query_by_label("Copy selection").is_some(),
        "Right-clicking with blocked text must offer Copy selection"
    );
    assert!(
        harness.query_by_label("Send selection to Decoder").is_some(),
        "Right-clicking with blocked text must offer Send selection to Decoder"
    );
    harness.get_by_label("Send selection to Decoder").click();
    harness.run();
    assert_eq!(harness.state().tool, gulpsuite::ui::app::DECODER);
    assert_eq!(harness.state().panels.decoder.input, "secret");
}

#[test]
fn generate_documentation_screenshots() {
    let out_dir = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../docs/screenshots");
    std::fs::create_dir_all(&out_dir).expect("create docs/screenshots");

    // 1. Dashboard (Light) — with platform fonts (SF Pro + Menlo) installed
    let mut h_light = harness(false, 1440.0);
    gulpsuite::ui::app::install_fonts(&h_light.ctx);
    h_light.run();
    h_light
        .render()
        .expect("render dashboard light")
        .save(out_dir.join("01-dashboard-light.png"))
        .expect("save 01-dashboard-light.png");

    // 2. Dashboard (Dark)
    let mut h_dark = harness(true, 1440.0);
    gulpsuite::ui::app::install_fonts(&h_dark.ctx);
    h_dark.run();
    h_dark
        .render()
        .expect("render dashboard dark")
        .save(out_dir.join("02-dashboard-dark.png"))
        .expect("save 02-dashboard-dark.png");

    // Seed sample HTTP traffic for Target, Proxy, Intruder, Repeater, Decoder
    for (method, target, status, req, resp) in [
        (
            "GET",
            "https://ginandjuice.shop/catalog/product?productId=3",
            200u16,
            "GET /catalog/product?productId=3 HTTP/1.1\r\nHost: ginandjuice.shop\r\nUser-Agent: Mozilla/5.0 (Macintosh; Intel Mac OS X 14_0) AppleWebKit/537.36\r\nAccept: text/html,application/xhtml+xml\r\nCookie: session=eyJhbGciOiJIUzI1NiJ9\r\n\r\n",
            "HTTP/1.1 200 OK\r\nContent-Type: text/html; charset=utf-8\r\nConnection: close\r\nContent-Length: 248\r\n\r\n<!DOCTYPE html>\n<html>\n  <head>\n    <link href='/resources/css/labsEcommerce.css' rel='stylesheet'>\n    <title>Pineapple Edition Cocktail</title>\n  </head>\n  <body>\n    <h1>Pineapple Edition</h1>\n  </body>\n</html>",
        ),
        (
            "POST",
            "https://ginandjuice.shop/api/v1/login",
            302u16,
            "POST /api/v1/login HTTP/1.1\r\nHost: ginandjuice.shop\r\nContent-Type: application/x-www-form-urlencoded\r\nContent-Length: 29\r\n\r\nusername=carlos&password=test",
            "HTTP/1.1 302 Found\r\nLocation: /my-account?id=carlos\r\nSet-Cookie: session=s3cr3t_t0k3n; HttpOnly; Secure\r\nContent-Length: 0\r\n\r\n",
        ),
        (
            "GET",
            "https://ginandjuice.shop/my-account?id=carlos",
            200u16,
            "GET /my-account?id=carlos HTTP/1.1\r\nHost: ginandjuice.shop\r\nCookie: session=s3cr3t_t0k3n\r\n\r\n",
            "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\n\r\n{\"username\":\"carlos\",\"role\":\"user\",\"apiKey\":\"ak_live_98f12b4c\"}",
        ),
    ] {
        h_light
            .state_mut()
            .log
            .push_back(gulpsuite::ui::app::Transaction {
                method: method.into(),
                target: target.into(),
                status,
                bytes: resp.len() as u64,
                host: "ginandjuice.shop".into(),
                secure: true,
                request: req.into(),
                response: resp.into(),
                truncated: false,
            });
    }
    h_light.state_mut().log_version += 1;

    // 3. New Scan Launcher window
    h_light.get_by_label("New scan").click();
    h_light.state_mut().panels.scanner.urls_to_scan =
        "https://ginandjuice.shop/\nhttps://ginandjuice.shop/catalog".into();
    h_light.run();
    h_light
        .render()
        .expect("render new scan launcher")
        .save(out_dir.join("03-new-scan-launcher.png"))
        .expect("save 03-new-scan-launcher.png");
    h_light.state_mut().panels.scanner.show_launcher = false;

    // 4. Target -> Site map & Target -> Issues
    h_light.get_by_label("Target").click();
    h_light.state_mut().panels.target_panel.host = Some("https://ginandjuice.shop".into());
    h_light.state_mut().panels.target_panel.path =
        Some("/catalog/product?productId=3".into());
    h_light.run();
    h_light
        .render()
        .expect("render target sitemap")
        .save(out_dir.join("04-target-sitemap.png"))
        .expect("save 04-target-sitemap.png");

    h_light.state_mut().view = 2;
    h_light.state_mut().panels.target_panel.selected_issue = Some(0);
    h_light.run();
    h_light
        .render()
        .expect("render target issues")
        .save(out_dir.join("04b-target-issues.png"))
        .expect("save 04b-target-issues.png");
    h_light.state_mut().view = 0;

    // 5. Proxy -> HTTP history
    h_light.get_by_label("Proxy").click();
    h_light.run();
    h_light.get_by_label("HTTP history").click();
    h_light.state_mut().panels.proxy_panel.selected = Some(0);
    h_light.run();
    h_light
        .render()
        .expect("render proxy history")
        .save(out_dir.join("05-proxy-history.png"))
        .expect("save 05-proxy-history.png");

    // 6. Intruder Getting Started & Attack workspace
    h_light.get_by_label("Intruder").click();
    h_light.state_mut().panels.intruder.show_getting_started = true;
    h_light.run();
    h_light
        .render()
        .expect("render intruder getting started")
        .save(out_dir.join("06a-intruder-getting-started.png"))
        .expect("save 06a-intruder-getting-started.png");

    h_light.state_mut().panels.intruder.show_getting_started = false;
    h_light.state_mut().panels.intruder.host = "https://ginandjuice.shop".into();
    h_light.state_mut().panels.intruder.template =
        "POST /api/v1/login HTTP/1.1\r\nHost: ginandjuice.shop\r\nContent-Type: application/x-www-form-urlencoded\r\n\r\nusername=§carlos§&password=§test§".into();
    h_light.state_mut().panels.intruder.payload_sets[0].values =
        "admin\ncarlos\nwiener\nadministrator\nroot".into();
    h_light.run();
    h_light
        .render()
        .expect("render intruder")
        .save(out_dir.join("06-intruder-attack.png"))
        .expect("save 06-intruder-attack.png");

    // 7. Repeater Getting Started screen
    h_light.get_by_label("Repeater").click();
    h_light.run();
    h_light
        .render()
        .expect("render repeater getting started")
        .save(out_dir.join("07-repeater-getting-started.png"))
        .expect("save 07-repeater-getting-started.png");

    // 8. Repeater active tab workspace
    h_light.state_mut().panels.repeater.show_getting_started = false;
    h_light.state_mut().panels.repeater.active_mut().name = "1".into();
    h_light.state_mut().panels.repeater.active_mut().host =
        "https://ginandjuice.shop".into();
    h_light.state_mut().panels.repeater.active_mut().raw =
        "GET /product?productId=3 HTTP/1.1\r\nHost: ginandjuice.shop\r\nSec-Ch-Ua: \"Not A;Brand\";v=\"99\", \"Chromium\";v=\"124\"\r\nSec-Ch-Ua-Mobile: ?0\r\nUpgrade-Insecure-Requests: 1\r\nUser-Agent: Mozilla/5.0 (Macintosh; Intel Mac OS X 14_0) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36\r\nAccept: text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8\r\n\r\n".into();
    h_light.state_mut().panels.repeater.active_mut().status = Some(200);
    h_light.state_mut().panels.repeater.active_mut().elapsed_ms = 18;
    h_light.state_mut().panels.repeater.active_mut().response =
        "HTTP/1.1 200 OK\r\nContent-Type: text/html; charset=utf-8\r\nConnection: close\r\nContent-Length: 4142\r\n\r\n<!DOCTYPE html>\n<html>\n  <head>\n    <link href=/resources/labheader/css/academyLabHeader.css rel=stylesheet>\n    <link href=/resources/css/labsEcommerce.css rel=stylesheet>\n    <title>\n      Information disclosure in error messages\n    </title>\n  </head>\n  <body>\n    <section class=\"product-detail\">\n      <h2>Pineapple Edition Cocktail</h2>\n    </section>\n  </body>\n</html>".into();
    h_light.run();
    h_light
        .render()
        .expect("render repeater workspace")
        .save(out_dir.join("08-repeater-workspace.png"))
        .expect("save 08-repeater-workspace.png");

    // 9. Decoder
    h_light.get_by_label("Decoder").click();
    h_light.state_mut().panels.decoder.input =
        "eyJ1c2VybmFtZSI6ImNhcmxvcyIsInJvbGUiOiJhZG1pbiJ9".into();
    h_light.run();
    h_light.get_by_label("Smart decode").click();
    h_light.run();
    h_light
        .render()
        .expect("render decoder")
        .save(out_dir.join("09-decoder-smart-decode.png"))
        .expect("save 09-decoder-smart-decode.png");

    // 10. Collaborator (matching `gulp-collaborator-tut-4-polling-for-interactions.png`)
    h_light.get_by_label("Collaborator").click();
    h_light.state_mut().panels.collaborator_hits = vec![
        gulpsuite::collaborator::Hit {
            kind: "DNS".into(),
            method: "A".into(),
            path: "xlmmyqvknz5x645l19w1cxs4xv3srif7.oastify.com".into(),
            peer: "3.251.105.10".into(),
            host: "xlmmyqvknz5x645l19w1cxs4xv3srif7.oastify.com".into(),
            resolved: Some("127.0.0.1".into()),
            timestamp_utc: "2026-Oct-21 12:41:30.756 UTC".into(),
            payload_id: "xlmmyqvknz5x645l19w1cxs4xv3srif7".into(),
            raw_request: ";; QUESTION SECTION:\r\n;xlmmyqvknz5x645l19w1cxs4xv3srif7.oastify.com.\tIN\tA".into(),
            raw_response: ";; ANSWER SECTION:\r\nxlmmyqvknz5x645l19w1cxs4xv3srif7.oastify.com.\t60\tIN\tA\t127.0.0.1".into(),
            read: false,
            comment: String::new(),
            highlight: None,
        },
        gulpsuite::collaborator::Hit {
            kind: "DNS".into(),
            method: "A".into(),
            path: "xlmmyqvknz5x645l19w1cxs4xv3srif7.oastify.com".into(),
            peer: "3.251.128.115".into(),
            host: "xlmmyqvknz5x645l19w1cxs4xv3srif7.oastify.com".into(),
            resolved: Some("127.0.0.1".into()),
            timestamp_utc: "2026-Oct-21 12:41:30.755 UTC".into(),
            payload_id: "xlmmyqvknz5x645l19w1cxs4xv3srif7".into(),
            raw_request: ";; QUESTION SECTION:\r\n;xlmmyqvknz5x645l19w1cxs4xv3srif7.oastify.com.\tIN\tA".into(),
            raw_response: ";; ANSWER SECTION:\r\nxlmmyqvknz5x645l19w1cxs4xv3srif7.oastify.com.\t60\tIN\tA\t127.0.0.1".into(),
            read: true,
            comment: String::new(),
            highlight: None,
        },
        gulpsuite::collaborator::Hit {
            kind: "HTTP".into(),
            method: "GET".into(),
            path: "/".into(),
            peer: "34.253.173.2".into(),
            host: "xlmmyqvknz5x645l19w1cxs4xv3srif7.oastify.com".into(),
            resolved: None,
            timestamp_utc: "2026-Oct-21 12:41:31.124 UTC".into(),
            payload_id: "xlmmyqvknz5x645l19w1cxs4xv3srif7".into(),
            raw_request: "GET / HTTP/1.1\r\nHost: xlmmyqvknz5x645l19w1cxs4xv3srif7.oastify.com\r\nUser-Agent: Mozilla/5.0\r\n\r\n".into(),
            raw_response: "HTTP/1.1 200 OK\r\nServer: Collaborator\r\n\r\n<html><body>collaborator cr4393h3ipr3hi30f3jif3op</body></html>".into(),
            read: false,
            comment: String::new(),
            highlight: None,
        },
    ];
    h_light.state_mut().panels.collaborator_panel.selected_hit = Some(1);
    h_light.run();
    h_light
        .render()
        .expect("render collaborator")
        .save(out_dir.join("10-collaborator-interactions.png"))
        .expect("save 10-collaborator-interactions.png");
}

#[test]
fn http_history_uses_bounded_columns_and_whole_row_selection() {
    let mut h = harness(false, 1440.0);
    for (path, bytes) in [
        ("/short".to_string(), 12345),
        (format!("/{}", "long-path".repeat(80)), 67890),
    ] {
        h.state_mut()
            .log
            .push_back(gulpsuite::ui::app::Transaction {
                method: "GET".into(),
                target: format!("https://history.test{path}"),
                status: 200,
                bytes,
                host: "history.test".into(),
                secure: true,
                request: format!("GET {path} HTTP/1.1\r\nHost: history.test\r\n\r\n"),
                response:
                    "HTTP/1.1 200 OK\r\nContent-Type: text/html\r\n\r\n<title>History</title>"
                        .into(),
                truncated: false,
            });
    }
    h.state_mut().log_version += 1;
    h.get_by_label("Proxy").click();
    h.run();
    h.get_by_label("HTTP history").click();
    h.run();
    assert!(
        h.query_by_label("/short").is_some(),
        "URL column must show the path and query"
    );
    let url = h.get_by_label("/short").rect();
    let length = h.get_by_label("12345").rect();
    assert!(url.width() <= 400.0, "Long URLs must not expand columns");
    assert!(
        length.right() < 1440.0,
        "Length must remain in the viewport"
    );
    assert!(
        h.query_by_label("To Repeater").is_none(),
        "Actions belong in the row context menu"
    );
    let edge = h.get_by_label("URL").rect().right_center();
    h.input_mut().events.extend([
        eframe::egui::Event::PointerMoved(edge),
        eframe::egui::Event::PointerButton {
            pos: edge,
            button: eframe::egui::PointerButton::Primary,
            pressed: true,
            modifiers: Default::default(),
        },
    ]);
    h.step();
    let moved = edge + eframe::egui::vec2(50.0, 0.0);
    h.input_mut()
        .events
        .push(eframe::egui::Event::PointerMoved(moved));
    h.step();
    h.input_mut()
        .events
        .push(eframe::egui::Event::PointerButton {
            pos: moved,
            button: eframe::egui::PointerButton::Primary,
            pressed: false,
            modifiers: Default::default(),
        });
    h.run();
    assert!(
        (h.get_by_label("/short").rect().width() - url.width() - 50.0).abs() < 2.0,
        "Dragging a header divider must resize its column by the drag distance"
    );

    h.get_by_label("12345").click();
    h.run();
    assert_eq!(
        h.state().panels.proxy_panel.selected,
        Some(0),
        "Every column must select its row"
    );
    assert!(h.query_by_label("Request").is_some());
    if std::env::var_os("GULPSUITE_HISTORY_SCREENSHOTS").is_some() {
        let out = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../docs/screenshots");
        h.render()
            .unwrap()
            .save(out.join("http-history-light.png"))
            .unwrap();
        h.state_mut().set_dark(true);
        h.run();
        h.render()
            .unwrap()
            .save(out.join("http-history-dark.png"))
            .unwrap();
    }
}

#[test]
fn http_history_search_includes_entries_older_than_300_rows() {
    let mut h = harness(true, 1000.0);
    for index in 0..305 {
        h.state_mut()
            .log
            .push_back(gulpsuite::ui::app::Transaction {
                method: "GET".into(),
                target: format!("https://history.test/entry-{index}"),
                status: 200,
                bytes: 42,
                host: "history.test".into(),
                secure: true,
                request: "GET / HTTP/1.1\r\nHost: history.test\r\n\r\n".into(),
                response: "HTTP/1.1 200 OK\r\n\r\n".into(),
                truncated: false,
            });
    }
    h.state_mut().log_version += 1;
    h.state_mut().panels.proxy_panel.filter = "/entry-0".into();
    h.get_by_label("Proxy").click();
    h.run();
    h.get_by_label("HTTP history").click();
    h.run();
    h.get_by_label("/entry-0").click();
    h.run();
    assert_eq!(h.state().panels.proxy_panel.selected, Some(0));
    assert!(h.query_by_label("/entry-304").is_none());
    h.state_mut().panels.proxy_panel.selected = None;
    h.state_mut().panels.proxy_panel.filter.clear();
    h.run();
    let header = h.get_by_label("URL").rect();
    let row = h.get_by_label("/entry-0").rect();
    h.input_mut().events.extend([
        eframe::egui::Event::PointerMoved(row.center()),
        eframe::egui::Event::MouseWheel {
            unit: eframe::egui::MouseWheelUnit::Point,
            delta: eframe::egui::vec2(0.0, -400.0),
            modifiers: Default::default(),
        },
    ]);
    h.run_steps(12);
    h.input_mut()
        .events
        .push(eframe::egui::Event::PointerMoved(eframe::egui::pos2(
            5.0, 5.0,
        )));
    h.run_steps(12);
    assert_eq!(
        h.get_by_label("URL").rect(),
        header,
        "The header must remain fixed during vertical scrolling"
    );
    assert!(
        h.query_by_label("/entry-0").is_none(),
        "The body must scroll independently of the header"
    );
}

#[test]
fn right_click_convert_selection_encodes_and_decodes_base64_in_place() {
    let mut h = harness(false, 1280.0);
    let req = "GET /login HTTP/1.1\r\nHost: example.test\r\nAuthorization: Basic admin:secret123\r\n\r\n";
    h.state_mut().tool = gulpsuite::ui::app::REPEATER;
    h.state_mut()
        .panels
        .repeater
        .open("https://example.test/login", req);
    h.run();

    // Select ("block") `admin:secret123` inside the Repeater request editor (in default Pretty mode)
    let start = req.find("admin:secret123").unwrap();
    let end = start + "admin:secret123".len();
    gulpsuite::ui::panels::record_message_selection("repeater-req-edit", start..end, req);

    let ctx = h.ctx.clone();
    let raw_clone = h.state().panels.repeater.active().raw.clone();
    gulpsuite::ui::panels::apply_convert_selection(
        h.state_mut(),
        &ctx,
        "Base64 encode",
        &raw_clone,
        "",
    );
    let encoded_req = h.state().panels.repeater.active().raw.clone();
    assert!(
        encoded_req.contains("Authorization: Basic YWRtaW46c2VjcmV0MTIz"),
        "Expected in-place Base64 encoding in Repeater request, got: {encoded_req}"
    );

    // Chained decode back in-place without re-selecting
    gulpsuite::ui::panels::apply_convert_selection(
        h.state_mut(),
        &ctx,
        "Base64 decode",
        &encoded_req,
        "",
    );
    let decoded_req = h.state().panels.repeater.active().raw.clone();
    assert_eq!(decoded_req, req);
}
