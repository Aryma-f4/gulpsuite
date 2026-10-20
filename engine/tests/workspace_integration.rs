use gulpsuite::proxy::Event;
use gulpsuite::scanner::{Finding, Severity};
use gulpsuite::ui::panels::scanner::ScanUpdate;
use gulpsuite::ui::workspace_adapter::WorkspaceAdapter;
use gulpsuite::workspace::{EventLevel, TaskId, TaskKind, TaskProgress, TaskState, Workspace};

fn seeded() -> (Workspace, WorkspaceAdapter) {
    (
        Workspace {
            tasks: gulpsuite::workspace::TaskManager::seed_proxy_tasks(),
            ..Workspace::default()
        },
        WorkspaceAdapter::default(),
    )
}

#[test]
fn proxy_transactions_advance_both_live_tasks() {
    let (mut workspace, mut adapter) = seeded();
    adapter.apply_proxy(
        &mut workspace,
        &Event::Tx {
            method: "GET".into(),
            target: "https://a.test/".into(),
            status: 200,
            bytes: 42,
            request: "GET / HTTP/1.1\r\n\r\n".into(),
            response: "HTTP/1.1 200 OK\r\n\r\n".into(),
            secure: true,
        },
    );

    assert_eq!(
        workspace.tasks.get(TaskId(1)).unwrap().progress.completed,
        1
    );
    assert_eq!(
        workspace.tasks.get(TaskId(2)).unwrap().progress.completed,
        1
    );
    assert_eq!(workspace.events.len(), 1);
    assert!(
        !workspace.issues.is_empty(),
        "live passive audit must automatically record findings from proxy traffic"
    );
}

#[test]
fn scanner_updates_create_one_task_and_normalized_issues() {
    let (mut workspace, mut adapter) = seeded();
    adapter.begin_scan(&mut workspace, "https://a.test/");
    adapter.apply_scan(
        &mut workspace,
        &ScanUpdate::Progress("Crawled 2 pages".into()),
    );
    adapter.apply_scan(
        &mut workspace,
        &ScanUpdate::Done {
            findings: vec![Finding::new(
                "Reflected input",
                Severity::High,
                "https://a.test/?q=x",
                Some("q".into()),
                "marker-123",
                "Firm",
            )],
            pages: vec![("https://a.test/".into(), 200)],
        },
    );

    let scans: Vec<_> = workspace
        .tasks
        .iter()
        .filter(|task| task.kind == TaskKind::Scan)
        .collect();
    assert_eq!(scans.len(), 1);
    assert_eq!(scans[0].state, TaskState::Completed);
    assert_eq!(scans[0].progress.completed, 1);
    assert_eq!(workspace.issues.len(), 1);
    let issue = workspace.issues.iter().next().unwrap();
    assert_eq!(issue.name, "Reflected input");
    assert_eq!(issue.confidence, "Firm");
}

#[test]
fn intruder_completion_is_idempotent() {
    let (mut workspace, mut adapter) = seeded();
    adapter.begin_attack(&mut workspace, "example.com", 3);
    adapter.apply_attack(
        &mut workspace,
        &Event::AttackResult {
            index: 0,
            status: 200,
            length: 123,
            matched: true,
            error: None,
        },
    );
    let done = Event::AttackDone {
        total: 3,
        matches: 1,
    };
    adapter.apply_attack(&mut workspace, &done);
    adapter.apply_attack(&mut workspace, &done);

    let attacks: Vec<_> = workspace
        .tasks
        .iter()
        .filter(|task| task.kind == TaskKind::Intruder)
        .collect();
    assert_eq!(attacks.len(), 1);
    assert_eq!(attacks[0].state, TaskState::Completed);
    assert_eq!(attacks[0].progress.completed, 3);
    assert_eq!(attacks[0].progress.total, Some(3));
}

#[test]
fn proxy_error_records_context_without_discarding_progress() {
    let (mut workspace, mut adapter) = seeded();
    let task = adapter.begin_scan(&mut workspace, "https://a.test/");
    workspace
        .tasks
        .update_progress(
            task,
            TaskProgress {
                completed: 7,
                total: Some(10),
                status: "Crawling".into(),
            },
        )
        .unwrap();

    adapter.apply_proxy(&mut workspace, &Event::Error("connection reset".into()));

    let task = workspace.tasks.get(task).unwrap();
    assert_eq!(task.progress.completed, 7);
    assert_eq!(task.progress.total, Some(10));
    assert_eq!(task.state, TaskState::Running);
    let error = workspace.events.iter().last().unwrap();
    assert_eq!(error.level, EventLevel::Error);
    assert_eq!(error.task_id, Some(task.id));
    assert!(error.message.contains("connection reset"));
}
