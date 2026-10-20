//! Translation from existing engine messages into the shared Dashboard workspace.

use crate::discover;
use crate::proxy::Event;
use crate::scanner;
use crate::ui::panels::scanner::ScanUpdate;
use crate::workspace::{
    EventLevel, IssueRecord, IssueSeverity, TaskId, TaskKind, TaskProgress, TaskState, Workspace,
};

#[derive(Clone, Debug)]
pub struct WorkspaceAdapter {
    passive_crawl: TaskId,
    live_audit: TaskId,
    scan_task: Option<TaskId>,
    discover_task: Option<TaskId>,
    attack_task: Option<TaskId>,
}

impl Default for WorkspaceAdapter {
    fn default() -> Self {
        Self {
            passive_crawl: TaskId(1),
            live_audit: TaskId(2),
            scan_task: None,
            discover_task: None,
            attack_task: None,
        }
    }
}

impl WorkspaceAdapter {
    pub fn begin_scan(&mut self, workspace: &mut Workspace, seed: &str) -> TaskId {
        let id = begin_task(
            workspace,
            &mut self.scan_task,
            TaskKind::Scan,
            format!("Scan of {seed}"),
            "Crawl and audit",
            None,
        );
        if let Some(task) = workspace.tasks.get_mut(id) {
            task.scope = seed.into();
        }
        id
    }

    pub fn begin_discover(&mut self, workspace: &mut Workspace, total: usize) -> TaskId {
        begin_task(
            workspace,
            &mut self.discover_task,
            TaskKind::Discover,
            "Content discovery".into(),
            "Discover content from proxy history",
            Some(total as u64),
        )
    }

    pub fn begin_attack(
        &mut self,
        workspace: &mut Workspace,
        target: &str,
        total: usize,
    ) -> TaskId {
        let id = begin_task(
            workspace,
            &mut self.attack_task,
            TaskKind::Intruder,
            format!("Intruder attack against {target}"),
            "Sniper attack",
            Some(total as u64),
        );
        if let Some(task) = workspace.tasks.get_mut(id) {
            task.scope = target.into();
        }
        id
    }

    pub fn apply_proxy(&mut self, workspace: &mut Workspace, event: &Event) {
        match event {
            Event::Tx {
                method,
                target,
                status,
                response,
                ..
            } => {
                increment_task(workspace, self.passive_crawl, "response captured");
                increment_task(workspace, self.live_audit, "item processed");
                if workspace
                    .tasks
                    .get(self.live_audit)
                    .is_some_and(|task| task.state == TaskState::Running)
                    && !response.is_empty()
                {
                    let parsed = scanner::http::parse_response(response);
                    for mut finding in scanner::passive::inspect(target, &parsed) {
                        if scanner::passive::is_host_wide_passive_issue(&finding.name) {
                            if let Some((scheme, rest)) = finding.url.split_once("://") {
                                let host = rest.split('/').next().unwrap_or(rest);
                                finding.url = format!("{scheme}://{host}/");
                            }
                        }
                        workspace
                            .issues
                            .upsert(issue_from_finding(self.live_audit, &finding));
                    }
                }
                workspace.events.push(
                    now_ms(),
                    EventLevel::Info,
                    "Proxy",
                    format!("{method} {target} returned {status}"),
                    Some(self.passive_crawl),
                );
            }
            Event::AttackResult { .. } | Event::AttackDone { .. } => {
                self.apply_attack(workspace, event);
            }
            Event::Error(message) => {
                let task_id = self.active_task(workspace);
                workspace
                    .events
                    .push(now_ms(), EventLevel::Error, "Engine", message, task_id);
                if let Some(task_id) = task_id {
                    if let Some(task) = workspace.tasks.get_mut(task_id) {
                        task.progress.status = format!("Error: {message}");
                    }
                }
            }
            Event::Listening { port } => {
                workspace.events.push(
                    now_ms(),
                    EventLevel::Info,
                    "Proxy",
                    format!("Listener started on 127.0.0.1:{port}"),
                    Some(self.passive_crawl),
                );
            }
            Event::ListenerStopped => {
                workspace.events.push(
                    now_ms(),
                    EventLevel::Warning,
                    "Proxy",
                    "Listener stopped",
                    Some(self.passive_crawl),
                );
            }
            _ => {}
        }
    }

    pub fn apply_scan(&mut self, workspace: &mut Workspace, update: &ScanUpdate) {
        let task_id = self.ensure_scan(workspace);
        match update {
            ScanUpdate::Progress(status) => {
                if let Some(task) = workspace.tasks.get_mut(task_id) {
                    task.progress.status = status.clone();
                }
                workspace
                    .events
                    .push(now_ms(), EventLevel::Info, "Scanner", status, Some(task_id));
            }
            ScanUpdate::Live {
                status,
                completed,
                total,
                findings,
                ..
            } => {
                for finding in findings {
                    workspace
                        .issues
                        .upsert(issue_from_finding(task_id, finding));
                }
                if let Some(task) = workspace.tasks.get_mut(task_id) {
                    task.progress.completed = *completed as u64;
                    task.progress.total = Some((*total).max(1) as u64);
                    task.progress.status = status.clone();
                }
            }
            ScanUpdate::Done { findings, pages } => {
                for finding in findings {
                    workspace
                        .issues
                        .upsert(issue_from_finding(task_id, finding));
                }
                if let Some(task) = workspace.tasks.get_mut(task_id) {
                    task.progress = TaskProgress {
                        completed: pages.len() as u64,
                        total: Some(pages.len() as u64),
                        status: format!("Scan finished: {} issue(s)", findings.len()),
                    };
                }
                complete_once(workspace, task_id);
                workspace.events.push(
                    now_ms(),
                    EventLevel::Info,
                    "Scanner",
                    format!("Scan finished with {} issue(s)", findings.len()),
                    Some(task_id),
                );
            }
        }
    }

    pub fn apply_discover(&mut self, workspace: &mut Workspace, update: &discover::Update) {
        let task_id = match update {
            discover::Update::Probing { total, .. } => self.begin_discover(workspace, *total),
            _ => self.ensure_discover(workspace),
        };
        match update {
            discover::Update::Probing { host, done, total } => {
                if let Some(task) = workspace.tasks.get_mut(task_id) {
                    task.progress = TaskProgress {
                        completed: *done as u64,
                        total: Some(*total as u64),
                        status: format!("Probing {host}"),
                    };
                }
            }
            discover::Update::Found(finding) => {
                workspace.events.push(
                    now_ms(),
                    EventLevel::Info,
                    "Discover",
                    format!("{} returned {}", finding.url, finding.status),
                    Some(task_id),
                );
            }
            discover::Update::Done { probes } => {
                if let Some(task) = workspace.tasks.get_mut(task_id) {
                    task.progress.completed = *probes as u64;
                    task.progress.total = Some(*probes as u64);
                    task.progress.status = format!("{probes} answer(s)");
                }
                complete_once(workspace, task_id);
            }
        }
    }

    pub fn apply_attack(&mut self, workspace: &mut Workspace, event: &Event) {
        let task_id = match self.attack_task {
            Some(id) if workspace.tasks.get(id).is_some() => id,
            _ => self.begin_attack(workspace, "unknown target", 0),
        };
        match event {
            Event::AttackResult { index, error, .. } => {
                if let Some(task) = workspace.tasks.get_mut(task_id) {
                    task.progress.completed = task.progress.completed.max(*index as u64 + 1);
                    task.progress.status = error
                        .as_ref()
                        .map(|error| format!("Request failed: {error}"))
                        .unwrap_or_else(|| "Sending requests".into());
                }
                if let Some(error) = error {
                    workspace.events.push(
                        now_ms(),
                        EventLevel::Error,
                        "Intruder",
                        error,
                        Some(task_id),
                    );
                }
            }
            Event::AttackDone { total, matches } => {
                if let Some(task) = workspace.tasks.get_mut(task_id) {
                    task.progress = TaskProgress {
                        completed: *total as u64,
                        total: Some(*total as u64),
                        status: format!("Finished: {matches} match(es)"),
                    };
                }
                complete_once(workspace, task_id);
            }
            _ => {}
        }
    }

    fn ensure_scan(&mut self, workspace: &mut Workspace) -> TaskId {
        match self.scan_task {
            Some(id) if workspace.tasks.get(id).is_some() => id,
            _ => self.begin_scan(workspace, "current target"),
        }
    }

    fn ensure_discover(&mut self, workspace: &mut Workspace) -> TaskId {
        match self.discover_task {
            Some(id) if workspace.tasks.get(id).is_some() => id,
            _ => self.begin_discover(workspace, 0),
        }
    }

    fn active_task(&self, workspace: &Workspace) -> Option<TaskId> {
        [self.scan_task, self.attack_task, self.discover_task]
            .into_iter()
            .flatten()
            .find(|id| {
                workspace
                    .tasks
                    .get(*id)
                    .is_some_and(|task| task.state == TaskState::Running)
            })
            .or_else(|| {
                workspace
                    .tasks
                    .get(self.live_audit)
                    .filter(|task| task.state == TaskState::Running)
                    .map(|task| task.id)
            })
    }
}

fn begin_task(
    workspace: &mut Workspace,
    slot: &mut Option<TaskId>,
    kind: TaskKind,
    name: String,
    configuration: &str,
    total: Option<u64>,
) -> TaskId {
    if let Some(id) = *slot {
        if workspace
            .tasks
            .get(id)
            .is_some_and(|task| !task.state.is_terminal())
        {
            return id;
        }
    }
    let id = workspace.tasks.create(kind, name, configuration, now_ms());
    workspace.tasks.start(id).expect("new task starts");
    workspace
        .tasks
        .update_progress(
            id,
            TaskProgress {
                completed: 0,
                total,
                status: "Running".into(),
            },
        )
        .expect("running task accepts progress");
    *slot = Some(id);
    id
}

fn increment_task(workspace: &mut Workspace, id: TaskId, status: &str) {
    if let Some(task) = workspace.tasks.get_mut(id) {
        if task.state == TaskState::Running {
            task.progress.completed = task.progress.completed.saturating_add(1);
            task.progress.status = status.into();
        }
    }
}

fn complete_once(workspace: &mut Workspace, id: TaskId) {
    if workspace
        .tasks
        .get(id)
        .is_some_and(|task| !task.state.is_terminal())
    {
        let _ = workspace.tasks.complete(id);
    }
}

fn issue_from_finding(task_id: TaskId, finding: &scanner::Finding) -> IssueRecord {
    let severity = match finding.severity {
        scanner::Severity::Info => IssueSeverity::Info,
        scanner::Severity::Low => IssueSeverity::Low,
        scanner::Severity::Medium => IssueSeverity::Medium,
        scanner::Severity::High => IssueSeverity::High,
    };
    IssueRecord::new(
        task_id,
        &finding.name,
        severity,
        &finding.confidence,
        &finding.url,
        finding.parameter.clone(),
        &finding.evidence,
        now_ms(),
    )
}

fn now_ms() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis() as u64
}
