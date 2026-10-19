use std::cmp::Reverse;
use std::collections::{BTreeSet, VecDeque};

use serde::{Deserialize, Serialize};

#[derive(
    Clone, Copy, Debug, Default, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize,
)]
pub struct TaskId(pub u64);

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub enum TaskKind {
    PassiveCrawl,
    LiveAudit,
    Scan,
    Intruder,
    Discover,
    Other,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub enum TaskState {
    Queued,
    Running,
    Paused,
    Completed,
    Failed,
    Cancelled,
    Interrupted,
}

impl TaskState {
    pub fn is_terminal(self) -> bool {
        matches!(
            self,
            Self::Completed | Self::Failed | Self::Cancelled | Self::Interrupted
        )
    }
}

#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct TaskProgress {
    pub completed: u64,
    pub total: Option<u64>,
    pub status: String,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Task {
    pub id: TaskId,
    pub kind: TaskKind,
    pub name: String,
    pub configuration: String,
    pub state: TaskState,
    pub progress: TaskProgress,
    pub created_unix_ms: u64,
    pub failure: Option<String>,
}

#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct TaskQuery {
    pub states: BTreeSet<TaskState>,
    pub kinds: BTreeSet<TaskKind>,
    pub search: String,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct WorkspaceError(pub String);

impl std::fmt::Display for WorkspaceError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str(&self.0)
    }
}

impl std::error::Error for WorkspaceError {}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct TaskManager {
    capacity: usize,
    next_id: u64,
    tasks: VecDeque<Task>,
    selected: Option<TaskId>,
}

impl Default for TaskManager {
    fn default() -> Self {
        Self::with_capacity(Self::DEFAULT_CAPACITY)
    }
}

impl TaskManager {
    pub const DEFAULT_CAPACITY: usize = 1_000;

    pub fn with_capacity(capacity: usize) -> Self {
        Self {
            capacity: capacity.max(1),
            next_id: 1,
            tasks: VecDeque::new(),
            selected: None,
        }
    }

    pub fn seed_proxy_tasks() -> Self {
        let mut tasks = Self::default();
        let crawl = tasks.create(
            TaskKind::PassiveCrawl,
            "1. Live passive crawl from Proxy (all traffic)",
            "Add links. Add item itself, same domain and URLs in suite scope.",
            0,
        );
        tasks.start(crawl).expect("seeded crawl is queued");
        let audit = tasks.create(
            TaskKind::LiveAudit,
            "2. Live audit from Proxy (all traffic)",
            "Audit checks - passive",
            0,
        );
        tasks.start(audit).expect("seeded audit is queued");
        tasks.selected = Some(audit);
        tasks
    }

    pub fn create(
        &mut self,
        kind: TaskKind,
        name: impl Into<String>,
        configuration: impl Into<String>,
        created_unix_ms: u64,
    ) -> TaskId {
        let id = TaskId(self.next_id);
        self.next_id += 1;
        self.tasks.push_back(Task {
            id,
            kind,
            name: name.into(),
            configuration: configuration.into(),
            state: TaskState::Queued,
            progress: TaskProgress::default(),
            created_unix_ms,
            failure: None,
        });
        while self.tasks.len() > self.capacity {
            if let Some(removed) = self.tasks.pop_front() {
                if self.selected == Some(removed.id) {
                    self.selected = None;
                }
            }
        }
        if self.selected.is_none() {
            self.selected = Some(id);
        }
        id
    }

    pub fn is_empty(&self) -> bool {
        self.tasks.is_empty()
    }

    pub fn len(&self) -> usize {
        self.tasks.len()
    }

    pub fn iter(&self) -> impl Iterator<Item = &Task> {
        self.tasks.iter()
    }

    pub fn get(&self, id: TaskId) -> Option<&Task> {
        self.tasks.iter().find(|task| task.id == id)
    }

    pub fn get_mut(&mut self, id: TaskId) -> Option<&mut Task> {
        self.tasks.iter_mut().find(|task| task.id == id)
    }

    pub fn selected(&self) -> Option<TaskId> {
        self.selected
    }

    pub fn select(&mut self, id: TaskId) -> Result<(), WorkspaceError> {
        self.require(id)?;
        self.selected = Some(id);
        Ok(())
    }

    pub fn query(&self, query: &TaskQuery) -> Vec<&Task> {
        let needle = query.search.trim().to_lowercase();
        let mut matches: Vec<&Task> = self
            .tasks
            .iter()
            .filter(|task| query.states.is_empty() || query.states.contains(&task.state))
            .filter(|task| query.kinds.is_empty() || query.kinds.contains(&task.kind))
            .filter(|task| {
                needle.is_empty()
                    || task.name.to_lowercase().contains(&needle)
                    || task.configuration.to_lowercase().contains(&needle)
            })
            .collect();
        matches.sort_by_key(|task| (display_rank(task.kind), Reverse(task.id)));
        matches
    }

    pub fn rename(&mut self, id: TaskId, name: &str) -> Result<(), WorkspaceError> {
        let name = name.trim();
        if name.is_empty() {
            return Err(WorkspaceError("task name cannot be blank".into()));
        }
        self.require_mut(id)?.name = name.to_string();
        Ok(())
    }

    pub fn start(&mut self, id: TaskId) -> Result<(), WorkspaceError> {
        self.transition(id, &[TaskState::Queued], TaskState::Running)
    }

    pub fn pause(&mut self, id: TaskId) -> Result<(), WorkspaceError> {
        self.transition(id, &[TaskState::Running], TaskState::Paused)
    }

    pub fn resume(&mut self, id: TaskId) -> Result<(), WorkspaceError> {
        self.transition(id, &[TaskState::Paused], TaskState::Running)
    }

    pub fn complete(&mut self, id: TaskId) -> Result<(), WorkspaceError> {
        self.transition(
            id,
            &[TaskState::Queued, TaskState::Running, TaskState::Paused],
            TaskState::Completed,
        )
    }

    pub fn cancel(&mut self, id: TaskId) -> Result<(), WorkspaceError> {
        self.transition(
            id,
            &[TaskState::Queued, TaskState::Running, TaskState::Paused],
            TaskState::Cancelled,
        )
    }

    pub fn fail(&mut self, id: TaskId, error: impl Into<String>) -> Result<(), WorkspaceError> {
        let task = self.require_mut(id)?;
        if task.state.is_terminal() {
            return Err(invalid_transition(id, task.state, TaskState::Failed));
        }
        task.state = TaskState::Failed;
        task.failure = Some(error.into());
        Ok(())
    }

    pub fn update_progress(
        &mut self,
        id: TaskId,
        progress: TaskProgress,
    ) -> Result<(), WorkspaceError> {
        let task = self.require_mut(id)?;
        if task.state.is_terminal() {
            return Err(WorkspaceError(format!(
                "cannot update terminal task {}",
                id.0
            )));
        }
        task.progress = progress;
        Ok(())
    }

    fn transition(
        &mut self,
        id: TaskId,
        allowed: &[TaskState],
        next: TaskState,
    ) -> Result<(), WorkspaceError> {
        let task = self.require_mut(id)?;
        if !allowed.contains(&task.state) {
            return Err(invalid_transition(id, task.state, next));
        }
        task.state = next;
        Ok(())
    }

    fn require(&self, id: TaskId) -> Result<&Task, WorkspaceError> {
        self.get(id)
            .ok_or_else(|| WorkspaceError(format!("unknown task {}", id.0)))
    }

    fn require_mut(&mut self, id: TaskId) -> Result<&mut Task, WorkspaceError> {
        self.get_mut(id)
            .ok_or_else(|| WorkspaceError(format!("unknown task {}", id.0)))
    }
}

fn display_rank(kind: TaskKind) -> u8 {
    match kind {
        TaskKind::LiveAudit => 0,
        TaskKind::PassiveCrawl => 1,
        _ => 2,
    }
}

fn invalid_transition(id: TaskId, from: TaskState, to: TaskState) -> WorkspaceError {
    WorkspaceError(format!(
        "task {} cannot transition from {from:?} to {to:?}",
        id.0
    ))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn seeded_proxy_tasks_have_stable_ids_and_burp_display_order() {
        let tasks = TaskManager::seed_proxy_tasks();
        assert_eq!(tasks.get(TaskId(1)).unwrap().kind, TaskKind::PassiveCrawl);
        assert_eq!(tasks.get(TaskId(2)).unwrap().kind, TaskKind::LiveAudit);
        let shown: Vec<TaskId> = tasks
            .query(&TaskQuery::default())
            .iter()
            .map(|t| t.id)
            .collect();
        assert_eq!(shown, vec![TaskId(2), TaskId(1)]);
    }

    #[test]
    fn lifecycle_rejects_invalid_transitions() {
        let mut tasks = TaskManager::default();
        let id = tasks.create(TaskKind::Scan, "Scan", "https://a.test", 10);
        assert!(tasks.pause(id).is_err());
        tasks.start(id).unwrap();
        tasks.pause(id).unwrap();
        tasks.resume(id).unwrap();
        tasks.complete(id).unwrap();
        assert!(tasks.resume(id).is_err());
        assert!(tasks.cancel(id).is_err());
        assert!(tasks.fail(id, "late failure").is_err());
    }

    #[test]
    fn rename_rejects_blank_names() {
        let mut tasks = TaskManager::default();
        let id = tasks.create(TaskKind::Other, "Original", "", 10);
        assert!(tasks.rename(id, "  ").is_err());
        tasks.rename(id, "Renamed").unwrap();
        assert_eq!(tasks.get(id).unwrap().name, "Renamed");
    }

    #[test]
    fn query_combines_filters_without_losing_selection() {
        let mut tasks = TaskManager::default();
        let scan = tasks.create(TaskKind::Scan, "Checkout audit", "https://shop.test", 10);
        tasks.start(scan).unwrap();
        let attack = tasks.create(TaskKind::Intruder, "Login attack", "POST /login", 20);
        tasks.start(attack).unwrap();
        tasks.pause(attack).unwrap();
        tasks.select(scan).unwrap();

        let mut query = TaskQuery::default();
        query.kinds.insert(TaskKind::Intruder);
        query.states.insert(TaskState::Paused);
        query.search = "LOGIN".into();
        assert_eq!(
            tasks
                .query(&query)
                .iter()
                .map(|task| task.id)
                .collect::<Vec<_>>(),
            vec![attack]
        );

        query.search = "missing".into();
        assert!(tasks.query(&query).is_empty());
        assert_eq!(tasks.selected(), Some(scan));
    }
}
