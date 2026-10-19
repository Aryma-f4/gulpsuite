mod event;
mod issue;
mod task;

pub use event::*;
pub use issue::*;
pub use task::*;

use serde::{Deserialize, Serialize};

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Workspace {
    #[serde(default)]
    pub tasks: TaskManager,
    #[serde(default)]
    pub events: EventStore,
    #[serde(default)]
    pub issues: IssueStore,
}

impl Default for Workspace {
    fn default() -> Self {
        Self {
            tasks: TaskManager::default(),
            events: EventStore::default(),
            issues: IssueStore::default(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn workspace_default_is_bounded_and_empty() {
        let workspace = Workspace::default();
        assert!(workspace.tasks.is_empty());
        assert!(workspace.events.is_empty());
        assert!(workspace.issues.is_empty());
    }
}
