use std::collections::VecDeque;

use serde::{Deserialize, Serialize};

use super::TaskId;

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct IssueId(pub u64);

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub enum IssueSeverity {
    Info,
    Low,
    Medium,
    High,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct IssueRecord {
    pub id: IssueId,
    pub task_id: TaskId,
    pub name: String,
    pub severity: IssueSeverity,
    pub confidence: String,
    pub url: String,
    pub parameter: Option<String>,
    pub evidence: String,
    pub observed_unix_ms: u64,
}

impl IssueRecord {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        task_id: TaskId,
        name: impl Into<String>,
        severity: IssueSeverity,
        confidence: impl Into<String>,
        url: impl Into<String>,
        parameter: Option<String>,
        evidence: impl Into<String>,
        observed_unix_ms: u64,
    ) -> Self {
        Self {
            id: IssueId(0),
            task_id,
            name: name.into(),
            severity,
            confidence: confidence.into(),
            url: url.into(),
            parameter,
            evidence: evidence.into(),
            observed_unix_ms,
        }
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct IssueStore {
    capacity: usize,
    next_id: u64,
    records: VecDeque<IssueRecord>,
}

impl Default for IssueStore {
    fn default() -> Self {
        Self::with_capacity(Self::DEFAULT_CAPACITY)
    }
}

impl IssueStore {
    pub const DEFAULT_CAPACITY: usize = 2_000;

    pub fn with_capacity(capacity: usize) -> Self {
        Self {
            capacity: capacity.max(1),
            next_id: 1,
            records: VecDeque::new(),
        }
    }

    pub fn upsert(&mut self, mut issue: IssueRecord) -> IssueId {
        if let Some(existing) = self.records.iter_mut().find(|existing| {
            existing.task_id == issue.task_id
                && existing.name == issue.name
                && existing.url == issue.url
                && existing.parameter == issue.parameter
                && existing.evidence == issue.evidence
        }) {
            issue.id = existing.id;
            *existing = issue;
            return existing.id;
        }
        let id = IssueId(self.next_id);
        self.next_id += 1;
        issue.id = id;
        self.records.push_back(issue);
        while self.records.len() > self.capacity {
            self.records.pop_front();
        }
        id
    }

    pub fn len(&self) -> usize {
        self.records.len()
    }

    pub fn is_empty(&self) -> bool {
        self.records.is_empty()
    }

    pub fn iter(&self) -> impl Iterator<Item = &IssueRecord> {
        self.records.iter()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::workspace::TaskId;

    fn issue(task_id: TaskId, evidence: &str) -> IssueRecord {
        IssueRecord::new(
            task_id,
            "Reflected input",
            IssueSeverity::Medium,
            "Firm",
            "https://a.test/?q=x",
            Some("q".into()),
            evidence,
            10,
        )
    }

    #[test]
    fn issue_store_is_bounded_and_deduplicates_identity() {
        let mut issues = IssueStore::with_capacity(3);
        let task = TaskId(7);
        let first = issues.upsert(issue(task, "one"));
        let duplicate = issues.upsert(issue(task, "one"));
        assert_eq!(first, duplicate);
        assert_eq!(issues.len(), 1);

        issues.upsert(issue(task, "two"));
        issues.upsert(issue(task, "three"));
        issues.upsert(issue(task, "four"));
        assert_eq!(issues.len(), 3);
        assert_eq!(
            issues
                .iter()
                .map(|issue| issue.evidence.as_str())
                .collect::<Vec<_>>(),
            vec!["two", "three", "four"]
        );
    }
}
