use std::collections::VecDeque;

use serde::{Deserialize, Serialize};

use super::TaskId;

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct EventId(pub u64);

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum EventLevel {
    Debug,
    Info,
    Warning,
    Error,
    Critical,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct EventRecord {
    pub id: EventId,
    pub timestamp_unix_ms: u64,
    pub level: EventLevel,
    pub source: String,
    pub message: String,
    pub task_id: Option<TaskId>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct EventStore {
    capacity: usize,
    next_id: u64,
    records: VecDeque<EventRecord>,
}

impl Default for EventStore {
    fn default() -> Self {
        Self::with_capacity(Self::DEFAULT_CAPACITY)
    }
}

impl EventStore {
    pub const DEFAULT_CAPACITY: usize = 2_000;

    pub fn with_capacity(capacity: usize) -> Self {
        Self {
            capacity: capacity.max(1),
            next_id: 1,
            records: VecDeque::new(),
        }
    }

    pub fn push(
        &mut self,
        timestamp_unix_ms: u64,
        level: EventLevel,
        source: impl Into<String>,
        message: impl Into<String>,
        task_id: Option<TaskId>,
    ) -> EventId {
        let id = EventId(self.next_id);
        self.next_id += 1;
        self.records.push_back(EventRecord {
            id,
            timestamp_unix_ms,
            level,
            source: source.into(),
            message: message.into(),
            task_id,
        });
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

    pub fn iter(&self) -> impl Iterator<Item = &EventRecord> {
        self.records.iter()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn event_store_drops_the_oldest_record_at_capacity() {
        let mut events = EventStore::with_capacity(3);
        for index in 0..4 {
            events.push(
                index,
                EventLevel::Info,
                "Scanner",
                format!("event-{index}"),
                None,
            );
        }
        assert_eq!(events.len(), 3);
        assert_eq!(
            events
                .iter()
                .map(|event| event.message.as_str())
                .collect::<Vec<_>>(),
            vec!["event-1", "event-2", "event-3"]
        );
    }
}
