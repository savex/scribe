use std::time::Duration;

use scribe_storage_api::{BackendOptions, EventKind};

/// One backend instance: `kind = "sqlite"` plus its options.
#[derive(Debug, Clone)]
pub struct BackendConfig {
    pub kind: String,
    pub options: BackendOptions,
}

#[derive(Debug, Clone)]
pub struct SinkConfig {
    pub name: String,
    pub backend: BackendConfig,
    /// Empty means all event kinds.
    pub events: Vec<EventKind>,
    /// `None` keeps events forever.
    pub retention: Option<Duration>,
    /// Write a batch when this many events are waiting...
    pub batch_max_events: u32,
    /// ...or when the oldest has waited this long.
    pub batch_max_wait: Duration,
}

impl SinkConfig {
    /// A sink with the default retention (30 days) and batching (500 events or 1 s).
    pub fn new(name: impl Into<String>, backend: BackendConfig) -> Self {
        Self {
            name: name.into(),
            backend,
            events: vec![],
            retention: Some(Duration::from_secs(30 * 86_400)),
            batch_max_events: 500,
            batch_max_wait: Duration::from_secs(1),
        }
    }
}

impl SinkConfig {
    pub fn accepts(&self, kind: EventKind) -> bool {
        self.events.is_empty() || self.events.contains(&kind)
    }
}

#[derive(Debug, Clone)]
pub struct StorageConfig {
    pub state: BackendConfig,
    pub sinks: Vec<SinkConfig>,
}

impl StorageConfig {
    /// Single local SQLite file used as both state store and event history.
    pub fn sqlite_default(path: &str) -> Self {
        let backend = BackendConfig {
            kind: "sqlite".into(),
            options: BackendOptions::from([("path".to_owned(), path.to_owned())]),
        };
        Self {
            state: backend.clone(),
            sinks: vec![SinkConfig::new("local-history", backend)],
        }
    }
}
