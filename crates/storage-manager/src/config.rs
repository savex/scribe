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
            sinks: vec![SinkConfig { name: "local-history".into(), backend, events: vec![] }],
        }
    }
}
