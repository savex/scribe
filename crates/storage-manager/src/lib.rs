//! Owns the configured storage backends.
//!
//! Planned responsibilities on top of what is here:
//! - in-memory LRU of hosts / baselines in front of the state store
//! - per-sink writer tasks that batch by size or time
//! - local spool + replay when a sink is down
//! - retention for sinks without native retention

pub mod config;
pub mod registry;

use scribe_storage_api::{EventSink, Result, StateStore, StoredEvent};

pub use config::{BackendConfig, SinkConfig, StorageConfig};
pub use registry::Registry;

pub struct StorageManager {
    state: Box<dyn StateStore>,
    sinks: Vec<(SinkConfig, Box<dyn EventSink>)>,
}

impl StorageManager {
    pub fn from_config(registry: &Registry, config: &StorageConfig) -> Result<Self> {
        let state = registry.build_state(&config.state)?;
        let sinks = config
            .sinks
            .iter()
            .map(|cfg| registry.build_sink(cfg).map(|sink| (cfg.clone(), sink)))
            .collect::<Result<_>>()?;
        Ok(Self { state, sinks })
    }

    pub fn state(&self) -> &dyn StateStore {
        self.state.as_ref()
    }

    pub fn sinks(&self) -> impl Iterator<Item = &dyn EventSink> {
        self.sinks.iter().map(|(_, sink)| sink.as_ref())
    }

    pub async fn migrate(&self) -> Result<()> {
        self.state.migrate().await?;
        for (_, sink) in &self.sinks {
            sink.migrate().await?;
        }
        Ok(())
    }

    /// Send events to every sink subscribed to their kind.
    // TODO: move to buffered per-sink tasks so one slow sink cannot block the others.
    pub async fn publish(&self, events: &[StoredEvent]) -> Result<()> {
        for (cfg, sink) in &self.sinks {
            let selected: Vec<StoredEvent> =
                events.iter().filter(|e| cfg.accepts(e.kind())).cloned().collect();
            if !selected.is_empty() {
                sink.write_batch(&selected).await?;
            }
        }
        Ok(())
    }
}
