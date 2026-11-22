//! Owns the configured storage backends.
//!
//! [`StorageManager`] builds the backends from config; [`StorageManager::start`] turns it into a
//! running [`Storage`] with one writer task per sink (batching by size and time, retention for
//! sinks without their own). Still to come in phase 2: spool and replay, the state-store outage
//! buffer and the host cache.

pub mod config;
pub mod registry;
mod run;
mod writer;

use std::sync::Arc;

use scribe_storage_api::{EventSink, Result, StateStore, StoredEvent};

pub use config::{BackendConfig, SinkConfig, StorageConfig};
pub use registry::Registry;
pub use run::{RunOptions, Storage};
pub use writer::{SinkCounters, SinkStatus};

pub struct StorageManager {
    state: Arc<dyn StateStore>,
    sinks: Vec<(SinkConfig, Arc<dyn EventSink>)>,
}

impl StorageManager {
    pub fn from_config(registry: &Registry, config: &StorageConfig) -> Result<Self> {
        let state = Arc::from(registry.build_state(&config.state)?);
        let sinks = config
            .sinks
            .iter()
            .map(|cfg| {
                registry
                    .build_sink(cfg)
                    .map(|sink| (cfg.clone(), Arc::from(sink)))
            })
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

    /// Write events to every sink subscribed to their kind, one sink after another, before
    /// [`StorageManager::start`]. A running [`Storage`] queues them instead.
    pub async fn publish(&self, events: &[StoredEvent]) -> Result<()> {
        for (cfg, sink) in &self.sinks {
            let selected: Vec<StoredEvent> = events
                .iter()
                .filter(|e| cfg.accepts(&e.kind()))
                .cloned()
                .collect();
            if !selected.is_empty() {
                sink.write_batch(&selected).await?;
            }
        }
        Ok(())
    }
}
