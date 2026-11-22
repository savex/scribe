//! The running storage: writer tasks per sink behind a non-blocking `publish`.

use std::sync::Arc;
use std::time::Duration;

use scribe_core::{Clock, SystemClock};
use scribe_storage_api::{StateStore, StoredEvent};
use tokio::sync::{mpsc, oneshot};
use tokio::task::JoinHandle;

use crate::spool::{Spool, SpoolBudget, SpoolOptions};
use crate::writer::{Command, SinkCounters, SinkStatus, Writer};
use crate::{SinkConfig, StorageManager};

/// How the running storage behaves.
#[derive(Clone)]
pub struct RunOptions {
    /// Wall-clock time for retention cutoffs (timers use the runtime's monotonic clock).
    pub clock: Arc<dyn Clock>,
    /// Messages each sink queue holds before `publish` drops (and counts) events for it.
    pub queue_capacity: usize,
    /// How often retention runs for sinks without native retention.
    pub retention_every: Duration,
    /// Where failed batches wait for replay; `None` drops them (and counts the drops).
    pub spool: Option<SpoolOptions>,
    /// First retry after a failed write; doubled after each failure up to `retry_max`.
    pub retry_min: Duration,
    pub retry_max: Duration,
}

impl Default for RunOptions {
    fn default() -> Self {
        Self {
            clock: Arc::new(SystemClock),
            queue_capacity: 1024,
            retention_every: Duration::from_secs(3600),
            spool: None,
            retry_min: Duration::from_secs(1),
            retry_max: Duration::from_secs(60),
        }
    }
}

struct SinkHandle {
    config: SinkConfig,
    tx: mpsc::Sender<Command>,
    counters: Arc<SinkCounters>,
    task: JoinHandle<()>,
}

/// Storage with its writer tasks running. Created by [`StorageManager::start`] inside a Tokio
/// runtime.
pub struct Storage {
    state: Arc<dyn StateStore>,
    sinks: Vec<SinkHandle>,
}

impl StorageManager {
    /// Start one writer task per sink on the current Tokio runtime.
    pub fn start(self, options: RunOptions) -> Storage {
        let budget = options.spool.clone().map(SpoolBudget::new);
        let sinks = self
            .sinks
            .into_iter()
            .map(|(config, sink)| {
                let (tx, rx) = mpsc::channel(options.queue_capacity.max(1));
                let counters = Arc::new(SinkCounters::default());
                let writer = Writer {
                    config: config.clone(),
                    sink,
                    counters: counters.clone(),
                    clock: options.clock.clone(),
                    retention_every: options.retention_every,
                    spool: budget.as_ref().and_then(|b| {
                        Spool::open(b.clone(), &config.name)
                            .map_err(|e| {
                                tracing::warn!(sink = config.name, "spool unavailable: {e}")
                            })
                            .ok()
                    }),
                    retry_min: options.retry_min,
                    retry_max: options.retry_max,
                };
                let task = tokio::spawn(writer.run(rx));
                SinkHandle {
                    config,
                    tx,
                    counters,
                    task,
                }
            })
            .collect();
        Storage {
            state: self.state,
            sinks,
        }
    }
}

impl Storage {
    pub fn state(&self) -> &dyn StateStore {
        self.state.as_ref()
    }

    /// Queue events for every sink subscribed to their kind. Never waits: when a sink's queue is
    /// full its share is dropped and counted, so a slow sink can't hold up capture (NFR-7).
    pub fn publish(&self, events: &[StoredEvent]) {
        for sink in &self.sinks {
            let selected: Vec<StoredEvent> = events
                .iter()
                .filter(|e| sink.config.accepts(&e.kind()))
                .cloned()
                .collect();
            if selected.is_empty() {
                continue;
            }
            let n = selected.len() as u64;
            match sink.tx.try_send(Command::Events(selected)) {
                Ok(()) => {
                    sink.counters
                        .queued
                        .fetch_add(n, std::sync::atomic::Ordering::Relaxed);
                }
                Err(_) => {
                    sink.counters
                        .dropped_queue_full
                        .fetch_add(n, std::sync::atomic::Ordering::Relaxed);
                }
            }
        }
    }

    /// Wait until every sink has written what was queued before this call.
    pub async fn flush(&self) {
        let mut waits = Vec::new();
        for sink in &self.sinks {
            let (done, wait) = oneshot::channel();
            if sink.tx.send(Command::Flush(done)).await.is_ok() {
                waits.push(wait);
            }
        }
        for wait in waits {
            let _ = wait.await;
        }
    }

    pub fn sink_status(&self) -> Vec<SinkStatus> {
        self.sinks
            .iter()
            .map(|s| s.counters.snapshot(&s.config.name))
            .collect()
    }

    /// Write what is queued, stop the writer tasks and flush the sinks.
    pub async fn shutdown(self) {
        let mut tasks = Vec::new();
        for sink in self.sinks {
            drop(sink.tx);
            tasks.push(sink.task);
        }
        for task in tasks {
            let _ = task.await;
        }
    }
}
