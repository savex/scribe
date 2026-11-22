//! The running storage: writer tasks per sink behind a non-blocking `publish`.

use std::sync::Arc;
use std::time::Duration;

use scribe_core::{Clock, SystemClock};
use scribe_storage_api::{Health, StateStore, StoredEvent};
use tokio::sync::{mpsc, oneshot};
use tokio::task::JoinHandle;

use crate::cache::{CacheLimits, CacheStatus, CachedState};
use crate::spool::{Spool, SpoolBudget, SpoolOptions};
use crate::state::{BufferLimits, BufferedState, StateStatus};
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
    /// The in-memory buffer for state-store outages.
    pub buffer: BufferLimits,
    /// The host and baseline cache.
    pub cache: CacheLimits,
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
            buffer: BufferLimits::default(),
            cache: CacheLimits::default(),
        }
    }
}

struct SinkHandle {
    config: SinkConfig,
    sink: Arc<dyn scribe_storage_api::EventSink>,
    tx: mpsc::Sender<Command>,
    counters: Arc<SinkCounters>,
    task: JoinHandle<()>,
}

/// Storage with its writer tasks running. Created by [`StorageManager::start`] inside a Tokio
/// runtime.
pub struct Storage {
    state: Arc<CachedState>,
    buffered: Arc<BufferedState>,
    sinks: Vec<SinkHandle>,
    replay: JoinHandle<()>,
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
                    sink: sink.clone(),
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
                    sink,
                    tx,
                    counters,
                    task,
                }
            })
            .collect();
        let buffered = Arc::new(BufferedState::new(self.state, options.buffer));
        let state = Arc::new(CachedState::new(buffered.clone(), options.cache));
        let replay = tokio::spawn(replay_state(
            buffered.clone(),
            options.retry_min,
            options.retry_max,
        ));
        Storage {
            state,
            buffered,
            sinks,
            replay,
        }
    }
}

impl Storage {
    /// The state store, with the host cache and the outage buffer in front of it.
    pub fn state(&self) -> &dyn StateStore {
        self.state.as_ref()
    }

    pub fn state_status(&self) -> StateStatus {
        self.buffered.status()
    }

    pub fn cache_status(&self) -> CacheStatus {
        self.state.status()
    }

    /// Empty the host and baseline cache (`scribe daemon reset --caches`).
    pub fn clear_cache(&self) {
        self.state.clear();
    }

    /// Health of the state store and of every sink; the overall result is the worst of them.
    pub async fn health(&self) -> StorageHealth {
        let state = self.state.health().await;
        let mut sinks = Vec::new();
        for handle in &self.sinks {
            let status = handle.counters.snapshot(&handle.config.name);
            let health = if status.spool_events > 0 {
                Health::Degraded(format!(
                    "spooling {} events ({} bytes)",
                    status.spool_events, status.spool_bytes
                ))
            } else {
                match handle.sink.health().await {
                    Health::Ok if status.dropped_queue_full + status.dropped_write_failed > 0 => {
                        Health::Degraded(format!(
                            "{} events dropped",
                            status.dropped_queue_full + status.dropped_write_failed
                        ))
                    }
                    other => other,
                }
            };
            sinks.push((handle.config.name.clone(), health));
        }
        let overall = std::iter::once(&state)
            .chain(sinks.iter().map(|(_, h)| h))
            .fold(Health::Ok, worse);
        StorageHealth {
            overall,
            state,
            sinks,
        }
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

    /// Write what is queued, stop the writer tasks and flush the sinks. Buffered state writes get
    /// one last replay; whatever still can't be stored is lost (and was counted as buffered).
    pub async fn shutdown(self) {
        self.replay.abort();
        self.buffered.replay().await;
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

/// Health of the storage as a whole and of each part.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StorageHealth {
    pub overall: Health,
    pub state: Health,
    pub sinks: Vec<(String, Health)>,
}

fn rank(h: &Health) -> u8 {
    match h {
        Health::Ok => 0,
        Health::Degraded(_) => 1,
        Health::Down(_) => 2,
    }
}

fn worse(a: Health, b: &Health) -> Health {
    if rank(b) > rank(&a) {
        b.clone()
    } else {
        a
    }
}

/// Replays the state buffer while it holds writes: every `retry_min`, doubling to `retry_max`
/// while the store stays down.
async fn replay_state(state: Arc<BufferedState>, retry_min: Duration, retry_max: Duration) {
    let mut wait = retry_min;
    loop {
        tokio::time::sleep(wait).await;
        if !state.is_buffering() {
            wait = retry_min;
            continue;
        }
        wait = if state.replay().await {
            retry_min
        } else {
            (wait * 2).min(retry_max)
        };
    }
}
