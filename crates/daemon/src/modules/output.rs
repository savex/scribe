//! Module output on its way to storage: a bounded queue per daemon, drained by an async task.
//! Emitting never blocks a module; when the queue is full the item is dropped and counted.

use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::mpsc::{sync_channel, Receiver, SyncSender, TrySendError};
use std::sync::Arc;

use scribe_core::{MetricSample, ModuleRecord};
use scribe_module_api::Emitter;
use scribe_storage_api::StoredEvent;
use serde_json::Value;

/// Default queue length for module output.
pub const QUEUE: usize = 10_000;

#[derive(Debug, Clone)]
pub enum Output {
    Event(StoredEvent),
    State {
        module: &'static str,
        key: String,
        value: Value,
    },
}

/// One emitter per module, all feeding the same queue.
pub struct QueueEmitter {
    module: &'static str,
    tx: SyncSender<Output>,
    dropped: Arc<AtomicU64>,
    /// This module's share of `dropped`.
    own: Arc<AtomicU64>,
}

impl QueueEmitter {
    fn send(&self, item: Output) {
        match self.tx.try_send(item) {
            Ok(()) => {}
            Err(TrySendError::Full(_) | TrySendError::Disconnected(_)) => {
                self.dropped.fetch_add(1, Ordering::Relaxed);
                self.own.fetch_add(1, Ordering::Relaxed);
            }
        }
    }
}

impl Emitter for QueueEmitter {
    fn record(&self, record: ModuleRecord) {
        self.send(Output::Event(StoredEvent::Module(record)));
    }

    fn metric(&self, sample: MetricSample) {
        self.send(Output::Event(StoredEvent::Metric(sample)));
    }

    fn put_state(&self, key: &str, value: Value) {
        self.send(Output::State {
            module: self.module,
            key: key.to_owned(),
            value,
        });
    }
}

/// The queue and its drop counter.
pub struct OutputQueue {
    tx: SyncSender<Output>,
    rx: Receiver<Output>,
    dropped: Arc<AtomicU64>,
    per_module: std::sync::Mutex<Vec<(&'static str, Arc<AtomicU64>)>>,
}

impl OutputQueue {
    pub fn new(capacity: usize) -> Self {
        let (tx, rx) = sync_channel(capacity);
        Self {
            tx,
            rx,
            dropped: Arc::default(),
            per_module: std::sync::Mutex::default(),
        }
    }

    pub fn emitter(&self, module: &'static str) -> Arc<dyn Emitter> {
        let own = {
            let mut per_module = self.per_module.lock().unwrap_or_else(|e| e.into_inner());
            match per_module.iter().find(|(id, _)| *id == module) {
                Some((_, counter)) => counter.clone(),
                None => {
                    let counter = Arc::new(AtomicU64::new(0));
                    per_module.push((module, counter.clone()));
                    counter
                }
            }
        };
        Arc::new(QueueEmitter {
            module,
            tx: self.tx.clone(),
            dropped: self.dropped.clone(),
            own,
        })
    }

    /// Items of `module` dropped because the queue was full.
    pub fn dropped_by(&self, module: &str) -> u64 {
        let per_module = self.per_module.lock().unwrap_or_else(|e| e.into_inner());
        per_module
            .iter()
            .find(|(id, _)| *id == module)
            .map_or(0, |(_, c)| c.load(Ordering::Relaxed))
    }

    /// Everything queued so far.
    pub fn take(&self) -> Vec<Output> {
        self.rx.try_iter().collect()
    }

    pub fn dropped(&self) -> u64 {
        self.dropped.load(Ordering::Relaxed)
    }
}
