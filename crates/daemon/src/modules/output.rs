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
}

impl QueueEmitter {
    fn send(&self, item: Output) {
        match self.tx.try_send(item) {
            Ok(()) => {}
            Err(TrySendError::Full(_) | TrySendError::Disconnected(_)) => {
                self.dropped.fetch_add(1, Ordering::Relaxed);
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
}

impl OutputQueue {
    pub fn new(capacity: usize) -> Self {
        let (tx, rx) = sync_channel(capacity);
        Self {
            tx,
            rx,
            dropped: Arc::default(),
        }
    }

    pub fn emitter(&self, module: &'static str) -> Arc<dyn Emitter> {
        Arc::new(QueueEmitter {
            module,
            tx: self.tx.clone(),
            dropped: self.dropped.clone(),
        })
    }

    /// Everything queued so far.
    pub fn take(&self) -> Vec<Output> {
        self.rx.try_iter().collect()
    }

    pub fn dropped(&self) -> u64 {
        self.dropped.load(Ordering::Relaxed)
    }
}
