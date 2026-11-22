//! Spool and replay while a sink is down: order, back-off, limits, restart. Paused Tokio time;
//! the spool lives in a temporary folder per test.

use std::collections::HashMap;
use std::path::Path;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, SystemTime};

use scribe_storage_api::{
    AuditRecord, BackendOptions, BoxFuture, EventQuery, EventSink, Health, Page, Result, SinkCaps,
    StateStore, StorageError, StorageFactory, StoredEvent,
};
use scribe_storage_manager::{
    BackendConfig, Registry, RunOptions, SinkConfig, SpoolOptions, Storage, StorageConfig,
    StorageManager,
};
use scribe_test_support::MemoryStore;
use tokio::time::sleep;

/// Records the audit messages it receives, in order; can be switched to failing.
#[derive(Default)]
struct Flaky {
    received: Mutex<Vec<String>>,
    failing: AtomicBool,
    attempts: AtomicU64,
}

impl Flaky {
    fn failing() -> Arc<Self> {
        let s = Self::default();
        s.failing.store(true, Ordering::SeqCst);
        Arc::new(s)
    }
    fn received(&self) -> Vec<String> {
        self.received.lock().unwrap().clone()
    }
    fn set_failing(&self, on: bool) {
        self.failing.store(on, Ordering::SeqCst);
    }
}

struct Shared(Arc<Flaky>);

impl EventSink for Shared {
    fn name(&self) -> &str {
        "flaky"
    }
    fn capabilities(&self) -> SinkCaps {
        SinkCaps {
            queryable: false,
            native_retention: true,
            max_batch: 1000,
        }
    }
    fn migrate(&self) -> BoxFuture<'_, Result<()>> {
        Box::pin(async { Ok(()) })
    }
    fn write_batch<'a>(&'a self, batch: &'a [StoredEvent]) -> BoxFuture<'a, Result<()>> {
        Box::pin(async move {
            self.0.attempts.fetch_add(1, Ordering::SeqCst);
            if self.0.failing.load(Ordering::SeqCst) {
                return Err(StorageError::backend(std::io::Error::other("down")));
            }
            let mut got = self.0.received.lock().unwrap();
            for e in batch {
                if let StoredEvent::Audit(a) = e {
                    got.push(a.message.clone());
                }
            }
            Ok(())
        })
    }
    fn query<'a>(&'a self, _q: &'a EventQuery) -> BoxFuture<'a, Result<Page<StoredEvent>>> {
        Box::pin(async {
            Ok(Page {
                items: vec![],
                total: None,
            })
        })
    }
    fn flush(&self) -> BoxFuture<'_, Result<()>> {
        Box::pin(async { Ok(()) })
    }
    fn health(&self) -> BoxFuture<'_, Health> {
        Box::pin(async { Health::Ok })
    }
}

struct Factory(Arc<Flaky>);

impl StorageFactory for Factory {
    fn kind(&self) -> &'static str {
        "flaky"
    }
    fn build_state(&self, _o: &BackendOptions) -> Option<Result<Box<dyn StateStore>>> {
        Some(Ok(Box::new(MemoryStore::default())))
    }
    fn build_sink(&self, _n: &str, _o: &BackendOptions) -> Option<Result<Box<dyn EventSink>>> {
        Some(Ok(Box::new(Shared(self.0.clone()))))
    }
}

fn start(sink: &Arc<Flaky>, spool: Option<SpoolOptions>) -> Storage {
    let mut registry = Registry::new();
    registry.register(Box::new(Factory(sink.clone())));
    let backend = BackendConfig {
        kind: "flaky".into(),
        options: BackendOptions::new(),
    };
    let mut cfg = SinkConfig::new("central", backend.clone());
    cfg.batch_max_events = 1;
    cfg.retention = None;
    let config = StorageConfig {
        state: backend,
        sinks: vec![cfg],
    };
    StorageManager::from_config(&registry, &config)
        .unwrap()
        .start(RunOptions {
            spool,
            ..Default::default()
        })
}

fn spool_in(dir: &Path) -> SpoolOptions {
    let mut o = SpoolOptions::new(dir, 1 << 20, 0);
    o.free_space = Arc::new(|_: &Path| Ok(u64::MAX));
    o
}

fn audit(i: usize) -> StoredEvent {
    StoredEvent::Audit(AuditRecord {
        ts: SystemTime::UNIX_EPOCH + Duration::from_secs(i as u64),
        message: format!("e{i}"),
    })
}

fn names(range: std::ops::Range<usize>) -> Vec<String> {
    range.map(|i| format!("e{i}")).collect()
}

#[tokio::test(start_paused = true)]
async fn failed_writes_are_spooled_and_replayed_in_order() {
    let dir = tempfile::tempdir().unwrap();
    let sink = Flaky::failing();
    let storage = start(&sink, Some(spool_in(dir.path())));
    for i in 0..5 {
        storage.publish(&[audit(i)]);
    }
    sleep(Duration::from_millis(10)).await;
    let s = storage.sink_status()[0].clone();
    assert_eq!((s.spooled, s.spool_events, s.written), (5, 5, 0), "{s:?}");
    assert!(!s.healthy());

    sink.set_failing(false);
    sleep(Duration::from_secs(1)).await;
    assert_eq!(sink.received(), names(0..5));
    let s = storage.sink_status()[0].clone();
    assert_eq!(
        (s.replayed, s.spool_events, s.spool_bytes),
        (5, 0, 0),
        "{s:?}"
    );
    assert!(s.healthy());
}

#[tokio::test(start_paused = true)]
async fn new_batches_wait_behind_the_spool() {
    let dir = tempfile::tempdir().unwrap();
    let sink = Flaky::failing();
    let storage = start(&sink, Some(spool_in(dir.path())));
    storage.publish(&[audit(0)]);
    sleep(Duration::from_millis(10)).await;
    sink.set_failing(false);
    storage.publish(&[audit(1)]);
    sleep(Duration::from_millis(10)).await;
    assert!(
        sink.received().is_empty(),
        "e1 must not overtake the spooled e0"
    );
    sleep(Duration::from_secs(1)).await;
    assert_eq!(sink.received(), names(0..2));
}

#[tokio::test(start_paused = true)]
async fn retries_back_off() {
    let dir = tempfile::tempdir().unwrap();
    let sink = Flaky::failing();
    let storage = start(&sink, Some(spool_in(dir.path())));
    storage.publish(&[audit(0)]);
    sleep(Duration::from_millis(10)).await;
    let attempts = || sink.attempts.load(Ordering::SeqCst);
    assert_eq!(attempts(), 1, "the first write");
    sleep(Duration::from_secs(1)).await; // retry at 1 s
    assert_eq!(attempts(), 2);
    sleep(Duration::from_secs(2)).await; // then 2 s later
    assert_eq!(attempts(), 3);
    sleep(Duration::from_secs(4)).await; // then 4 s later
    assert_eq!(attempts(), 4);
    drop(storage);
}

#[tokio::test(start_paused = true)]
async fn the_size_limit_drops_the_oldest_spooled_events() {
    let dir = tempfile::tempdir().unwrap();
    let sink = Flaky::failing();
    let mut options = spool_in(dir.path());
    options.max_size = 1_000;
    options.segment_max = 200;
    let storage = start(&sink, Some(options));
    for i in 0..40 {
        storage.publish(&[audit(i)]);
    }
    sleep(Duration::from_millis(10)).await;
    let s = storage.sink_status()[0].clone();
    assert!(s.spool_dropped > 0, "{s:?}");
    assert!(s.spool_bytes <= 1_000, "{s:?}");
    assert_eq!(s.spool_events + s.spool_dropped, 40);

    sink.set_failing(false);
    sleep(Duration::from_secs(1)).await;
    let got = sink.received();
    assert_eq!(
        got.last().map(String::as_str),
        Some("e39"),
        "the newest are kept"
    );
    assert!(!got.contains(&"e0".to_owned()), "the oldest were dropped");
}

#[tokio::test(start_paused = true)]
async fn a_full_disk_drops_the_new_batch() {
    let dir = tempfile::tempdir().unwrap();
    let sink = Flaky::failing();
    let mut options = spool_in(dir.path());
    options.min_free = 1 << 30;
    options.free_space = Arc::new(|_: &Path| Ok(1 << 20));
    let storage = start(&sink, Some(options));
    storage.publish(&[audit(0)]);
    sleep(Duration::from_millis(10)).await;
    let s = storage.sink_status()[0].clone();
    assert_eq!(
        (s.spooled, s.spool_dropped, s.spool_events),
        (0, 1, 0),
        "{s:?}"
    );
}

#[tokio::test(start_paused = true)]
async fn the_spool_survives_a_restart() {
    let dir = tempfile::tempdir().unwrap();
    let down = Flaky::failing();
    let storage = start(&down, Some(spool_in(dir.path())));
    for i in 0..3 {
        storage.publish(&[audit(i)]);
    }
    storage.shutdown().await;
    assert!(down.received().is_empty());

    let up = Arc::new(Flaky::default());
    let storage = start(&up, Some(spool_in(dir.path())));
    sleep(Duration::from_millis(10)).await;
    assert_eq!(up.received(), names(0..3), "replayed at start");
    assert_eq!(storage.sink_status()[0].spool_events, 0);
}

#[tokio::test(start_paused = true)]
async fn without_a_spool_failed_batches_are_dropped_and_counted() {
    let sink = Flaky::failing();
    let storage = start(&sink, None);
    storage.publish(&[audit(0)]);
    sleep(Duration::from_millis(10)).await;
    let s = storage.sink_status()[0].clone();
    assert_eq!((s.dropped_write_failed, s.write_errors), (1, 1), "{s:?}");
}

#[tokio::test(start_paused = true)]
async fn many_sinks_share_one_budget() {
    // Two flaky sinks with the same name prefix get separate folders but one size limit.
    let dir = tempfile::tempdir().unwrap();
    let sink = Flaky::failing();
    let mut registry = Registry::new();
    registry.register(Box::new(Factory(sink.clone())));
    let backend = BackendConfig {
        kind: "flaky".into(),
        options: BackendOptions::new(),
    };
    let sinks: Vec<_> = ["a/b", "a_b2"]
        .iter()
        .map(|n| {
            let mut c = SinkConfig::new(*n, backend.clone());
            c.batch_max_events = 1;
            c.retention = None;
            c
        })
        .collect();
    let mut options = spool_in(dir.path());
    options.max_size = 600;
    options.segment_max = 100;
    let storage = StorageManager::from_config(
        &registry,
        &StorageConfig {
            state: backend,
            sinks,
        },
    )
    .unwrap()
    .start(RunOptions {
        spool: Some(options),
        ..Default::default()
    });
    for i in 0..30 {
        storage.publish(&[audit(i)]);
    }
    sleep(Duration::from_millis(10)).await;
    let total: u64 = storage.sink_status().iter().map(|s| s.spool_bytes).sum();
    assert!(total <= 600, "shared budget, got {total}");
    let folders: HashMap<_, _> = std::fs::read_dir(dir.path())
        .unwrap()
        .map(|e| (e.unwrap().file_name().into_string().unwrap(), ()))
        .collect();
    assert!(
        folders.contains_key("a_b") && folders.contains_key("a_b2"),
        "{folders:?}"
    );
}
