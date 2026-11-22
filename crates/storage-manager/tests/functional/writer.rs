//! Writer tasks: batching by size and time, isolation between sinks, full queues, retention,
//! shutdown. Time is Tokio's paused clock, so waits are exact and instant.

use std::collections::HashMap;
use std::sync::{Arc, Mutex};
use std::time::{Duration, SystemTime};

use scribe_storage_api::{
    AuditRecord, BackendOptions, BoxFuture, EventQuery, EventSink, Health, Page, Result, SinkCaps,
    StateStore, StorageFactory, StoredEvent,
};
use scribe_storage_manager::{
    BackendConfig, Registry, RunOptions, SinkConfig, Storage, StorageConfig, StorageManager,
};
use scribe_test_support::{FakeClock, MemoryStore};
use tokio::sync::Semaphore;
use tokio::time::sleep;

/// A sink that records batch sizes and retention cutoffs; it can be slow or held at a gate.
#[derive(Default)]
struct Probe {
    batches: Mutex<Vec<usize>>,
    cutoffs: Mutex<Vec<SystemTime>>,
    delay: Duration,
    gate: Option<Arc<Semaphore>>,
    native_retention: bool,
}

impl Probe {
    fn batches(&self) -> Vec<usize> {
        self.batches.lock().unwrap().clone()
    }
}

struct Shared(Arc<Probe>);

impl EventSink for Shared {
    fn name(&self) -> &str {
        "probe"
    }
    fn capabilities(&self) -> SinkCaps {
        SinkCaps {
            queryable: false,
            native_retention: self.0.native_retention,
            max_batch: 1000,
        }
    }
    fn migrate(&self) -> BoxFuture<'_, Result<()>> {
        Box::pin(async { Ok(()) })
    }
    fn write_batch<'a>(&'a self, batch: &'a [StoredEvent]) -> BoxFuture<'a, Result<()>> {
        Box::pin(async move {
            if !self.0.delay.is_zero() {
                sleep(self.0.delay).await;
            }
            if let Some(gate) = &self.0.gate {
                gate.acquire().await.unwrap().forget();
            }
            self.0.batches.lock().unwrap().push(batch.len());
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
    fn delete_before(&self, cutoff: SystemTime) -> BoxFuture<'_, Result<u64>> {
        self.0.cutoffs.lock().unwrap().push(cutoff);
        Box::pin(async { Ok(0) })
    }
}

struct ProbeFactory(HashMap<String, Arc<Probe>>);

impl StorageFactory for ProbeFactory {
    fn kind(&self) -> &'static str {
        "probe"
    }
    fn build_state(&self, _o: &BackendOptions) -> Option<Result<Box<dyn StateStore>>> {
        Some(Ok(Box::new(MemoryStore::default())))
    }
    fn build_sink(&self, name: &str, _o: &BackendOptions) -> Option<Result<Box<dyn EventSink>>> {
        Some(Ok(Box::new(Shared(self.0[name].clone()))))
    }
}

fn sink(name: &str, batch: u32, wait: Duration) -> SinkConfig {
    let mut s = SinkConfig::new(
        name,
        BackendConfig {
            kind: "probe".into(),
            options: BackendOptions::new(),
        },
    );
    s.batch_max_events = batch;
    s.batch_max_wait = wait;
    s.retention = None;
    s
}

fn start(probes: &[(&str, Arc<Probe>, SinkConfig)], options: RunOptions) -> Storage {
    let mut registry = Registry::new();
    registry.register(Box::new(ProbeFactory(
        probes
            .iter()
            .map(|(n, p, _)| (n.to_string(), p.clone()))
            .collect(),
    )));
    let config = StorageConfig {
        state: BackendConfig {
            kind: "probe".into(),
            options: BackendOptions::new(),
        },
        sinks: probes.iter().map(|(_, _, c)| c.clone()).collect(),
    };
    StorageManager::from_config(&registry, &config)
        .unwrap()
        .start(options)
}

fn events(n: usize) -> Vec<StoredEvent> {
    (0..n)
        .map(|i| {
            StoredEvent::Audit(AuditRecord {
                ts: SystemTime::UNIX_EPOCH + Duration::from_secs(i as u64),
                message: format!("e{i}"),
                link: None,
            })
        })
        .collect()
}

#[tokio::test(start_paused = true)]
async fn batches_by_size() {
    let probe = Arc::new(Probe::default());
    let storage = start(
        &[("a", probe.clone(), sink("a", 3, Duration::from_secs(60)))],
        RunOptions::default(),
    );
    for e in events(7) {
        storage.publish(&[e]);
    }
    storage.flush().await;
    assert_eq!(probe.batches(), [3, 3, 1]);
    let status = &storage.sink_status()[0];
    assert_eq!((status.queued, status.written, status.batches), (7, 7, 3));
}

#[tokio::test(start_paused = true)]
async fn batches_by_time() {
    let probe = Arc::new(Probe::default());
    let storage = start(
        &[("a", probe.clone(), sink("a", 100, Duration::from_secs(1)))],
        RunOptions::default(),
    );
    storage.publish(&events(2));
    sleep(Duration::from_millis(999)).await;
    assert!(probe.batches().is_empty(), "not yet due");
    sleep(Duration::from_millis(2)).await;
    assert_eq!(
        probe.batches(),
        [2],
        "written when the oldest waited batch_max_wait"
    );
}

#[tokio::test(start_paused = true)]
async fn a_slow_sink_does_not_hold_up_others() {
    let slow = Arc::new(Probe {
        delay: Duration::from_secs(10),
        ..Default::default()
    });
    let fast = Arc::new(Probe::default());
    let storage = start(
        &[
            (
                "slow",
                slow.clone(),
                sink("slow", 1, Duration::from_secs(1)),
            ),
            (
                "fast",
                fast.clone(),
                sink("fast", 1, Duration::from_secs(1)),
            ),
        ],
        RunOptions::default(),
    );
    storage.publish(&events(1));
    sleep(Duration::from_millis(10)).await;
    assert_eq!(fast.batches(), [1]);
    assert!(slow.batches().is_empty());
    sleep(Duration::from_secs(10)).await;
    assert_eq!(slow.batches(), [1]);
}

#[tokio::test(start_paused = true)]
async fn a_full_queue_drops_and_counts() {
    let gate = Arc::new(Semaphore::new(0));
    let stuck = Arc::new(Probe {
        gate: Some(gate.clone()),
        ..Default::default()
    });
    let storage = start(
        &[(
            "stuck",
            stuck.clone(),
            sink("stuck", 1, Duration::from_secs(1)),
        )],
        RunOptions {
            queue_capacity: 2,
            ..Default::default()
        },
    );
    for e in events(10) {
        storage.publish(&[e]);
        tokio::task::yield_now().await;
    }
    let status = storage.sink_status()[0].clone();
    assert!(status.dropped_queue_full >= 6, "{status:?}");
    assert_eq!(status.queued + status.dropped_queue_full, 10);
    gate.add_permits(100);
    storage.flush().await;
    assert_eq!(stuck.batches().len() as u64, status.queued);
}

#[tokio::test(start_paused = true)]
async fn retention_runs_hourly_with_the_clock() {
    let clock = FakeClock::at_unix(1_700_000_000);
    let keeps = Arc::new(Probe::default());
    let native = Arc::new(Probe {
        native_retention: true,
        ..Default::default()
    });
    let mut with_retention = sink("keeps", 10, Duration::from_secs(1));
    with_retention.retention = Some(Duration::from_secs(30 * 86_400));
    let mut native_cfg = sink("native", 10, Duration::from_secs(1));
    native_cfg.retention = Some(Duration::from_secs(86_400));
    let _storage = start(
        &[
            ("keeps", keeps.clone(), with_retention),
            ("native", native.clone(), native_cfg),
        ],
        RunOptions {
            clock: Arc::new(clock.clone()),
            ..Default::default()
        },
    );
    sleep(Duration::from_millis(1)).await;
    let first = SystemTime::UNIX_EPOCH + Duration::from_secs(1_700_000_000 - 30 * 86_400);
    assert_eq!(*keeps.cutoffs.lock().unwrap(), [first], "runs at start");
    clock.advance(Duration::from_secs(3600));
    sleep(Duration::from_secs(3600)).await;
    assert_eq!(keeps.cutoffs.lock().unwrap().len(), 2, "and every hour");
    assert!(
        native.cutoffs.lock().unwrap().is_empty(),
        "never for native retention"
    );
}

#[tokio::test(start_paused = true)]
async fn shutdown_writes_what_is_queued() {
    let probe = Arc::new(Probe::default());
    let storage = start(
        &[(
            "a",
            probe.clone(),
            sink("a", 100, Duration::from_secs(3600)),
        )],
        RunOptions::default(),
    );
    storage.publish(&events(3));
    storage.shutdown().await;
    assert_eq!(probe.batches(), [3]);
}
