//! Registry and routing behaviour, with in-memory test backends.

use std::sync::{Arc, Mutex};
use std::time::Duration;

use scribe_storage_api::{
    BackendOptions, BoxFuture, EventKind, EventQuery, EventSink, Health, Page, Result, SinkCaps,
    StateStore, StorageError, StorageFactory, StoredEvent,
};
use scribe_storage_conformance::block_on;
use scribe_storage_manager::{BackendConfig, Registry, SinkConfig, StorageConfig, StorageManager};
use scribe_test_support::{flow, FaultySink, MemorySink, MemoryStore};

type Recorded = Arc<Mutex<Vec<(String, Arc<FaultySink<MemorySink>>)>>>;

/// A sink handle the test keeps, so it can inspect what the manager wrote.
struct SharedSink(Arc<FaultySink<MemorySink>>);

impl EventSink for SharedSink {
    fn name(&self) -> &str {
        self.0.name()
    }
    fn capabilities(&self) -> SinkCaps {
        self.0.capabilities()
    }
    fn migrate(&self) -> BoxFuture<'_, Result<()>> {
        self.0.migrate()
    }
    fn write_batch<'a>(&'a self, batch: &'a [StoredEvent]) -> BoxFuture<'a, Result<()>> {
        self.0.write_batch(batch)
    }
    fn query<'a>(&'a self, q: &'a EventQuery) -> BoxFuture<'a, Result<Page<StoredEvent>>> {
        self.0.query(q)
    }
    fn flush(&self) -> BoxFuture<'_, Result<()>> {
        self.0.flush()
    }
    fn health(&self) -> BoxFuture<'_, Health> {
        self.0.health()
    }
}

/// `memory` backs both roles; `state-only` and `sink-only` back one each.
struct TestFactory {
    kind: &'static str,
    state: bool,
    sink: bool,
    created: Recorded,
}

impl StorageFactory for TestFactory {
    fn kind(&self) -> &'static str {
        self.kind
    }

    fn build_state(&self, _options: &BackendOptions) -> Option<Result<Box<dyn StateStore>>> {
        self.state
            .then(|| Ok(Box::new(MemoryStore::default()) as Box<dyn StateStore>))
    }

    fn build_sink(
        &self,
        name: &str,
        _options: &BackendOptions,
    ) -> Option<Result<Box<dyn EventSink>>> {
        self.sink.then(|| {
            let sink = Arc::new(FaultySink::new(MemorySink::default()));
            self.created
                .lock()
                .unwrap()
                .push((name.to_owned(), Arc::clone(&sink)));
            Ok(Box::new(SharedSink(sink)) as Box<dyn EventSink>)
        })
    }
}

fn registry() -> (Registry, Recorded) {
    let created = Recorded::default();
    let mut registry = Registry::new();
    for (kind, state, sink) in [
        ("memory", true, true),
        ("state-only", true, false),
        ("sink-only", false, true),
    ] {
        registry.register(Box::new(TestFactory {
            kind,
            state,
            sink,
            created: Arc::clone(&created),
        }));
    }
    (registry, created)
}

fn backend(kind: &str) -> BackendConfig {
    BackendConfig {
        kind: kind.into(),
        options: BackendOptions::new(),
    }
}

fn sink(name: &str, kind: &str, events: Vec<EventKind>) -> SinkConfig {
    SinkConfig {
        events,
        ..SinkConfig::new(name, backend(kind))
    }
}

fn error_text<T>(result: Result<T>) -> String {
    match result {
        Ok(_) => panic!("expected an error"),
        Err(e) => e.to_string(),
    }
}

#[test]
fn lists_kinds_in_order() {
    let (registry, _) = registry();
    assert_eq!(
        registry.kinds().collect::<Vec<_>>(),
        ["memory", "sink-only", "state-only"]
    );
}

#[test]
fn unknown_kinds_name_the_built_ones() {
    let (registry, _) = registry();
    let msg = error_text(registry.build_state(&backend("mysql")));
    assert!(
        msg.contains("unknown storage kind 'mysql' (built with: memory, sink-only, state-only)"),
        "{msg}"
    );
}

#[test]
fn backends_are_only_used_in_roles_they_support() {
    let (registry, _) = registry();
    let msg = error_text(registry.build_state(&backend("sink-only")));
    assert!(
        msg.contains("'sink-only' cannot be used as state store"),
        "{msg}"
    );
    let msg = error_text(registry.build_sink(&sink("s", "state-only", vec![])));
    assert!(
        msg.contains("'state-only' cannot be used as event sink"),
        "{msg}"
    );
}

#[test]
fn registering_a_kind_again_replaces_it() {
    let (mut registry, created) = registry();
    registry.register(Box::new(TestFactory {
        kind: "memory",
        state: true,
        sink: false,
        created,
    }));
    assert_eq!(registry.kinds().count(), 3);
    assert!(registry.build_sink(&sink("s", "memory", vec![])).is_err());
}

#[test]
fn routes_events_to_subscribed_sinks_only() {
    let (registry, created) = registry();
    let config = StorageConfig {
        state: backend("memory"),
        sinks: vec![
            sink("everything", "sink-only", vec![]),
            sink("alerts", "memory", vec![EventKind::Alert]),
        ],
    };
    let manager = StorageManager::from_config(&registry, &config).unwrap();
    block_on(manager.migrate()).unwrap();
    assert_eq!(manager.sinks().count(), 2);
    assert!(block_on(manager.state().get_host("api.example.com"))
        .unwrap()
        .is_none());

    let flow_event =
        StoredEvent::Flow(flow("192.0.2.10:443").host("api.example.com").tls().build());
    let alert_event = StoredEvent::Alert(scribe_storage_api::AlertRecord {
        ts: std::time::UNIX_EPOCH + Duration::from_secs(1_700_000_000),
        host: None,
        dst_ip: "198.51.100.7".parse().unwrap(),
        dst_port: 8443,
        process_path: None,
        score: 90,
        reason: "raw_ip".into(),
        notes: Default::default(),
    });
    block_on(manager.publish(&[flow_event.clone(), alert_event])).unwrap();
    block_on(manager.publish(&[flow_event])).unwrap();

    let created = created.lock().unwrap();
    let get = |name: &str| &created.iter().find(|(n, _)| n == name).unwrap().1;
    let everything = get("everything");
    let alerts = get("alerts");
    assert_eq!(everything.inner().events().len(), 3);
    assert_eq!(alerts.inner().events().len(), 1);
    assert_eq!(alerts.inner().events()[0].kind(), EventKind::Alert);
    assert_eq!(
        alerts.attempts(),
        1,
        "no write for a batch with nothing subscribed"
    );
}

#[test]
fn routes_module_records_and_metrics_by_name() {
    let (registry, created) = registry();
    let config = StorageConfig {
        state: backend("memory"),
        sinks: vec![
            sink(
                "urls",
                "memory",
                vec![EventKind::parse("url.request").unwrap()],
            ),
            sink("metrics", "memory", vec![EventKind::Metric]),
        ],
    };
    let manager = StorageManager::from_config(&registry, &config).unwrap();
    let ts = std::time::UNIX_EPOCH + Duration::from_secs(1_700_000_000);
    let record = StoredEvent::Module(scribe_core::ModuleRecord {
        ts,
        module: "url".into(),
        kind: "url.request".into(),
        schema: 1,
        host: Some("plain.example.com".into()),
        payload: serde_json::json!({ "url": "http://plain.example.com/" }),
    });
    let other = StoredEvent::Module(scribe_core::ModuleRecord {
        kind: "url.other".into(),
        ..match &record {
            StoredEvent::Module(r) => r.clone(),
            _ => unreachable!(),
        }
    });
    let metric = StoredEvent::Metric(scribe_core::MetricSample {
        ts,
        module: "kperf".into(),
        name: "kperf.tcp_retrans".into(),
        labels: Default::default(),
        value: 1.0,
    });
    block_on(manager.publish(&[record, other, metric])).unwrap();

    let created = created.lock().unwrap();
    let get = |name: &str| {
        created
            .iter()
            .find(|(n, _)| n == name)
            .unwrap()
            .1
            .inner()
            .events()
    };
    let urls = get("urls");
    assert_eq!(urls.len(), 1);
    assert_eq!(urls[0].kind().name(), "url.request");
    let metrics = get("metrics");
    assert_eq!(metrics.len(), 1);
    assert_eq!(metrics[0].module(), Some("kperf"));
}

#[test]
fn sink_failures_reach_the_caller() {
    let (registry, created) = registry();
    let config = StorageConfig {
        state: backend("memory"),
        sinks: vec![sink("central", "memory", vec![])],
    };
    let manager = StorageManager::from_config(&registry, &config).unwrap();
    created.lock().unwrap()[0].1.set_failing(true);
    let event = StoredEvent::Flow(flow("192.0.2.10:443").build());
    let err = block_on(manager.publish(&[event])).unwrap_err();
    assert!(matches!(err, StorageError::Backend(_)), "{err}");
}

#[test]
fn from_config_reports_the_failing_backend() {
    let (registry, _) = registry();
    let config = StorageConfig {
        state: backend("memory"),
        sinks: vec![sink("central", "nope", vec![])],
    };
    let msg = error_text(StorageManager::from_config(&registry, &config));
    assert!(msg.contains("unknown storage kind 'nope'"), "{msg}");
}

#[test]
fn sink_defaults() {
    let s = SinkConfig::new("local-history", backend("memory"));
    assert_eq!(s.retention, Some(Duration::from_secs(30 * 86_400)));
    assert_eq!(s.batch_max_events, 500);
    assert_eq!(s.batch_max_wait, Duration::from_secs(1));
    assert!(s.accepts(&EventKind::Audit));
}
