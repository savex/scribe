//! Backend-independent test suite for [`StateStore`] and [`EventSink`] implementations.
//!
//! Each backend crate calls these from its own `tests/<backend>_conformance.rs`:
//!
//! ```ignore
//! scribe_storage_conformance::block_on(state_store_suite(&store));
//! ```
//!
//! Suites assume an empty, dedicated database and panic on the first failed check.

use std::future::Future;
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::sync::Arc;
use std::task::{Context, Poll, Wake, Waker};
use std::thread::{self, Thread};
use std::time::{Duration, SystemTime};

use scribe_core::{FlowEvent, FlowKind, MetricSample, ModuleRecord, Protocol, Security};
use scribe_storage_api::{
    AlertState, AuditRecord, BaselineEntry, EntrySource, EventKind, EventQuery, EventSink,
    HostDelta, HostQuery, StateStore, StoredEvent,
};
use serde_json::json;

/// Minimal executor so the suite does not pull in an async runtime.
pub fn block_on<F: Future>(fut: F) -> F::Output {
    struct ThreadWaker(Thread);

    impl Wake for ThreadWaker {
        fn wake(self: Arc<Self>) {
            self.0.unpark();
        }
    }

    let waker = Waker::from(Arc::new(ThreadWaker(thread::current())));
    let mut cx = Context::from_waker(&waker);
    let mut fut = std::pin::pin!(fut);
    loop {
        match fut.as_mut().poll(&mut cx) {
            Poll::Ready(out) => return out,
            Poll::Pending => thread::park(),
        }
    }
}

pub async fn state_store_suite(store: &dyn StateStore) {
    migrate_is_idempotent(store).await;
    missing_host_is_none(store).await;
    host_counters_are_deltas(store).await;
    security_flags_accumulate(store).await;
    unresolved_flag_is_sticky(store).await;
    process_counters_follow_deltas(store).await;
    hourly_buckets_add_up(store).await;
    list_hosts_paginates(store).await;
    baseline_round_trip(store).await;
    alert_state_round_trip(store).await;
    module_state_round_trip(store).await;
}

pub async fn event_sink_suite(sink: &dyn EventSink) {
    sink.migrate().await.expect("first migrate");
    sink.migrate()
        .await
        .expect("second migrate must be idempotent");

    let batch = vec![
        flow_event("a.example"),
        noted_flow_event("b.example"),
        audit_event("started"),
        metric_event("kperf.tcp_retrans", 3.0),
        module_event("url.request", "http://plain.example.com/download"),
    ];
    sink.write_batch(&batch).await.expect("write_batch");
    sink.flush().await.expect("flush");

    if !sink.capabilities().queryable {
        return;
    }
    let all = sink.query(&EventQuery::default()).await.expect("query all");
    assert_eq!(all.items.len(), 5, "all written events are returned");
    let noted = all
        .items
        .iter()
        .find_map(|e| match e {
            StoredEvent::Flow(f) if !f.notes.is_empty() => Some(f),
            _ => None,
        })
        .expect("flow notes are kept");
    assert_eq!(
        noted.notes.get_str("url"),
        Some("http://plain.example.com/b"),
        "flow notes round-trip"
    );

    let flows = sink
        .query(&EventQuery {
            kinds: vec![EventKind::Flow],
            ..Default::default()
        })
        .await
        .expect("query flows");
    assert_eq!(flows.items.len(), 2, "kind filter");
    assert!(flows.items.iter().all(|e| e.kind() == EventKind::Flow));

    let module = sink
        .query(&EventQuery {
            kinds: vec![EventKind::parse("url.request").unwrap()],
            ..Default::default()
        })
        .await
        .expect("query module records");
    assert_eq!(module.items.len(), 1, "module record kind filter");
    match &module.items[0] {
        StoredEvent::Module(r) => {
            assert_eq!((r.module.as_ref(), r.kind.as_ref()), ("url", "url.request"));
            assert_eq!(r.schema, 1);
            assert_eq!(r.host.as_deref(), Some("plain.example.com"));
            assert_eq!(
                r.payload,
                json!({ "url": "http://plain.example.com/download" }),
                "module payload round-trips"
            );
        }
        other => panic!("expected a module record, got {other:?}"),
    }

    let metrics = sink
        .query(&EventQuery {
            kinds: vec![EventKind::Metric],
            ..Default::default()
        })
        .await
        .expect("query metrics");
    assert_eq!(metrics.items.len(), 1, "metric kind filter");
    match &metrics.items[0] {
        StoredEvent::Metric(m) => {
            assert_eq!(m.name, "kperf.tcp_retrans");
            assert_eq!(m.value, 3.0);
            assert_eq!(m.labels.get("iface").map(String::as_str), Some("eth0"));
        }
        other => panic!("expected a metric sample, got {other:?}"),
    }

    let limited = sink
        .query(&EventQuery {
            limit: Some(1),
            ..Default::default()
        })
        .await
        .expect("query limited");
    assert_eq!(limited.items.len(), 1, "limit");

    if !sink.capabilities().native_retention {
        retention_removes_old_events(sink).await;
    }
}

/// Events and metric samples older than the cutoff go; newer ones stay.
async fn retention_removes_old_events(sink: &dyn EventSink) {
    let old = now() - Duration::from_secs(10 * 86_400);
    let mut stale = vec![
        audit_event("old audit"),
        metric_event("kperf.tcp_retrans", 1.0),
    ];
    for e in &mut stale {
        match e {
            StoredEvent::Audit(a) => a.ts = old,
            StoredEvent::Metric(m) => m.ts = old,
            _ => unreachable!(),
        }
    }
    sink.write_batch(&stale).await.expect("write old events");
    let before = sink
        .query(&EventQuery::default())
        .await
        .expect("query")
        .items
        .len();

    let removed = sink
        .delete_before(now() - Duration::from_secs(86_400))
        .await
        .expect("delete_before");
    assert_eq!(removed, 2, "both old records are removed");
    let after = sink
        .query(&EventQuery::default())
        .await
        .expect("query")
        .items;
    assert_eq!(after.len(), before - 2, "newer events stay");
    assert!(
        after.iter().all(|e| e.ts() > old),
        "nothing older than the cutoff remains"
    );
}

async fn migrate_is_idempotent(store: &dyn StateStore) {
    store.migrate().await.expect("first migrate");
    store
        .migrate()
        .await
        .expect("second migrate must be idempotent");
}

async fn missing_host_is_none(store: &dyn StateStore) {
    let host = store.get_host("missing.example").await.expect("get_host");
    assert!(host.is_none());
}

async fn host_counters_are_deltas(store: &dyn StateStore) {
    let id1 = store
        .upsert_host(&delta("count.example", 1, 2, 100))
        .await
        .expect("upsert 1");
    let id2 = store
        .upsert_host(&delta("count.example", 3, 0, 50))
        .await
        .expect("upsert 2");
    assert_eq!(id1, id2, "same host keeps its id");

    let host = store
        .get_host("count.example")
        .await
        .expect("get")
        .expect("host exists");
    assert_eq!(host.conn_count, 4);
    assert_eq!(host.req_count, 2);
    assert_eq!(host.bytes_out, 150);
    assert!(host.first_seen <= host.last_seen);

    let ip = IpAddr::V4(Ipv4Addr::new(192, 0, 2, 1));
    store
        .link_ip(id1, ip, Duration::from_secs(60))
        .await
        .expect("link_ip");
}

async fn security_flags_accumulate(store: &dyn StateStore) {
    let mut d = delta("mixed.example", 1, 0, 0);
    d.security = Security::Plaintext;
    store.upsert_host(&d).await.expect("plaintext");
    d.security = Security::Tls;
    store.upsert_host(&d).await.expect("tls");

    let host = store
        .get_host("mixed.example")
        .await
        .expect("get")
        .expect("host exists");
    assert!(
        host.tls_seen && host.plaintext_seen,
        "flags are sticky, not overwritten"
    );
}

async fn unresolved_flag_is_sticky(store: &dyn StateStore) {
    let mut d = delta("ech-outer.example", 1, 0, 0);
    d.unresolved = true;
    store.upsert_host(&d).await.expect("ech flow");
    d.unresolved = false;
    store.upsert_host(&d).await.expect("named flow");
    let host = store
        .get_host("ech-outer.example")
        .await
        .expect("get")
        .expect("host exists");
    assert!(host.unresolved, "unresolved only ever turns on");
    let named = delta("named.example", 1, 0, 0);
    store.upsert_host(&named).await.expect("named");
    let host = store
        .get_host("named.example")
        .await
        .expect("get")
        .expect("host");
    assert!(!host.unresolved);
}

async fn process_counters_follow_deltas(store: &dyn StateStore) {
    let mut d = delta("proc.example", 1, 1, 100);
    d.process = Some("/usr/bin/curl".into());
    store.upsert_host(&d).await.expect("curl 1");
    store.upsert_host(&d).await.expect("curl 2");
    d.process = Some("/usr/bin/wget".into());
    d.bytes_out = 7;
    store.upsert_host(&d).await.expect("wget");
    d.process = None;
    store.upsert_host(&d).await.expect("no process");

    let host = store
        .get_host("proc.example")
        .await
        .expect("get")
        .expect("host");
    assert_eq!(host.conn_count, 4, "every delta counts for the host");

    let curl = store
        .process_hosts(Some("/usr/bin/curl"))
        .await
        .expect("process_hosts");
    assert_eq!(curl.len(), 1);
    assert_eq!(
        (
            curl[0].host.as_str(),
            curl[0].conn_count,
            curl[0].req_count,
            curl[0].bytes_out
        ),
        ("proc.example", 2, 2, 200)
    );
    let all = store.process_hosts(None).await.expect("process_hosts");
    let procs: Vec<&str> = all
        .iter()
        .filter(|r| r.host == "proc.example")
        .map(|r| r.process.as_str())
        .collect();
    assert_eq!(
        procs,
        ["/usr/bin/curl", "/usr/bin/wget"],
        "ordered, no row without a process"
    );
}

async fn list_hosts_paginates(store: &dyn StateStore) {
    for i in 0..5 {
        store
            .upsert_host(&delta(&format!("page{i}.list.example"), 1, 0, 0))
            .await
            .expect("upsert");
    }
    let filter = Some("list.example".to_owned());

    let all = store
        .list_hosts(&HostQuery {
            name_contains: filter.clone(),
            ..Default::default()
        })
        .await
        .expect("list all");
    assert_eq!(all.items.len(), 5);

    let page = store
        .list_hosts(&HostQuery {
            name_contains: filter,
            offset: 2,
            limit: Some(2),
        })
        .await
        .expect("list page");
    assert_eq!(page.items.len(), 2);
}

async fn baseline_round_trip(store: &dyn StateStore) {
    let empty = store.baseline("conformance").await.expect("empty baseline");
    assert!(empty.entries.is_empty());

    let entry = BaselineEntry {
        host: "known.example".into(),
        source: EntrySource::Learned,
        added_at: now(),
    };
    store
        .add_to_baseline("conformance", &entry)
        .await
        .expect("add");
    store
        .add_to_baseline("conformance", &entry)
        .await
        .expect("re-adding is a no-op");

    let baseline = store.baseline("conformance").await.expect("baseline");
    assert_eq!(baseline.entries.len(), 1);
    assert!(baseline.contains("known.example"));

    let other = store
        .baseline("other-profile")
        .await
        .expect("other profile");
    assert!(!other.contains("known.example"), "profiles are isolated");

    let kept = BaselineEntry {
        host: "kept.example".into(),
        source: EntrySource::Manual,
        added_at: now(),
    };
    store
        .add_to_baseline("conformance", &kept)
        .await
        .expect("add a second host");
    store
        .add_to_baseline("other-profile", &entry)
        .await
        .expect("add to the other profile");
    assert!(store
        .remove_from_baseline("conformance", "known.example")
        .await
        .expect("remove"));
    assert!(
        !store
            .remove_from_baseline("conformance", "known.example")
            .await
            .expect("remove again"),
        "removing a host that isn't listed reports false"
    );
    let baseline = store.baseline("conformance").await.expect("baseline");
    assert!(!baseline.contains("known.example"));
    assert!(baseline.contains("kept.example"), "other hosts stay");
    let other = store
        .baseline("other-profile")
        .await
        .expect("other profile");
    assert!(other.contains("known.example"), "removal is per profile");
}

async fn alert_state_round_trip(store: &dyn StateStore) {
    assert!(store
        .get_alert_state("k")
        .await
        .expect("get missing")
        .is_none());

    let mut state = AlertState {
        key: "k".into(),
        last_alerted: now(),
        acknowledged: false,
    };
    store.put_alert_state(&state).await.expect("put");
    state.acknowledged = true;
    store.put_alert_state(&state).await.expect("overwrite");

    let got = store
        .get_alert_state("k")
        .await
        .expect("get")
        .expect("exists");
    assert!(got.acknowledged);

    let other = AlertState {
        key: "a|/usr/bin/curl".into(),
        last_alerted: now(),
        acknowledged: false,
    };
    store.put_alert_state(&other).await.expect("put another");
    let all = store.alert_states().await.expect("alert_states");
    let keys: Vec<&str> = all.iter().map(|s| s.key.as_str()).collect();
    assert_eq!(
        keys,
        ["a|/usr/bin/curl", "k"],
        "every state, ordered by key"
    );
    assert!(all[1].acknowledged && !all[0].acknowledged);
}

async fn module_state_round_trip(store: &dyn StateStore) {
    let empty = store.module_state("url").await.expect("module_state");
    assert!(empty.is_empty(), "a module with no state gets an empty map");

    store
        .put_module_state("url", "requests", &json!(1))
        .await
        .expect("put");
    store
        .put_module_state("url", "last", &json!({ "host": "plain.example.com" }))
        .await
        .expect("put");
    store
        .put_module_state("url", "requests", &json!(2))
        .await
        .expect("overwrite");
    store
        .put_module_state("kperf", "requests", &json!("other"))
        .await
        .expect("put other module");

    let url = store.module_state("url").await.expect("module_state");
    assert_eq!(url.len(), 2);
    assert_eq!(url["requests"], json!(2), "put replaces the value");
    assert_eq!(url["last"], json!({ "host": "plain.example.com" }));
    let kperf = store.module_state("kperf").await.expect("module_state");
    assert_eq!(
        kperf["requests"],
        json!("other"),
        "modules don't share keys"
    );
}

async fn hourly_buckets_add_up(store: &dyn StateStore) {
    use std::time::Duration;
    // A fixed day, so the test never straddles an hour boundary by accident.
    let base = SystemTime::UNIX_EPOCH + Duration::from_secs(1_700_002_800); // 23:00:00 UTC
    let at = |offset_secs: u64, conns: u64, bytes: u64| HostDelta {
        seen_at: base + Duration::from_secs(offset_secs),
        ..delta("hourly.example", conns, 0, bytes)
    };
    for d in [
        at(10, 1, 100),
        at(3599, 2, 50),
        at(3600, 1, 7),
        at(7200 + 5, 0, 0),
    ] {
        store.upsert_host(&d).await.expect("upsert");
    }
    let all = store
        .host_hours("hourly.example", base)
        .await
        .expect("host_hours");
    let rows: Vec<(SystemTime, u64, u64)> = all
        .iter()
        .map(|b| (b.hour, b.conn_count, b.bytes_out))
        .collect();
    assert_eq!(
        rows,
        [(base, 3, 150), (base + Duration::from_secs(3600), 1, 7)],
        "deltas add up per hour; an all-zero delta makes no bucket"
    );
    let later = store
        .host_hours("hourly.example", base + Duration::from_secs(3700))
        .await
        .expect("since");
    assert_eq!(later.len(), 1, "`since` counts from the start of its hour");
    assert!(store
        .host_hours("other.example", base)
        .await
        .expect("other host")
        .is_empty());
    let removed = store
        .prune_host_hours(base + Duration::from_secs(3600))
        .await
        .expect("prune");
    assert_eq!(removed, 1);
    let kept = store
        .host_hours("hourly.example", base)
        .await
        .expect("after prune");
    assert_eq!(kept.len(), 1);
    assert_eq!(kept[0].hour, base + Duration::from_secs(3600));
}

fn now() -> SystemTime {
    SystemTime::now()
}

fn delta(name: &str, connections: u64, requests: u64, bytes_out: u64) -> HostDelta {
    HostDelta {
        name: name.into(),
        seen_at: now(),
        connections,
        requests,
        bytes_out,
        security: Security::Tls,
        unresolved: false,
        process: None,
    }
}

fn flow_event(host: &str) -> StoredEvent {
    StoredEvent::Flow(FlowEvent {
        ts: now(),
        pid: Some(42),
        process_path: Some("/usr/bin/curl".into()),
        proto: Protocol::Tcp,
        src: SocketAddr::from(([10, 0, 0, 2], 50000)),
        dst_ip: IpAddr::V4(Ipv4Addr::new(192, 0, 2, 10)),
        dst_port: 443,
        hostname: Some(host.into()),
        ech: false,
        notes: Default::default(),
        security: Security::Tls,
        bytes_out: 512,
        kind: FlowKind::NewFlow,
    })
}

fn noted_flow_event(host: &str) -> StoredEvent {
    let StoredEvent::Flow(mut flow) = flow_event(host) else {
        unreachable!()
    };
    flow.notes
        .insert("url", json!("http://plain.example.com/b"));
    StoredEvent::Flow(flow)
}

fn metric_event(name: &'static str, value: f64) -> StoredEvent {
    StoredEvent::Metric(MetricSample {
        ts: now(),
        module: name.split('.').next().unwrap().into(),
        name: name.into(),
        labels: [("iface".to_owned(), "eth0".to_owned())].into(),
        value,
    })
}

fn module_event(kind: &'static str, url: &str) -> StoredEvent {
    StoredEvent::Module(ModuleRecord {
        ts: now(),
        module: kind.split('.').next().unwrap().into(),
        kind: kind.into(),
        schema: 1,
        host: Some("plain.example.com".into()),
        payload: json!({ "url": url }),
    })
}

fn audit_event(message: &str) -> StoredEvent {
    StoredEvent::Audit(AuditRecord {
        ts: now(),
        message: message.into(),
        link: None,
    })
}
