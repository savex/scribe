//! Backend-independent test suite for [`StateStore`] and [`EventSink`] implementations.
//!
//! Each backend crate calls these from its own `tests/conformance.rs`:
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

use scribe_core::{FlowEvent, FlowKind, Protocol, Security};
use scribe_storage_api::{
    AlertState, AuditRecord, BaselineEntry, EntrySource, EventKind, EventQuery, EventSink,
    HostDelta, HostQuery, StateStore, StoredEvent,
};

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
    list_hosts_paginates(store).await;
    baseline_round_trip(store).await;
    alert_state_round_trip(store).await;
}

pub async fn event_sink_suite(sink: &dyn EventSink) {
    sink.migrate().await.expect("first migrate");
    sink.migrate()
        .await
        .expect("second migrate must be idempotent");

    let batch = vec![
        flow_event("a.example"),
        flow_event("b.example"),
        audit_event("started"),
    ];
    sink.write_batch(&batch).await.expect("write_batch");
    sink.flush().await.expect("flush");

    if !sink.capabilities().queryable {
        return;
    }
    let all = sink.query(&EventQuery::default()).await.expect("query all");
    assert_eq!(all.items.len(), 3, "all written events are returned");

    let flows = sink
        .query(&EventQuery {
            kinds: vec![EventKind::Flow],
            ..Default::default()
        })
        .await
        .expect("query flows");
    assert_eq!(flows.items.len(), 2, "kind filter");
    assert!(flows.items.iter().all(|e| e.kind() == EventKind::Flow));

    let limited = sink
        .query(&EventQuery {
            limit: Some(1),
            ..Default::default()
        })
        .await
        .expect("query limited");
    assert_eq!(limited.items.len(), 1, "limit");
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
        url: None,
        security: Security::Tls,
        bytes_out: 512,
        kind: FlowKind::NewFlow,
    })
}

fn audit_event(message: &str) -> StoredEvent {
    StoredEvent::Audit(AuditRecord {
        ts: now(),
        message: message.into(),
    })
}
