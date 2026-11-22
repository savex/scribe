//! Functional tests for `scribe_storage_api::model` (moved from `src/model.rs`).

use scribe_core::{MetricSample, ModuleRecord};
use scribe_storage_api::model::*;
use std::borrow::Cow;
use std::collections::BTreeMap;
use std::time::UNIX_EPOCH;

#[test]
fn kinds_round_trip_through_their_names() {
    for kind in EventKind::CORE {
        assert_eq!(EventKind::parse(kind.name()), Some(kind.clone()));
        assert_eq!(kind.module(), None);
    }
    let module = EventKind::parse("url.request").unwrap();
    assert_eq!(module, EventKind::Module(Cow::Borrowed("url.request")));
    assert_eq!(module.name(), "url.request");
    assert_eq!(module.module(), Some("url"));
    assert_eq!(module.to_string(), "url.request");
    for bad in ["", "flows", "url", ".request", "url.", "Flow"] {
        assert_eq!(EventKind::parse(bad), None, "{bad:?}");
    }
}

#[test]
fn module_events_report_their_kind_and_module() {
    let record = StoredEvent::Module(ModuleRecord {
        ts: UNIX_EPOCH,
        module: "url".into(),
        kind: "url.request".into(),
        schema: 1,
        host: Some("plain.example.com".into()),
        payload: serde_json::json!({ "url": "http://plain.example.com/" }),
    });
    assert_eq!(record.kind().name(), "url.request");
    assert_eq!(record.module(), Some("url"));
    assert_eq!(record.ts(), UNIX_EPOCH);

    let metric = StoredEvent::Metric(MetricSample {
        ts: UNIX_EPOCH,
        module: "kperf".into(),
        name: "kperf.tcp_retrans".into(),
        labels: BTreeMap::new(),
        value: 3.0,
    });
    assert_eq!(metric.kind(), EventKind::Metric);
    assert_eq!(metric.module(), Some("kperf"));

    let audit = StoredEvent::Audit(AuditRecord {
        ts: UNIX_EPOCH,
        message: "x".into(),
    });
    assert_eq!(audit.module(), None);
}
