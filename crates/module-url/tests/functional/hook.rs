//! The flow hook end to end: note, record and request counter.

use scribe_module_api::{ConfigDoc, FlowContext, Module};
use scribe_module_url::UrlModule;
use scribe_test_support::{flow, module_context, FakeClock};

#[test]
fn notes_records_and_counts_a_plaintext_request() {
    let mut m = UrlModule::default();
    m.configure(&ConfigDoc::new("")).unwrap();
    let clock = FakeClock::default();
    let (ctx, emitter) = module_context(&clock);
    m.start(ctx).unwrap();
    let obs = flow("192.0.2.20:80")
        .http_get("http://plain.example.com/download?id=42")
        .observe();
    let out = m.flow_hook().unwrap().on_flow(&FlowContext {
        event: &obs.event,
        head: obs.head.as_deref(),
    });
    let expected = "http://plain.example.com/download?id=<redacted>";
    assert_eq!(out.note.unwrap().as_str(), Some(expected));
    let records = emitter.records();
    assert_eq!(records.len(), 1);
    assert_eq!(records[0].kind, "url.request");
    assert_eq!(records[0].payload["method"], "GET");
    assert_eq!(records[0].payload["url"], expected);
    assert_eq!(emitter.state()[0].0, "requests.plain.example.com");
}

#[test]
fn tls_flows_get_no_url() {
    let mut m = UrlModule::default();
    m.configure(&ConfigDoc::new("")).unwrap();
    let (ctx, emitter) = module_context(&FakeClock::default());
    m.start(ctx).unwrap();
    let obs = flow("192.0.2.10:443")
        .host("api.example.com")
        .tls()
        .observe();
    let out = m.flow_hook().unwrap().on_flow(&FlowContext {
        event: &obs.event,
        head: obs.head.as_deref(),
    });
    assert!(out.note.is_none());
    assert!(emitter.records().is_empty());
}
