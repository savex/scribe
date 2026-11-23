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

fn url_of(m: &UrlModule, target: &str) -> String {
    let obs = flow("192.0.2.20:80").http_get(target).observe();
    let out = m.flow_hook().unwrap().on_flow(&FlowContext {
        event: &obs.event,
        head: obs.head.as_deref(),
    });
    out.note.unwrap().as_str().unwrap().to_owned()
}

fn hash_module(data_dir: &std::path::Path) -> UrlModule {
    let mut m = UrlModule::default();
    m.configure(&ConfigDoc::new("[modules.url]\nquery = \"hash\"\n"))
        .unwrap();
    let (mut ctx, _) = module_context(&FakeClock::default());
    ctx.data_dir = Some(data_dir.to_owned());
    m.start(ctx).unwrap();
    m
}

#[test]
fn short_hash_is_hmac_sha256_cut_to_six_digits() {
    let key = ring::hmac::Key::new(ring::hmac::HMAC_SHA256, b"key");
    // Well-known example: HMAC-SHA256("key", "The quick brown fox…") = f7bc83f4…
    assert_eq!(
        scribe_module_url::short_hash(&key, "The quick brown fox jumps over the lazy dog"),
        "f7bc83"
    );
}

#[test]
fn hash_mode_creates_a_key_and_matches_repeated_queries() {
    let dir = tempfile::tempdir().unwrap();
    let m = hash_module(dir.path());
    assert!(dir.path().join(scribe_module_url::KEY_FILE).is_file());
    let a = url_of(&m, "http://plain.example.com/download?id=42");
    let b = url_of(&m, "http://plain.example.com/download?id=42");
    let c = url_of(&m, "http://plain.example.com/download?id=43");
    assert!(
        a.starts_with("http://plain.example.com/download?<hash:"),
        "{a}"
    );
    assert_eq!(
        a.len(),
        "http://plain.example.com/download?<hash:xxxxxx>".len()
    );
    assert_eq!(a, b);
    assert_ne!(a, c);
    // The query itself is gone (the random hash may well contain the digits "42").
    assert!(!a.contains("id=42") && !a.contains("id="), "{a}");

    // Same install, same key: a restart gives the same hash.
    assert_eq!(
        url_of(
            &hash_module(dir.path()),
            "http://plain.example.com/download?id=42"
        ),
        a
    );
    // Another install gets another key.
    let other = tempfile::tempdir().unwrap();
    assert_ne!(
        url_of(
            &hash_module(other.path()),
            "http://plain.example.com/download?id=42"
        ),
        a
    );
}

#[test]
fn hash_key_can_point_at_a_secret_file() {
    let dir = tempfile::tempdir().unwrap();
    let key = dir.path().join("custom.key");
    let mut m = UrlModule::default();
    let text = format!(
        "[modules.url]\nquery = \"hash\"\nhash_key = \"file:{}\"\n",
        key.display()
    );
    m.configure(&ConfigDoc::new(&text)).unwrap();
    let (ctx, _) = module_context(&FakeClock::default());
    m.start(ctx).unwrap();
    assert!(key.is_file());
    assert_eq!(
        m.effective_config().unwrap()["hash_key"].as_str(),
        Some(format!("file:{}", key.display()).as_str())
    );
}

#[test]
fn hash_mode_without_a_key_location_does_not_start() {
    let mut m = UrlModule::default();
    m.configure(&ConfigDoc::new("[modules.url]\nquery = \"hash\"\n"))
        .unwrap();
    let (ctx, _) = module_context(&FakeClock::default());
    let err = m.start(ctx).unwrap_err();
    assert!(err.to_string().contains("hash_key"), "{err}");
}

#[test]
fn a_bad_hash_key_reference_points_at_the_value() {
    let text = "[modules.url]\nquery = \"hash\"\nhash_key = \"plain-text-key\"\n";
    let err = scribe_module_url::settings(&ConfigDoc::new(text)).unwrap_err();
    assert!(err.message.contains("malformed secret reference"), "{err}");
    assert_eq!(&text[err.span.unwrap()], "\"plain-text-key\"");
}

#[test]
fn switching_to_hash_while_running_loads_the_key() {
    let dir = tempfile::tempdir().unwrap();
    let mut m = UrlModule::default();
    m.configure(&ConfigDoc::new("")).unwrap();
    let (mut ctx, _) = module_context(&FakeClock::default());
    ctx.data_dir = Some(dir.path().to_owned());
    m.start(ctx).unwrap();
    assert!(!dir.path().join(scribe_module_url::KEY_FILE).exists());
    m.configure(&ConfigDoc::new("[modules.url]\nquery = \"hash\"\n"))
        .unwrap();
    assert!(url_of(&m, "http://plain.example.com/a?x=1").contains("<hash:"));
}
