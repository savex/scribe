use std::net::IpAddr;
use std::sync::mpsc;
use std::time::Duration;

use scribe_core::{Alert, AlertOutput, Clock, FlowKind, Protocol, Security, Sensor, HEAD_MAX};
use scribe_storage_api::{EventSink, StoredEvent};
use scribe_storage_conformance::block_on;
use scribe_test_support::{
    flow, FakeClock, FakeSensor, FaultySink, MemorySink, RecordingAlertSink,
};

#[test]
fn fake_sensor_replays_events_in_order() {
    let events = vec![
        flow("192.0.2.10:443").host("a.example").tls().build(),
        flow("192.0.2.11:53").udp().plaintext().build(),
    ];
    let mut sensor = FakeSensor::new(events);
    let (tx, rx) = mpsc::channel();
    sensor.start(tx).unwrap();

    let got: Vec<_> = rx.try_iter().map(|o| o.event).collect();
    assert_eq!(got.len(), 2);
    assert_eq!(got[0].hostname.as_deref(), Some("a.example"));
    assert_eq!(got[0].security, Security::Tls);
    assert_eq!(got[1].proto, Protocol::Udp);
    sensor.stop();
    assert!(!sensor.is_running());

    // Starting again replays the same observations.
    let (tx, rx) = mpsc::channel();
    sensor.start(tx).unwrap();
    assert_eq!(rx.try_iter().count(), 2);
    assert_eq!(sensor.starts(), 2);
}

#[test]
fn builder_makes_http_payload_observations() {
    let obs = flow("192.0.2.20:80")
        .http_get("http://plain.example.com/download?id=42")
        .observe();
    assert_eq!(obs.event.kind, FlowKind::Payload);
    assert_eq!(obs.event.security, Security::Plaintext);
    assert_eq!(obs.event.hostname.as_deref(), Some("plain.example.com"));
    let head = String::from_utf8(obs.head.unwrap()).unwrap();
    assert!(
        head.starts_with("GET /download?id=42 HTTP/1.1\r\nHost: plain.example.com\r\n"),
        "{head}"
    );

    let root = flow("192.0.2.20:80")
        .http_get("http://plain.example.com")
        .observe();
    assert!(root.head.unwrap().starts_with(b"GET / HTTP/1.1"));

    let big = flow("192.0.2.20:80")
        .payload(&[b'x'; HEAD_MAX + 10])
        .observe();
    assert_eq!(big.head.unwrap().len(), HEAD_MAX);

    let plain = flow("192.0.2.20:80").observe();
    assert!(plain.head.is_none());

    let noted = flow("192.0.2.20:80")
        .note("url", serde_json::json!("http://plain.example.com/"))
        .build();
    assert_eq!(
        noted.notes.get_str("url"),
        Some("http://plain.example.com/")
    );
}

#[test]
fn fake_clock_moves_only_when_told() {
    let clock = FakeClock::default();
    let start = clock.now();
    assert_eq!(clock.now(), start);
    clock.advance(Duration::from_secs(90));
    assert_eq!(clock.now(), start + Duration::from_secs(90));
}

#[test]
fn faulty_sink_fails_then_recovers() {
    let sink = FaultySink::new(MemorySink::default());
    let batch = vec![StoredEvent::Flow(flow("192.0.2.10:443").build())];

    sink.set_failing(true);
    assert!(block_on(sink.write_batch(&batch)).is_err());
    sink.set_failing(false);
    assert!(block_on(sink.write_batch(&batch)).is_ok());

    assert_eq!(sink.attempts(), 2);
    assert_eq!(sink.inner().events().len(), 1);
}

#[test]
fn recording_alert_sink_keeps_alerts() {
    let sink = RecordingAlertSink::default();
    sink.notify(&Alert {
        ts: FakeClock::default().now(),
        host: None,
        dst_ip: IpAddr::from([198, 51, 100, 7]),
        dst_port: 8443,
        process_path: None,
        score: 80,
        reason: "raw_ip".into(),
        notes: Default::default(),
    });
    assert_eq!(sink.count(), 1);
    assert_eq!(sink.alerts()[0].reason, "raw_ip");
}
