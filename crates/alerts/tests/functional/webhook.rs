//! FUN-A02 `webhook_signing_and_https`, output part: signed JSON, retries, summaries (the HTTPS,
//! redirect and pin rules are tested in `scribe-net`).

use std::io::{Read, Write};
use std::net::TcpListener;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use scribe_alerts::{AlertOutput, WebhookOutput, SIGNATURE_HEADER};
use scribe_core::Clock;
use scribe_net::{Client, Options};
use scribe_test_support::FakeClock;

use super::alert;

#[derive(Debug, Clone)]
struct Got {
    head: String,
    body: Vec<u8>,
}

impl Got {
    fn header(&self, name: &str) -> Option<String> {
        self.head.lines().find_map(|l| {
            let (n, v) = l.split_once(':')?;
            n.eq_ignore_ascii_case(name).then(|| v.trim().to_owned())
        })
    }
}

/// Answers each connection with the next status and records the requests.
fn server(statuses: Vec<u16>) -> (String, Arc<Mutex<Vec<Got>>>) {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let url = format!(
        "http://127.0.0.1:{}/hook",
        listener.local_addr().unwrap().port()
    );
    let got = Arc::new(Mutex::new(Vec::new()));
    let log = got.clone();
    std::thread::spawn(move || {
        for status in statuses {
            let Ok((mut s, _)) = listener.accept() else {
                return;
            };
            let mut head = Vec::new();
            let mut b = [0u8; 1];
            while !head.ends_with(b"\r\n\r\n") && s.read(&mut b).unwrap_or(0) == 1 {
                head.push(b[0]);
            }
            let head = String::from_utf8_lossy(&head).into_owned();
            let mut req = Got { head, body: vec![] };
            let len: usize = req
                .header("content-length")
                .and_then(|v| v.parse().ok())
                .unwrap_or(0);
            req.body = vec![0; len];
            let _ = s.read_exact(&mut req.body);
            log.lock().unwrap().push(req);
            let _ = write!(s, "HTTP/1.1 {status} X\r\nContent-Length: 0\r\n\r\n");
        }
    });
    (url, got)
}

fn webhook(url: &str, clock: Arc<FakeClock>) -> WebhookOutput {
    webhook_with(url, clock, Duration::from_secs(5))
}

fn webhook_with(url: &str, clock: Arc<FakeClock>, timeout: Duration) -> WebhookOutput {
    let client = Client::new(Options {
        timeout,
        ..Options::default()
    })
    .unwrap();
    WebhookOutput::new(
        "ops",
        url,
        client,
        b"whsec_test".to_vec().into(),
        "build-01",
        clock,
    )
    .with_retry_after(vec![Duration::from_millis(10), Duration::from_millis(10)])
}

#[test]
fn webhook_posts_signed_json() {
    let (url, got) = server(vec![200, 204]);
    let clock = Arc::new(FakeClock::at_unix(1_800_000_000));
    let hook = webhook(&url, clock.clone());
    assert_eq!(hook.name(), "ops");
    hook.notify(&alert("example.com", clock.now())).unwrap();
    hook.suppressed(12).unwrap();

    let got = got.lock().unwrap().clone();
    let first = &got[0];
    assert!(first.head.starts_with("POST /hook HTTP/1.1"));
    assert_eq!(
        first.header("content-type").as_deref(),
        Some("application/json")
    );
    let sig = first.header(SIGNATURE_HEADER).unwrap();
    assert_eq!(
        sig,
        scribe_net::signature(b"whsec_test", 1_800_000_000, &first.body)
    );
    assert!(sig.starts_with("t=1800000000,v1="));

    let v: serde_json::Value = serde_json::from_slice(&first.body).unwrap();
    assert_eq!(v["type"], "alert");
    assert_eq!(v["version"], 1);
    assert_eq!(v["machine"], "build-01");
    assert_eq!(v["reason"], "plaintext");
    assert_eq!(v["score"], 60);
    assert_eq!(v["host"], "example.com");
    assert_eq!(v["dst"], "203.0.113.9:80");
    assert_eq!(v["process_path"], "/usr/bin/curl");
    assert_eq!(v["ts_ms"], 1_800_000_000_000u64);
    assert_eq!(v["notes"]["url"], "http://example.com/a?q=<redacted>");

    let summary: serde_json::Value = serde_json::from_slice(&got[1].body).unwrap();
    assert_eq!(summary["type"], "suppressed");
    assert_eq!(summary["count"], 12);
}

#[test]
fn webhook_retries_server_errors_but_not_client_errors() {
    let clock = Arc::new(FakeClock::at_unix(1_800_000_000));
    let (url, got) = server(vec![503, 429, 200]);
    webhook(&url, clock.clone())
        .notify(&alert("example.com", clock.now()))
        .unwrap();
    assert_eq!(got.lock().unwrap().len(), 3);

    let (url, got) = server(vec![400, 200]);
    let err = webhook(&url, clock.clone())
        .notify(&alert("example.com", clock.now()))
        .unwrap_err();
    assert_eq!(err, "the webhook answered 400");
    assert_eq!(got.lock().unwrap().len(), 1, "no retry for 4xx");

    let (url, got) = server(vec![500, 500, 500, 200]);
    let err = webhook(&url, clock.clone())
        .notify(&alert("example.com", clock.now()))
        .unwrap_err();
    assert_eq!(err, "the webhook answered 500 (after 3 attempts)");
    assert_eq!(got.lock().unwrap().len(), 3);
}

#[test]
fn webhook_network_failures_are_retried_then_reported() {
    let clock = Arc::new(FakeClock::at_unix(1_800_000_000));
    let port = TcpListener::bind("127.0.0.1:0")
        .unwrap()
        .local_addr()
        .unwrap()
        .port();
    // A short timeout: Windows retries a refused connect for about 2 s.
    let err = webhook_with(
        &format!("http://127.0.0.1:{port}/hook"),
        clock.clone(),
        Duration::from_millis(300),
    )
    .notify(&alert("example.com", clock.now()))
    .unwrap_err();
    assert!(err.contains("http://127.0.0.1:"), "{err}");
    assert!(err.ends_with("(after 3 attempts)"), "{err}");
}
