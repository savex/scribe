//! INT-11: alerts leave a running scribed through its outputs: a signed webhook to a local
//! receiver (plain http is allowed to loopback) and the log.

use std::io::{Read, Write};
use std::net::TcpListener;
use std::time::Duration;

use scribe_secrets::SecretRef;
use tokio::sync::mpsc;

use crate::api::{two_flows, Daemon};

/// A receiver on 127.0.0.1:0 that answers 200 and hands over each request's headers and body.
fn receiver() -> (String, mpsc::UnboundedReceiver<(String, Vec<u8>)>) {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let url = format!(
        "http://127.0.0.1:{}/scribe",
        listener.local_addr().unwrap().port()
    );
    let (tx, rx) = mpsc::unbounded_channel();
    std::thread::spawn(move || {
        for stream in listener.incoming() {
            let Ok(mut s) = stream else { return };
            let mut head = Vec::new();
            let mut b = [0u8; 1];
            while !head.ends_with(b"\r\n\r\n") && s.read(&mut b).unwrap_or(0) == 1 {
                head.push(b[0]);
            }
            let head = String::from_utf8_lossy(&head).into_owned();
            let len: usize = head
                .lines()
                .find_map(|l| l.strip_prefix("Content-Length: "))
                .and_then(|v| v.trim().parse().ok())
                .unwrap_or(0);
            let mut body = vec![0u8; len];
            let _ = s.read_exact(&mut body);
            let _ = s.write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n");
            if tx.send((head, body)).is_err() {
                return;
            }
        }
    });
    (url, rx)
}

#[tokio::test(flavor = "multi_thread")]
async fn an_alert_reaches_a_signed_webhook() {
    let dir = tempfile::tempdir().unwrap();
    let key = SecretRef::File(dir.path().join("webhook.key"));
    let secret = scribe_secrets::read_or_create(&key, 32).unwrap();
    let (url, mut received) = receiver();
    let extra = format!(
        "[alerts]\nmax_per_minute = 0\n[[alerts.webhooks]]\nname = 'ops'\nurl = '{url}'\nsecret = '{key}'\ntimeout = '5s'\n"
    );
    // Caution mode: the raw-IP flow of `two_flows` raises an alert.
    let daemon = Daemon::start_in(dir, "caution", &extra, two_flows()).await;

    let (head, body) = tokio::time::timeout(Duration::from_secs(10), received.recv())
        .await
        .expect("the webhook is called")
        .unwrap();
    assert!(head.starts_with("POST /scribe HTTP/1.1\r\n"), "{head}");
    let signature = head
        .lines()
        .find_map(|l| l.strip_prefix("X-Scribe-Signature: "))
        .unwrap()
        .trim()
        .to_owned();
    let ts: u64 = signature
        .strip_prefix("t=")
        .and_then(|s| s.split(',').next())
        .and_then(|t| t.parse().ok())
        .unwrap();
    assert_eq!(
        signature,
        scribe_net::signature(secret.expose(), ts, &body),
        "signed with the key from the secret reference"
    );
    let alert: serde_json::Value = serde_json::from_slice(&body).unwrap();
    assert_eq!(alert["type"], "alert");
    assert_eq!(alert["reason"], "raw_ip");
    assert_eq!(alert["dst"], "198.51.100.7:8443");
    assert_eq!(alert["process_path"], "/opt/agent/bin/agent");
    assert_eq!(alert["machine"], scribe_daemon::app::machine_name());

    daemon.stop().await;
}
