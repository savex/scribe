use std::net::SocketAddr;
use std::sync::Arc;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use scribe_core::{Alert, AlertOutput, Clock};
use scribe_net::{Client, NetError};
use scribe_secrets::Secret;
use serde_json::{json, Value};

/// Header carrying the HMAC signature (`t=<unix seconds>,v1=<hex>`, see [`scribe_net::signature`]).
pub const SIGNATURE_HEADER: &str = "X-Scribe-Signature";

/// Waits before the 2nd and 3rd attempt of a delivery that failed on the network or with a
/// 429 / 5xx answer.
pub const RETRY_AFTER: [Duration; 2] = [Duration::from_secs(1), Duration::from_secs(4)];

/// Posts each alert as JSON to an HTTPS endpoint, signed with HMAC-SHA256 (specs 12.1.1):
///
/// ```json
/// {"type": "alert", "version": 1, "machine": "build-01", "scribe_version": "0.3.0",
///  "ts_ms": 1800000000000, "reason": "plaintext", "score": 60, "host": "example.com",
///  "dst": "203.0.113.9:80", "process_path": "/usr/bin/curl",
///  "notes": {"url": "http://example.com/a?q=<redacted>"}}
/// ```
///
/// A rate-limit summary is `{"type": "suppressed", "count": 12, ...}`. Notes are what the modules
/// stored, so the URL follows `[modules.url] query`. Any 2xx is success; other answers fail.
pub struct WebhookOutput {
    name: String,
    url: String,
    client: Client,
    secret: Secret,
    machine: String,
    clock: Arc<dyn Clock>,
    retry_after: Vec<Duration>,
}

impl WebhookOutput {
    pub fn new(
        name: impl Into<String>,
        url: impl Into<String>,
        client: Client,
        secret: Secret,
        machine: impl Into<String>,
        clock: Arc<dyn Clock>,
    ) -> Self {
        Self {
            name: name.into(),
            url: url.into(),
            client,
            secret,
            machine: machine.into(),
            clock,
            retry_after: RETRY_AFTER.to_vec(),
        }
    }

    /// Other waits between attempts (tests use short ones); empty = a single attempt.
    pub fn with_retry_after(mut self, waits: Vec<Duration>) -> Self {
        self.retry_after = waits;
        self
    }

    fn envelope(&self, kind: &str, now: SystemTime) -> serde_json::Map<String, Value> {
        let mut m = serde_json::Map::new();
        m.insert("type".into(), json!(kind));
        m.insert("version".into(), json!(1));
        m.insert("machine".into(), json!(self.machine));
        m.insert("scribe_version".into(), json!(scribe_core::VERSION));
        m.insert("sent_ms".into(), json!(epoch_ms(now)));
        m
    }

    /// The JSON body for `alert`.
    pub fn alert_body(&self, alert: &Alert) -> Vec<u8> {
        let mut m = self.envelope("alert", self.clock.now());
        m.insert("ts_ms".into(), json!(epoch_ms(alert.ts)));
        m.insert("reason".into(), json!(alert.reason));
        m.insert("score".into(), json!(alert.score));
        m.insert("host".into(), json!(alert.host));
        m.insert(
            "dst".into(),
            json!(SocketAddr::new(alert.dst_ip, alert.dst_port).to_string()),
        );
        m.insert("process_path".into(), json!(alert.process_path));
        let notes: serde_json::Map<String, Value> = alert
            .notes
            .iter()
            .map(|(k, v)| (k.to_owned(), v.clone()))
            .collect();
        m.insert("notes".into(), Value::Object(notes));
        Value::Object(m).to_string().into_bytes()
    }

    fn deliver(&self, body: &[u8]) -> Result<(), String> {
        let mut attempt = 0;
        loop {
            let ts = self
                .clock
                .now()
                .duration_since(UNIX_EPOCH)
                .map_or(0, |d| d.as_secs());
            let signature = scribe_net::signature(self.secret.expose(), ts, body);
            let result = self.client.post(
                &self.url,
                &[
                    ("Content-Type", "application/json"),
                    (SIGNATURE_HEADER, &signature),
                ],
                body,
            );
            let retry = match &result {
                Ok(r) if r.is_success() => return Ok(()),
                Ok(r) => r.status == 429 || r.status >= 500,
                Err(e) => e.is_transient(),
            };
            let Some(wait) = self.retry_after.get(attempt).filter(|_| retry) else {
                return Err(describe(result, attempt + 1));
            };
            attempt += 1;
            std::thread::sleep(*wait);
        }
    }
}

fn describe(result: Result<scribe_net::Response, NetError>, attempts: usize) -> String {
    let tries = if attempts == 1 {
        String::new()
    } else {
        format!(" (after {attempts} attempts)")
    };
    match result {
        Ok(r) => format!("the webhook answered {}{tries}", r.status),
        Err(e) => format!("{e}{tries}"),
    }
}

fn epoch_ms(t: SystemTime) -> u64 {
    t.duration_since(UNIX_EPOCH)
        .map_or(0, |d| d.as_millis() as u64)
}

impl AlertOutput for WebhookOutput {
    fn name(&self) -> &str {
        &self.name
    }

    fn notify(&self, alert: &Alert) -> Result<(), String> {
        self.deliver(&self.alert_body(alert))
    }

    fn suppressed(&self, count: u64) -> Result<(), String> {
        let mut m = self.envelope("suppressed", self.clock.now());
        m.insert("count".into(), json!(count));
        self.deliver(Value::Object(m).to_string().as_bytes())
    }
}
