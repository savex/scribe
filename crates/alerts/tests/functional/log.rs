//! FUN-A01 `log_output_writes_alerts`: the alert log line and its fields.

use std::io::Write;
use std::sync::{Arc, Mutex};

use scribe_alerts::{alert_line, AlertOutput, LogOutput};
use scribe_core::Clock;
use scribe_test_support::FakeClock;
use tracing_subscriber::fmt::MakeWriter;

use super::alert;

#[derive(Clone, Default)]
struct Captured(Arc<Mutex<Vec<u8>>>);

impl Write for Captured {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        self.0.lock().unwrap().extend_from_slice(buf);
        Ok(buf.len())
    }
    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

impl<'a> MakeWriter<'a> for Captured {
    type Writer = Captured;
    fn make_writer(&'a self) -> Self::Writer {
        self.clone()
    }
}

fn logged(json: bool, f: impl FnOnce()) -> String {
    let out = Captured::default();
    let builder = tracing_subscriber::fmt()
        .with_writer(out.clone())
        .with_ansi(false)
        .without_time();
    if json {
        tracing::subscriber::with_default(builder.json().finish(), f);
    } else {
        tracing::subscriber::with_default(builder.finish(), f);
    }
    let bytes = out.0.lock().unwrap().clone();
    String::from_utf8(bytes).unwrap()
}

#[test]
fn log_output_writes_alerts() {
    let clock = FakeClock::at_unix(1_800_000_000);
    let a = alert("example.com", clock.now());
    let text = logged(false, || LogOutput.notify(&a).unwrap());
    assert!(text.starts_with(" WARN scribe::alert:"), "{text}");
    assert!(
        text.contains("alert plaintext: example.com (203.0.113.9:80)"),
        "{text}"
    );
    for field in [
        "reason=plaintext",
        "host=\"example.com\"",
        "dst=203.0.113.9:80",
        "process=\"/usr/bin/curl\"",
        "score=60",
        "notes=url=http://example.com/a?q=<redacted>",
    ] {
        assert!(text.contains(field), "{field} missing in {text}");
    }

    let json = logged(true, || LogOutput.notify(&a).unwrap());
    let v: serde_json::Value = serde_json::from_str(json.trim()).unwrap();
    assert_eq!(v["level"], "WARN");
    assert_eq!(v["target"], "scribe::alert");
    assert_eq!(v["fields"]["reason"], "plaintext");
    assert_eq!(v["fields"]["score"], 60);
}

#[test]
fn log_output_line_without_host_and_summary() {
    let clock = FakeClock::at_unix(1_800_000_000);
    let mut a = alert("x", clock.now());
    a.host = None;
    a.reason = "raw_ip".into();
    assert_eq!(alert_line(&a), "alert raw_ip: 203.0.113.9:80");
    let text = logged(false, || LogOutput.suppressed(7).unwrap());
    assert!(text.contains("suppressed=7"), "{text}");
    assert!(text.contains("7 more alerts in the last minute"), "{text}");
}
