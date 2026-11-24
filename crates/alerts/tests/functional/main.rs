//! Functional tests for `scribe_alerts`: rate limit, dispatcher lanes and the log output.

mod dispatch;
mod log;
mod throttle;
#[cfg(feature = "webhook")]
mod webhook;

use std::net::IpAddr;
use std::time::{Duration, SystemTime};

use scribe_core::{Alert, Notes};

pub fn alert(host: &str, at: SystemTime) -> Alert {
    let mut notes = Notes::new();
    notes.insert("url", "http://example.com/a?q=<redacted>".into());
    Alert {
        ts: at,
        host: Some(host.to_owned()),
        dst_ip: IpAddr::from([203, 0, 113, 9]),
        dst_port: 80,
        process_path: Some("/usr/bin/curl".into()),
        score: 60,
        reason: "plaintext".into(),
        notes,
    }
}

pub const GRACE: Duration = Duration::from_secs(5);
