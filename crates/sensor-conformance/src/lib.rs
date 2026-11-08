//! Backend-independent test suite for [`Sensor`] implementations.
//!
//! The suite starts the sensor, generates known traffic from this process to local servers,
//! and checks the sensor reports each connection correctly. It needs whatever privileges the
//! sensor needs (root, admin, an approved Network Extension), so backend crates mark it `#[ignore]`
//! and CI runs it with `--ignored` on dedicated machines.
//!
//! The traffic stays on loopback. Sensors that cannot see loopback (e.g. some Network Extension
//! setups) need a variant of [`traffic::send`] that targets a lab host instead.

pub mod traffic;

use std::sync::mpsc::{self, Receiver};
use std::time::{Duration, Instant};

use scribe_core::{Observation, Sensor};

pub use traffic::{Case, Expected};

pub struct SuiteOptions {
    /// Check pid and process path. False for the pcap fallback.
    pub expect_process_info: bool,
    /// Longest wait for each expected event.
    pub timeout: Duration,
}

impl Default for SuiteOptions {
    fn default() -> Self {
        Self {
            expect_process_info: true,
            timeout: Duration::from_secs(1),
        }
    }
}

pub fn default_cases() -> Vec<Case> {
    vec![
        Case::TlsSni {
            host: "conformance.example.com",
        },
        Case::PlainHttp {
            host: "plain.example.com",
            path: "/conformance?id=1",
        },
        Case::PlainTcp {
            payload: b"\x00\x01SCRIBE-CONFORMANCE",
        },
        Case::Udp {
            payload: b"scribe-conformance-udp",
        },
    ]
}

/// Runs every case and returns all mismatches instead of stopping at the first one.
pub fn run_sensor_suite(sensor: &mut dyn Sensor, opts: &SuiteOptions) -> Result<(), Vec<String>> {
    let (tx, rx) = mpsc::channel();
    sensor
        .start(tx)
        .map_err(|e| vec![format!("{}: start failed: {e}", sensor.name())])?;

    let mut failures = Vec::new();
    for case in default_cases() {
        match traffic::send(&case) {
            Ok((expected, receipt)) => {
                if let Err(err) = receipt.wait() {
                    failures.push(format!("{case:?}: local server error: {err}"));
                    continue;
                }
                let seen = wait_for(&rx, &expected, opts.timeout);
                match seen.first() {
                    Some(first) => {
                        failures.extend(compare(&case, &expected, &first.event, opts));
                        failures.extend(check_head(&case, &expected, &seen));
                    }
                    None => failures.push(format!(
                        "{case:?}: no event for {} within {:?}",
                        expected.dst, opts.timeout
                    )),
                }
            }
            Err(err) => failures.push(format!("{case:?}: could not send traffic: {err}")),
        }
    }

    sensor.stop();
    if failures.is_empty() {
        Ok(())
    } else {
        Err(failures)
    }
}

/// Observations for the expected destination, until the expected head bytes arrived (or, when
/// none are expected, until the first one) or the timeout ran out.
fn wait_for(
    rx: &Receiver<Observation>,
    expected: &Expected,
    timeout: Duration,
) -> Vec<Observation> {
    let deadline = Instant::now() + timeout;
    let mut seen = Vec::new();
    while let Some(left) = deadline.checked_duration_since(Instant::now()) {
        let Ok(obs) = rx.recv_timeout(left) else {
            break;
        };
        if obs.event.dst_ip != expected.dst.ip() || obs.event.dst_port != expected.dst.port() {
            continue;
        }
        seen.push(obs);
        let done = match &expected.head {
            None => true,
            Some(want) => seen.iter().any(|o| head_matches(o, want)),
        };
        if done {
            break;
        }
    }
    seen
}

fn head_matches(obs: &Observation, want: &[u8]) -> bool {
    // A sensor may pass on only the first segment, so a non-empty prefix of `want` counts too.
    obs.head
        .as_deref()
        .is_some_and(|got| !got.is_empty() && (got.starts_with(want) || want.starts_with(got)))
}

/// The sensor must pass on the client's first bytes for TCP cases, in some observation.
fn check_head(case: &Case, expected: &Expected, seen: &[Observation]) -> Vec<String> {
    match &expected.head {
        Some(want) if !seen.iter().any(|o| head_matches(o, want)) => vec![format!(
            "{case:?}: no observation carried the first {} client bytes",
            want.len()
        )],
        _ => Vec::new(),
    }
}

fn compare(
    case: &Case,
    expected: &Expected,
    event: &scribe_core::FlowEvent,
    opts: &SuiteOptions,
) -> Vec<String> {
    let mut out = Vec::new();
    let mut check = |field: &str, ok: bool, got: String, want: String| {
        if !ok {
            out.push(format!("{case:?}: {field} is {got}, expected {want}"));
        }
    };
    check(
        "proto",
        event.proto == expected.proto,
        format!("{:?}", event.proto),
        format!("{:?}", expected.proto),
    );
    check(
        "hostname",
        event.hostname == expected.hostname,
        format!("{:?}", event.hostname),
        format!("{:?}", expected.hostname),
    );
    // UDP payloads are opaque, so only TCP cases pin the security classification.
    if expected.proto != scribe_core::Protocol::Udp {
        check(
            "security",
            event.security == expected.security,
            format!("{:?}", event.security),
            format!("{:?}", expected.security),
        );
    }
    if opts.expect_process_info {
        let pid = std::process::id();
        check(
            "pid",
            event.pid == Some(pid),
            format!("{:?}", event.pid),
            pid.to_string(),
        );
        let exe = std::env::current_exe()
            .ok()
            .map(|p| p.to_string_lossy().into_owned());
        check(
            "process_path",
            event.process_path == exe,
            format!("{:?}", event.process_path),
            format!("{exe:?}"),
        );
    }
    out
}
