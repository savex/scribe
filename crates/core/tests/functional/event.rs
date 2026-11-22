//! Functional tests for `scribe_core::event` (moved from `src/event.rs`).

use scribe_core::event::*;
use scribe_core::*;
use std::time::UNIX_EPOCH;

fn event(hostname: Option<&str>, ech: bool) -> FlowEvent {
    FlowEvent {
        ts: UNIX_EPOCH,
        pid: None,
        process_path: None,
        proto: Protocol::Tcp,
        src: "10.0.0.2:50000".parse().unwrap(),
        dst_ip: "192.0.2.12".parse().unwrap(),
        dst_port: 443,
        hostname: hostname.map(str::to_owned),
        ech,
        notes: Notes::new(),
        security: Security::Tls,
        bytes_out: 0,
        kind: FlowKind::NewFlow,
    }
}

#[test]
fn unresolved_means_no_name_or_only_an_ech_outer_name() {
    assert!(!event(Some("api.example.com"), false).unresolved());
    assert!(event(None, false).unresolved());
    assert!(event(Some("public.example.com"), true).unresolved());
}

#[test]
fn observations_cut_payload_to_head_max() {
    let obs = Observation::from(event(None, false)).with_head(&[7; HEAD_MAX + 1]);
    assert_eq!(obs.head.unwrap().len(), HEAD_MAX);
}
