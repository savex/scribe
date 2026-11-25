use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use scribe_core::{FlowKind, Observation};
use scribe_sensor_linux::{Joiner, Owners, Record, RecordKind, HOLD};
use scribe_test_support::{flow, FakeClock};

fn addr(s: &str) -> SocketAddr {
    s.parse().unwrap()
}

fn joiner() -> (Joiner, Arc<FakeClock>) {
    let clock = Arc::new(FakeClock::at_unix(1_800_000_000));
    let owners = Owners::new(clock.clone(), Box::new(|pid| Some(format!("/bin/p{pid}"))));
    (Joiner::new(owners, clock.clone()), clock)
}

fn new_flow(src: &str, dst: &str) -> Observation {
    let mut o = flow(dst).observe();
    o.event.src = addr(src);
    o.event.kind = FlowKind::NewFlow;
    o
}

fn udp_record(tgid: u32, src: &str, dst: &str) -> Record {
    Record {
        kind: RecordKind::UdpSend,
        ts_ns: 0,
        cgroup_id: 0,
        tgid,
        pid: tgid,
        uid: 0,
        comm: "dig".into(),
        src: addr(src),
        dst: addr(dst),
    }
}

#[test]
fn an_observation_waits_for_a_late_record_and_keeps_its_place() {
    let (mut j, clock) = joiner();
    let mut early = new_flow("10.0.0.2:53001", "192.0.2.53:53");
    early.event.proto = scribe_core::Protocol::Udp;
    let mut later = new_flow("10.0.0.2:53002", "192.0.2.54:53");
    later.event.proto = scribe_core::Protocol::Udp;
    assert!(j.push(vec![early, later]).is_empty(), "no owner yet: held");
    assert_eq!(j.held(), 2);

    // The record of the second flow arrives first: it still waits behind the first.
    j.record(&udp_record(8, "0.0.0.0:53002", "192.0.2.54:53"));
    assert!(j.ready().is_empty());
    j.record(&udp_record(7, "0.0.0.0:53001", "192.0.2.53:53"));
    let out = j.ready();
    let pids: Vec<Option<u32>> = out.iter().map(|o| o.event.pid).collect();
    assert_eq!(pids, [Some(7), Some(8)]);
    assert_eq!(out[0].event.process_path.as_deref(), Some("/bin/p7"));
    assert_eq!(j.held(), 0);
    clock.advance(Duration::from_secs(1));
    let s = j.stats();
    assert_eq!((s.attributed, s.missed), (2, 0));
}

#[test]
fn without_a_record_an_observation_goes_out_after_the_hold() {
    let (mut j, clock) = joiner();
    assert!(j
        .push(vec![new_flow("10.0.0.2:1", "192.0.2.10:443")])
        .is_empty());
    clock.advance(HOLD - Duration::from_millis(1));
    assert!(j.ready().is_empty());
    clock.advance(Duration::from_millis(1));
    let out = j.ready();
    assert_eq!(out.len(), 1);
    assert_eq!(out[0].event.pid, None);
    let s = j.stats();
    assert_eq!((s.attributed, s.missed), (0, 1));
}

#[test]
fn dns_answers_and_known_processes_pass_at_once_and_flush_empties_the_queue() {
    let (mut j, _) = joiner();
    let mut dns = flow("10.0.0.2:53001").observe();
    dns.event.kind = FlowKind::DnsResponse;
    let known = flow("192.0.2.10:443")
        .process(5, "/usr/bin/known")
        .observe();
    let out = j.push(vec![dns, known]);
    assert_eq!(out.len(), 2);
    assert_eq!(out[0].event.pid, None, "DNS answers get no process");

    assert!(j
        .push(vec![new_flow("10.0.0.2:2", "192.0.2.10:443")])
        .is_empty());
    assert_eq!(j.flush().len(), 1);
    assert_eq!(j.held(), 0);
}
