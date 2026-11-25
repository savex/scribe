use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use scribe_core::FlowKind;
use scribe_process::Transport;
use scribe_sensor_linux::{Owners, Record, RecordKind, OWNER_TTL};
use scribe_test_support::{flow, FakeClock};

fn addr(s: &str) -> SocketAddr {
    s.parse().unwrap()
}

fn record(kind: RecordKind, tgid: u32, src: &str, dst: &str) -> Record {
    Record {
        kind,
        ts_ns: 0,
        cgroup_id: 1,
        tgid,
        pid: tgid + 1,
        uid: 1000,
        comm: format!("app{tgid}"),
        src: addr(src),
        dst: addr(dst),
    }
}

fn owners() -> (Owners, Arc<FakeClock>, Arc<std::sync::Mutex<u32>>) {
    let clock = Arc::new(FakeClock::at_unix(1_800_000_000));
    let reads = Arc::new(std::sync::Mutex::new(0));
    let counted = reads.clone();
    let exe = Box::new(move |pid: u32| {
        *counted.lock().unwrap() += 1;
        (pid != 0).then(|| format!("/opt/app{pid}/bin/app"))
    });
    (Owners::new(clock.clone(), exe), clock, reads)
}

#[test]
fn tcp_flows_match_by_their_exact_addresses_and_transport() {
    let (mut o, _, _) = owners();
    o.record(&record(
        RecordKind::TcpConnect,
        42,
        "10.0.0.2:50001",
        "192.0.2.10:443",
    ));
    let owner = o
        .lookup(
            Transport::Tcp,
            addr("10.0.0.2:50001"),
            addr("192.0.2.10:443"),
        )
        .unwrap();
    assert_eq!(
        (owner.pid, owner.uid, owner.comm.as_str()),
        (42, 1000, "app42")
    );
    assert_eq!(owner.path.as_deref(), Some("/opt/app42/bin/app"));
    assert!(o
        .lookup(
            Transport::Udp,
            addr("10.0.0.2:50001"),
            addr("192.0.2.10:443")
        )
        .is_none());
    assert!(o
        .lookup(
            Transport::Tcp,
            addr("10.0.0.2:50001"),
            addr("192.0.2.11:443")
        )
        .is_none());
}

#[test]
fn an_unbound_udp_socket_matches_by_port_and_mapped_addresses_by_ipv4() {
    let (mut o, _, _) = owners();
    o.record(&record(
        RecordKind::UdpSend,
        7,
        "0.0.0.0:53001",
        "192.0.2.53:53",
    ));
    o.record(&record(
        RecordKind::UdpSend,
        8,
        "[::]:53002",
        "[2001:db8::53]:53",
    ));
    let pid = |o: &mut Owners, src: &str, dst: &str| {
        o.lookup(Transport::Udp, addr(src), addr(dst))
            .map(|x| x.pid)
    };
    assert_eq!(pid(&mut o, "10.0.0.2:53001", "192.0.2.53:53"), Some(7));
    assert_eq!(
        pid(&mut o, "[::ffff:10.0.0.2]:53001", "[::ffff:192.0.2.53]:53"),
        Some(7)
    );
    assert_eq!(pid(&mut o, "[fd00::2]:53002", "[2001:db8::53]:53"), Some(8));
    assert_eq!(pid(&mut o, "10.0.0.2:53001", "192.0.2.54:53"), None);
}

#[test]
fn observations_get_the_owner_unless_the_sensor_knew_it() {
    let (mut o, _, _) = owners();
    o.record(&record(
        RecordKind::TcpConnect,
        42,
        "10.0.0.2:50001",
        "192.0.2.10:443",
    ));
    let mut obs = flow("192.0.2.10:443").observe();
    obs.event.src = addr("10.0.0.2:50001");
    obs.event.kind = FlowKind::NewFlow;
    assert!(o.attribute(&mut obs));
    assert_eq!(obs.event.pid, Some(42));
    assert_eq!(
        obs.event.process_path.as_deref(),
        Some("/opt/app42/bin/app")
    );

    let mut known = flow("192.0.2.10:443")
        .process(5, "/usr/bin/known")
        .observe();
    known.event.src = addr("10.0.0.2:50001");
    assert!(o.attribute(&mut known));
    assert_eq!(known.event.pid, Some(5));

    let mut stranger = flow("198.51.100.4:443").observe();
    assert!(!o.attribute(&mut stranger));
    assert_eq!(stranger.event.pid, None);
}

#[test]
fn owners_expire_after_the_ttl_unless_used() {
    let (mut o, clock, _) = owners();
    o.record(&record(
        RecordKind::TcpConnect,
        1,
        "10.0.0.2:1",
        "192.0.2.10:443",
    ));
    o.record(&record(
        RecordKind::TcpConnect,
        2,
        "10.0.0.2:2",
        "192.0.2.10:443",
    ));
    clock.advance(OWNER_TTL - Duration::from_secs(1));
    // Flow 1 stays in use.
    assert!(o
        .lookup(Transport::Tcp, addr("10.0.0.2:1"), addr("192.0.2.10:443"))
        .is_some());
    clock.advance(Duration::from_secs(2));
    o.record(&record(
        RecordKind::TcpConnect,
        3,
        "10.0.0.2:3",
        "192.0.2.10:443",
    ));
    assert_eq!(o.len(), 2, "flow 2 expired, 1 and 3 remain");
    assert!(o
        .lookup(Transport::Tcp, addr("10.0.0.2:2"), addr("192.0.2.10:443"))
        .is_none());
}

#[test]
fn a_busy_process_has_its_path_read_once_in_a_while() {
    let (mut o, clock, reads) = owners();
    for port in 1..=50 {
        o.record(&record(
            RecordKind::TcpConnect,
            9,
            &format!("10.0.0.2:{port}"),
            "192.0.2.10:443",
        ));
    }
    assert_eq!(*reads.lock().unwrap(), 1);
    clock.advance(Duration::from_secs(6));
    o.record(&record(
        RecordKind::TcpConnect,
        9,
        "10.0.0.2:99",
        "192.0.2.10:443",
    ));
    assert_eq!(
        *reads.lock().unwrap(),
        2,
        "read again: the pid may be reused"
    );
}
