use std::net::SocketAddr;
use std::time::{Duration, SystemTime};

use scribe_core::{FlowKind, Protocol};
use scribe_sensor_windows::flows::UDP_REPEAT;
use scribe_sensor_windows::{EtwFlows, NetEvent, NetKind};

fn ev(kind: NetKind, pid: u32, src: &str, dst: &str) -> NetEvent {
    NetEvent {
        kind,
        pid,
        src: src.parse::<SocketAddr>().unwrap(),
        dst: dst.parse::<SocketAddr>().unwrap(),
    }
}

#[test]
fn every_tcp_attempt_is_a_flow_without_process_or_bytes() {
    let mut f = EtwFlows::new();
    let t = SystemTime::UNIX_EPOCH;
    let e = ev(NetKind::TcpConnect, 5, "10.0.0.2:50001", "192.0.2.10:443");
    for _ in 0..2 {
        let o = f.observe(&e, t).unwrap();
        assert_eq!(o.event.kind, FlowKind::NewFlow);
        assert_eq!(o.event.proto, Protocol::Tcp);
        assert_eq!(
            (o.event.dst_ip.to_string(), o.event.dst_port),
            ("192.0.2.10".into(), 443)
        );
        assert_eq!(o.event.pid, None, "the join fills it in");
        assert!(o.head.is_none());
    }
}

#[test]
fn a_udp_flow_is_new_once_per_socket_and_destination_until_it_goes_quiet() {
    let mut f = EtwFlows::new();
    let t0 = SystemTime::UNIX_EPOCH + Duration::from_secs(1_800_000_000);
    let dns = ev(NetKind::UdpSend, 9, "10.0.0.2:53001", "192.0.2.53:53");
    assert!(f.observe(&dns, t0).is_some());
    assert!(f.observe(&dns, t0 + Duration::from_secs(10)).is_none());
    // Each datagram restarts the quiet period.
    assert!(f.observe(&dns, t0 + Duration::from_secs(35)).is_none());
    assert!(f
        .observe(&dns, t0 + Duration::from_secs(35) + UDP_REPEAT)
        .is_some());
    // Another destination, another process: new flows.
    assert!(f
        .observe(
            &ev(NetKind::UdpSend, 9, "10.0.0.2:53001", "192.0.2.54:53"),
            t0
        )
        .is_some());
    assert!(f
        .observe(
            &ev(NetKind::UdpSend, 10, "10.0.0.2:53001", "192.0.2.53:53"),
            t0
        )
        .is_some());
    assert_eq!(f.udp_flows(), 3);
}
