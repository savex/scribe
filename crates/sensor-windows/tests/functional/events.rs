use std::net::SocketAddr;

use scribe_sensor_windows::events::{
    DNS_QUERY_COMPLETED, TCP_CONNECT_V4, TCP_CONNECT_V6, UDP_SEND_V4, UDP_SEND_V6,
};
use scribe_sensor_windows::{DnsQuery, EventError, NetEvent, NetKind};

fn addr(s: &str) -> SocketAddr {
    s.parse().unwrap()
}

fn event(kind: NetKind, pid: u32, src: &str, dst: &str) -> NetEvent {
    NetEvent {
        kind,
        pid,
        src: addr(src),
        dst: addr(dst),
    }
}

#[test]
fn kernel_network_events_read_back_for_both_families_and_kinds() {
    for (e, id) in [
        (
            event(
                NetKind::TcpConnect,
                6120,
                "10.0.0.2:50001",
                "192.0.2.10:443",
            ),
            TCP_CONNECT_V4,
        ),
        (
            event(
                NetKind::TcpConnect,
                7,
                "[fd00::2]:50002",
                "[2001:db8::10]:443",
            ),
            TCP_CONNECT_V6,
        ),
        (
            event(NetKind::UdpSend, 900, "10.0.0.2:53001", "192.0.2.53:53"),
            UDP_SEND_V4,
        ),
        (
            event(NetKind::UdpSend, 900, "[::]:53002", "[2001:db8::53]:53"),
            UDP_SEND_V6,
        ),
    ] {
        let (got_id, bytes) = e.to_bytes();
        assert_eq!(got_id, id);
        assert_eq!(NetEvent::parse(id, &bytes).unwrap(), Some(e));
    }
}

#[test]
fn ports_and_addresses_are_in_network_order_and_pid_little_endian() {
    // Event 12 as Windows lays it out: PID, size, daddr, saddr, dport, sport (then more).
    let mut b = vec![0xe8, 0x17, 0, 0, 0, 0, 0, 0];
    b.extend_from_slice(&[192, 0, 2, 10, 10, 0, 0, 2]);
    b.extend_from_slice(&[0x01, 0xbb, 0xc3, 0x51]);
    let e = NetEvent::parse(TCP_CONNECT_V4, &b).unwrap().unwrap();
    assert_eq!(e.pid, 6120);
    assert_eq!(e.dst, addr("192.0.2.10:443"));
    assert_eq!(e.src, addr("10.0.0.2:50001"));
}

#[test]
fn mapped_addresses_come_back_as_ipv4_and_other_events_are_skipped() {
    let e = event(
        NetKind::TcpConnect,
        1,
        "[::ffff:10.0.0.2]:50010",
        "[::ffff:192.0.2.60]:443",
    );
    let (id, b) = e.to_bytes();
    let back = NetEvent::parse(id, &b).unwrap().unwrap();
    assert_eq!(back.dst, addr("192.0.2.60:443"));
    assert_eq!(back.src, addr("10.0.0.2:50010"));
    // 10 / 11: data sent / received; 13: disconnect.
    for other in [10, 11, 13, 15, 43] {
        assert_eq!(NetEvent::parse(other, &b).unwrap(), None);
    }
}

#[test]
fn short_events_are_refused_and_no_input_panics() {
    let (_, b) = event(NetKind::TcpConnect, 1, "[fd00::2]:1", "[2001:db8::1]:443").to_bytes();
    assert_eq!(
        NetEvent::parse(TCP_CONNECT_V6, &b[..43]),
        Err(EventError::Short {
            id: TCP_CONNECT_V6,
            len: 43,
            need: 44
        })
    );
    for id in [TCP_CONNECT_V4, TCP_CONNECT_V6, UDP_SEND_V4, UDP_SEND_V6] {
        for len in 0..b.len() {
            let _ = NetEvent::parse(id, &b[..len]);
        }
    }
    let dns = DnsQuery {
        name: "a.example.com".into(),
        qtype: 1,
        status: 0,
        results: "192.0.2.1;".into(),
    }
    .to_bytes();
    for len in 0..dns.len() {
        let _ = DnsQuery::parse(&dns[..len]);
    }
    let _ = DNS_QUERY_COMPLETED;
}

#[test]
fn dns_queries_read_back_with_their_addresses() {
    let q = DnsQuery {
        name: "cdn.example.com".into(),
        qtype: 1,
        status: 0,
        results: "type: 5 edge.example.net;192.0.2.50;::ffff:192.0.2.51;2001:db8::50;".into(),
    };
    let back = DnsQuery::parse(&q.to_bytes()).unwrap();
    assert_eq!(back, q);
    let addrs: Vec<String> = back.addresses().iter().map(|a| a.to_string()).collect();
    assert_eq!(addrs, ["192.0.2.50", "192.0.2.51", "2001:db8::50"]);
    assert!(DnsQuery::parse(&[0x61, 0x00, 0x62]).is_err(), "no NUL");
}
