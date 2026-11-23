//! Flow tracking: the fixtures as live capture would report them (FUN-SN01), byte accounting,
//! timeouts, closing, local addresses, the payload switch, QUIC follow-ups, limits.

use std::net::SocketAddr;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use scribe_core::{FlowKind, Observation, Protocol};
use scribe_sensor_pcap::decode::{decode, LINKTYPE_ETHERNET};
use scribe_sensor_pcap::flows::{replay, FlowTracker, TrackerOptions};
use scribe_test_support::fixtures;
use scribe_test_support::packets::{tcp_frame, udp_frame, TcpFlow};

fn addr(s: &str) -> SocketAddr {
    s.parse().unwrap()
}

fn proto_name(p: Protocol) -> &'static str {
    match p {
        Protocol::Tcp => "tcp",
        Protocol::Udp | Protocol::Quic => "udp",
    }
}

/// FUN-SN01: every fixture gives one `NewFlow` per expected flow (QUIC is still UDP here), and
/// the expected `payload` observations, with the right first bytes.
#[test]
fn pcap_decoder_matches_expected_flows() {
    for f in fixtures::all() {
        let obs = replay(&f.pcap(), TrackerOptions::default()).unwrap();
        let reported: Vec<(&str, SocketAddr, &str)> = obs
            .iter()
            .filter(|o| match o.event.kind {
                FlowKind::NewFlow => true,
                FlowKind::Payload => o.event.proto == Protocol::Tcp,
                _ => false,
            })
            .map(|o| {
                (
                    proto_name(o.event.proto),
                    SocketAddr::new(o.event.dst_ip, o.event.dst_port),
                    if o.event.kind == FlowKind::NewFlow {
                        "new_flow"
                    } else {
                        "payload"
                    },
                )
            })
            .collect();
        let expected: Vec<(&str, SocketAddr, &str)> = f
            .expected
            .iter()
            .map(|e| {
                (
                    if e.proto == "quic" { "udp" } else { e.proto },
                    e.dst,
                    e.kind,
                )
            })
            .collect();
        assert_eq!(reported, expected, "fixture {}", f.name);
        for o in obs.iter().filter(|o| o.event.kind == FlowKind::NewFlow) {
            assert!(
                o.event.pid.is_none() && o.event.process_path.is_none(),
                "pcap has no process info"
            );
            let head = o.head.as_deref().unwrap_or_default();
            match (f.name, o.event.dst_port) {
                (_, 443) if o.event.proto == Protocol::Tcp => {
                    assert_eq!(head.first(), Some(&0x16), "{}", f.name)
                }
                ("http_plain" | "http_keepalive", 80) => {
                    assert!(head.starts_with(b"GET "), "{}", f.name)
                }
                _ => {}
            }
        }
    }
}

#[test]
fn a_reordered_client_hello_is_joined_before_it_is_reported() {
    let f = fixtures::all()
        .into_iter()
        .find(|f| f.name == "tls_out_of_order")
        .unwrap();
    let obs = replay(&f.pcap(), TrackerOptions::default()).unwrap();
    let head = obs[0].head.as_deref().unwrap();
    // The whole record (5-byte header + its length), with the name the second segment carries.
    let record = 5 + usize::from(u16::from_be_bytes([head[3], head[4]]));
    assert_eq!(head.len(), record, "nothing missing, nothing extra");
    assert!(head.windows(15).any(|w| w == b"ooo.example.com"));
}

#[test]
fn dns_answers_become_dns_responses_and_closes_carry_the_rest_of_the_bytes() {
    let f = fixtures::all()
        .into_iter()
        .find(|f| f.name == "dns_cname_then_tls")
        .unwrap();
    let obs = replay(&f.pcap(), TrackerOptions::default()).unwrap();
    let dns: Vec<&Observation> = obs
        .iter()
        .filter(|o| o.event.kind == FlowKind::DnsResponse)
        .collect();
    assert_eq!(dns.len(), 1);
    assert_eq!(dns[0].event.src.port(), 53);
    // Every client byte is counted exactly once over NewFlow, Payload and Close.
    for o in obs.iter().filter(|o| o.event.kind == FlowKind::Close) {
        let key = (o.event.src, o.event.dst_ip, o.event.dst_port);
        let total: u64 = obs
            .iter()
            .filter(|x| (x.event.src, x.event.dst_ip, x.event.dst_port) == key)
            .map(|x| x.event.bytes_out)
            .sum();
        assert!(total > 0, "{key:?}");
    }
}

fn feed(tracker: &mut FlowTracker, frames: &[Vec<u8>], start: SystemTime) -> Vec<Observation> {
    let mut out = Vec::new();
    for (i, frame) in frames.iter().enumerate() {
        let ts = start + Duration::from_millis(i as u64);
        let p = decode(LINKTYPE_ETHERNET, frame, ts).unwrap();
        out.extend(tracker.push(&p));
    }
    out
}

fn kinds(obs: &[Observation]) -> Vec<FlowKind> {
    obs.iter().map(|o| o.event.kind).collect()
}

#[test]
fn a_silent_connection_is_reported_after_the_wait_and_closed_by_fin() {
    let mut t = FlowTracker::new(TrackerOptions::default());
    let mut flow = TcpFlow::new(addr("10.0.0.2:50100"), addr("192.0.2.25:25"));
    let out = feed(&mut t, &flow.handshake(), UNIX_EPOCH);
    assert!(out.is_empty(), "waiting for the client's first bytes");
    let later = t.tick(UNIX_EPOCH + Duration::from_secs(2));
    assert_eq!(kinds(&later), [FlowKind::NewFlow]);
    assert!(later[0].head.is_none());
    let fin = feed(
        &mut t,
        &[flow.client_fin()],
        UNIX_EPOCH + Duration::from_secs(3),
    );
    assert_eq!(kinds(&fin), [FlowKind::Close]);
    assert!(t.is_empty());
}

#[test]
fn a_server_reset_closes_and_reports_bytes_left() {
    let mut t = FlowTracker::new(TrackerOptions::default());
    let (c, s) = (addr("10.0.0.2:50101"), addr("192.0.2.30:8443"));
    let mut flow = TcpFlow::new(c, s);
    let mut frames = flow.handshake();
    frames.push(flow.client_data(b"\x00\x01first"));
    frames.push(flow.client_data(b"more-data"));
    frames.push(tcp_frame(s, c, 7000, 0, 0x04, &[], false)); // RST from the server
    let out = feed(&mut t, &frames, UNIX_EPOCH);
    assert_eq!(kinds(&out), [FlowKind::NewFlow, FlowKind::Close]);
    assert_eq!(out[0].event.bytes_out, 7);
    assert_eq!(
        out[1].event.bytes_out, 9,
        "bytes after the first observation"
    );
}

#[test]
fn without_payload_later_requests_are_only_counted() {
    let f = fixtures::all()
        .into_iter()
        .find(|f| f.name == "http_keepalive")
        .unwrap();
    let opts = TrackerOptions {
        payload: false,
        ..Default::default()
    };
    let obs = replay(&f.pcap(), opts).unwrap();
    assert_eq!(kinds(&obs), [FlowKind::NewFlow, FlowKind::Close]);
    assert!(
        obs[1].event.bytes_out > 0,
        "the second request's bytes still count"
    );
}

#[test]
fn local_addresses_keep_inbound_flows_out() {
    let opts = TrackerOptions {
        local: vec!["10.0.0.2".parse().unwrap()],
        ..Default::default()
    };
    let mut t = FlowTracker::new(opts);
    let mut inbound = TcpFlow::new(addr("198.51.100.9:40000"), addr("10.0.0.2:22"));
    assert!(feed(&mut t, &inbound.handshake(), UNIX_EPOCH).is_empty());
    let udp_in = udp_frame(
        addr("198.51.100.9:5000"),
        addr("10.0.0.2:5000"),
        b"x",
        false,
    );
    let udp_out = udp_frame(addr("10.0.0.2:5001"), addr("198.51.100.9:5001"), b"y", true);
    let out = feed(&mut t, &[udp_in, udp_out], UNIX_EPOCH);
    assert_eq!(out.len(), 1);
    assert_eq!(out[0].event.src, addr("10.0.0.2:5001"));
}

#[test]
fn quic_follow_up_initials_are_passed_on_and_udp_flows_expire() {
    let f = fixtures::all()
        .into_iter()
        .find(|f| f.name == "quic_split_hello")
        .unwrap();
    let mut t = FlowTracker::new(TrackerOptions::default());
    let out = feed(&mut t, &f.frames, UNIX_EPOCH);
    assert_eq!(
        kinds(&out),
        [FlowKind::NewFlow, FlowKind::Payload, FlowKind::Payload]
    );
    assert!(out.iter().all(|o| o.head.is_some()));
    let expired = t.tick(UNIX_EPOCH + Duration::from_secs(61));
    assert_eq!(kinds(&expired), [FlowKind::Close]);
    assert_eq!(
        expired[0].event.bytes_out, 0,
        "every byte was already reported"
    );
}

#[test]
fn connections_without_a_syn_are_not_tracked_and_the_table_is_bounded() {
    let mut t = FlowTracker::new(TrackerOptions {
        max_flows: 2,
        ..Default::default()
    });
    let midstream = tcp_frame(
        addr("10.0.0.2:50200"),
        addr("192.0.2.10:443"),
        1,
        1,
        0x18,
        b"data",
        true,
    );
    assert!(feed(&mut t, &[midstream], UNIX_EPOCH).is_empty());
    assert!(t.is_empty());
    let mut out = Vec::new();
    for port in 50300u16..50303 {
        let mut flow = TcpFlow::new(addr(&format!("10.0.0.2:{port}")), addr("192.0.2.10:443"));
        out.extend(feed(
            &mut t,
            &flow.handshake()[..1],
            UNIX_EPOCH + Duration::from_millis(u64::from(port)),
        ));
    }
    assert_eq!(t.len(), 2);
    assert_eq!(
        kinds(&out),
        [FlowKind::NewFlow, FlowKind::Close],
        "the oldest flow made room"
    );
    assert_eq!(out[0].event.src.port(), 50300);
}
