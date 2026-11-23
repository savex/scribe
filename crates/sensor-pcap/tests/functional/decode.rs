//! Decoding: every link type, VLAN tags, fragments, IPv6 extension headers, hostile input.

use std::net::SocketAddr;
use std::time::UNIX_EPOCH;

use proptest::prelude::*;
use scribe_sensor_pcap::decode::*;
use scribe_test_support::packets::{tcp_frame, udp_frame};

fn addr(s: &str) -> SocketAddr {
    s.parse().unwrap()
}

/// An Ethernet frame carrying a TCP segment with a payload.
fn eth_tcp(src: &str, dst: &str) -> Vec<u8> {
    tcp_frame(
        addr(src),
        addr(dst),
        1000,
        0,
        TCP_ACK | 0x08,
        b"hello",
        true,
    )
}

fn check_tcp(p: &Packet<'_>, src: &str, dst: &str) {
    assert_eq!((p.src, p.dst), (addr(src), addr(dst)));
    assert_eq!(
        p.transport,
        Transport::Tcp {
            flags: TCP_ACK | 0x08,
            seq: 1000
        }
    );
    assert_eq!(p.payload, b"hello");
}

#[test]
fn ethernet_ipv4_and_ipv6() {
    let f = eth_tcp("10.0.0.2:50000", "192.0.2.10:443");
    check_tcp(
        &decode(LINKTYPE_ETHERNET, &f, UNIX_EPOCH).unwrap(),
        "10.0.0.2:50000",
        "192.0.2.10:443",
    );
    let f6 = eth_tcp("[2001:db8::2]:50000", "[2001:db8::10]:443");
    check_tcp(
        &decode(LINKTYPE_ETHERNET, &f6, UNIX_EPOCH).unwrap(),
        "[2001:db8::2]:50000",
        "[2001:db8::10]:443",
    );
    let u = udp_frame(addr("10.0.0.2:5353"), addr("192.0.2.53:53"), b"query", true);
    let p = decode(LINKTYPE_ETHERNET, &u, UNIX_EPOCH).unwrap();
    assert_eq!((p.transport, p.payload), (Transport::Udp, &b"query"[..]));
}

#[test]
fn every_link_type_decodes_the_same_packet() {
    let eth = eth_tcp("10.0.0.2:50000", "192.0.2.10:443");
    let ip = &eth[14..];
    let with = |prefix: &[u8]| [prefix, ip].concat();
    let cases: Vec<(i32, Vec<u8>)> = vec![
        (LINKTYPE_NULL, with(&2u32.to_le_bytes())),
        (LINKTYPE_NULL, with(&2u32.to_be_bytes())),
        (LINKTYPE_LOOP, with(&2u32.to_be_bytes())),
        (LINKTYPE_RAW, ip.to_vec()),
        (LINKTYPE_RAW_DLT, ip.to_vec()),
        (LINKTYPE_IPV4, ip.to_vec()),
        (
            LINKTYPE_LINUX_SLL,
            with(&[0, 4, 0, 1, 0, 6, 2, 0, 0, 0, 0, 0, 0, 2, 0x08, 0x00]),
        ),
        (
            LINKTYPE_LINUX_SLL2,
            with(&[
                0x08, 0x00, 0, 0, 0, 0, 0, 1, 0, 1, 4, 6, 2, 0, 0, 0, 0, 0, 0, 2,
            ]),
        ),
        (
            LINKTYPE_ETHERNET,
            [&eth[..12], &[0x81, 0x00, 0x00, 0x05], &eth[12..]].concat(),
        ),
        (
            LINKTYPE_ETHERNET,
            [
                &eth[..12],
                &[0x88, 0xa8, 0, 1, 0x81, 0x00, 0, 5],
                &eth[12..],
            ]
            .concat(),
        ),
    ];
    for (linktype, frame) in cases {
        let p =
            decode(linktype, &frame, UNIX_EPOCH).unwrap_or_else(|| panic!("linktype {linktype}"));
        check_tcp(&p, "10.0.0.2:50000", "192.0.2.10:443");
        assert!(supported(linktype));
    }
    let v6 = eth_tcp("[2001:db8::2]:50000", "[2001:db8::10]:443");
    for family in [10u32, 24, 28, 30] {
        let frame = [&family.to_le_bytes()[..], &v6[14..]].concat();
        assert!(
            decode(LINKTYPE_NULL, &frame, UNIX_EPOCH).is_some(),
            "AF_INET6 = {family}"
        );
    }
    assert!(!supported(105), "802.11 is not decoded");
}

#[test]
fn ipv4_fragments_are_left_out() {
    let mut f = eth_tcp("10.0.0.2:50000", "192.0.2.10:443");
    f[14 + 6] = 0x20; // more fragments
    assert!(decode(LINKTYPE_ETHERNET, &f, UNIX_EPOCH).is_none());
    let mut later = eth_tcp("10.0.0.2:50000", "192.0.2.10:443");
    later[14 + 7] = 0x10; // offset 16
    assert!(decode(LINKTYPE_ETHERNET, &later, UNIX_EPOCH).is_none());
    let mut dont_fragment = eth_tcp("10.0.0.2:50000", "192.0.2.10:443");
    dont_fragment[14 + 6] = 0x40;
    assert!(decode(LINKTYPE_ETHERNET, &dont_fragment, UNIX_EPOCH).is_some());
}

/// Insert an IPv6 extension header (8 bytes) of type `kind` after the fixed header.
fn with_ext(frame: &[u8], kind: u8, ext: [u8; 8]) -> Vec<u8> {
    let mut ip = frame[14..].to_vec();
    let next = ip[6];
    ip[6] = kind;
    let len = u16::from_be_bytes([ip[4], ip[5]]) + 8;
    ip[4..6].copy_from_slice(&len.to_be_bytes());
    let mut ext = ext;
    ext[0] = next;
    [&frame[..14], &ip[..40], &ext[..], &ip[40..]].concat()
}

#[test]
fn ipv6_extension_headers_are_skipped_and_fragments_left_out() {
    let f = eth_tcp("[2001:db8::2]:50000", "[2001:db8::10]:443");
    let hop = with_ext(&f, 0, [0, 0, 1, 4, 0, 0, 0, 0]);
    check_tcp(
        &decode(LINKTYPE_ETHERNET, &hop, UNIX_EPOCH).unwrap(),
        "[2001:db8::2]:50000",
        "[2001:db8::10]:443",
    );
    let atomic = with_ext(&f, 44, [0, 0, 0, 0, 0, 0, 0, 7]);
    assert!(
        decode(LINKTYPE_ETHERNET, &atomic, UNIX_EPOCH).is_some(),
        "atomic fragment"
    );
    let first_of_many = with_ext(&f, 44, [0, 0, 0, 1, 0, 0, 0, 7]);
    assert!(decode(LINKTYPE_ETHERNET, &first_of_many, UNIX_EPOCH).is_none());
}

#[test]
fn the_malformed_fixture_decodes_to_nothing() {
    let fixture = scribe_test_support::fixtures::all()
        .into_iter()
        .find(|f| f.name == "malformed")
        .unwrap();
    for frame in &fixture.frames {
        assert!(decode(LINKTYPE_ETHERNET, frame, UNIX_EPOCH).is_none());
    }
}

proptest! {
    #[test]
    fn random_frames_never_panic(linktype in prop::sample::select(vec![0, 1, 12, 14, 101, 108, 113, 228, 229, 276, 9999]),
                                 bytes in prop::collection::vec(any::<u8>(), 0..200)) {
        let _ = decode(linktype, &bytes, UNIX_EPOCH);
    }

    #[test]
    fn mutated_frames_never_panic(at in 0usize..60, byte in any::<u8>(), cut in 0usize..70) {
        let mut f = eth_tcp("[2001:db8::2]:50000", "[2001:db8::10]:443");
        if at < f.len() { f[at] = byte; }
        f.truncate(cut.max(1));
        let _ = decode(LINKTYPE_ETHERNET, &f, UNIX_EPOCH);
    }
}
