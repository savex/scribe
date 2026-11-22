//! QUIC Initial decryption: RFC 9001 / RFC 9369 sample packets, a second implementation in
//! test-support, reassembly across packets and hostile input.

use proptest::prelude::*;
use scribe_enrich::quic::{
    client_hello_from_initial, crypto_frames, decrypt_initial, InitialReassembler, Progress,
    QuicError, VERSION_1, VERSION_2,
};
use scribe_test_support::packets::quic::{
    client_initial, client_initials, crypto_frame, hex, RFC9001_CLIENT_INITIAL,
    RFC9369_CLIENT_INITIAL, RFC_CRYPTO_FRAME, RFC_DCID,
};
use scribe_test_support::packets::tls::{client_hello, ClientHelloOptions};

#[test]
fn quic_initial_rfc9001_vector() {
    let packet = hex(RFC9001_CLIENT_INITIAL);
    assert_eq!(packet.len(), 1200);
    let initial = decrypt_initial(&packet).unwrap();
    assert_eq!(initial.version, VERSION_1);
    assert_eq!(initial.dcid, RFC_DCID);
    assert_eq!(initial.packet_number, 2);
    assert_eq!(initial.payload.len(), 1162);
    let frame = hex(RFC_CRYPTO_FRAME);
    assert_eq!(&initial.payload[..frame.len()], frame.as_slice());
    assert!(initial.payload[frame.len()..].iter().all(|&b| b == 0));

    let hello = client_hello_from_initial(&packet).unwrap();
    assert_eq!(hello.sni.as_deref(), Some("example.com"));
    assert!(hello.tls13);
    assert!(!hello.ech);
}

#[test]
fn quic_v2_initial_rfc9369_vector() {
    let packet = hex(RFC9369_CLIENT_INITIAL);
    let initial = decrypt_initial(&packet).unwrap();
    assert_eq!(initial.version, VERSION_2);
    assert_eq!(initial.packet_number, 2);
    let hello = client_hello_from_initial(&packet).unwrap();
    assert_eq!(hello.sni.as_deref(), Some("example.com"));
}

#[test]
fn the_test_builder_reproduces_both_rfc_packets() {
    let frame = hex(RFC_CRYPTO_FRAME);
    assert_eq!(
        client_initial(VERSION_1, &RFC_DCID, 2, &frame, 1162),
        hex(RFC9001_CLIENT_INITIAL)
    );
    assert_eq!(
        client_initial(VERSION_2, &RFC_DCID, 2, &frame, 1162),
        hex(RFC9369_CLIENT_INITIAL)
    );
}

fn handshake(sni: &str) -> Vec<u8> {
    // Strip the 5-byte TLS record header: QUIC carries the bare handshake message.
    client_hello(&ClientHelloOptions {
        sni: Some(sni.into()),
        tls13: true,
        alpn: vec!["h3".into()],
        ..Default::default()
    })[5..]
        .to_vec()
}

#[test]
fn a_hello_split_over_initials_is_joined_in_any_order() {
    let dcid = [0x0a; 8];
    let packets = client_initials(&dcid, &handshake("split.example.com"), 60);
    assert!(packets.len() >= 3);
    let mut r = InitialReassembler::default();
    let (last, rest) = packets.split_first().unwrap();
    for p in rest.iter().rev() {
        assert_eq!(r.push(p), Progress::NeedMore);
    }
    let Progress::Hello(hello) = r.push(last) else {
        panic!("no hello")
    };
    assert_eq!(hello.sni.as_deref(), Some("split.example.com"));
    assert_eq!(hello.alpn, ["h3"]);
    assert_eq!(r.push(last), Progress::Failed, "one hello per flow");
}

#[test]
fn initials_for_another_connection_id_are_ignored() {
    let hello = handshake("a.example.com");
    let a = client_initials(&[1; 8], &hello, 60);
    let b = client_initials(&[2; 8], &hello, 60);
    let mut r = InitialReassembler::default();
    assert_eq!(r.push(&a[0]), Progress::NeedMore);
    for p in &b {
        assert_eq!(r.push(p), Progress::NeedMore);
    }
    for p in &a[1..a.len() - 1] {
        assert_eq!(r.push(p), Progress::NeedMore);
    }
    assert!(matches!(r.push(a.last().unwrap()), Progress::Hello(_)));
}

#[test]
fn non_tls_crypto_data_fails_the_flow() {
    let frame = crypto_frame(0, b"\x02not a client hello");
    let packet = client_initial(VERSION_1, &[3; 8], 0, &frame, 1162);
    assert_eq!(
        InitialReassembler::default().push(&packet),
        Progress::Failed
    );
}

#[test]
fn other_packets_are_rejected_without_panicking() {
    let good = hex(RFC9001_CLIENT_INITIAL);
    let mut corrupted = good.clone();
    corrupted[600] ^= 1;
    assert_eq!(decrypt_initial(&corrupted), Err(QuicError::Decrypt));

    let mut short = good.clone();
    short[0] = 0x40; // short header
    assert_eq!(decrypt_initial(&short), Err(QuicError::NotInitial));
    let mut handshake = good.clone();
    handshake[0] = 0xe0; // long header, type Handshake
    assert_eq!(decrypt_initial(&handshake), Err(QuicError::NotInitial));
    let mut negotiation = good.clone();
    negotiation[1..5].fill(0);
    assert_eq!(decrypt_initial(&negotiation), Err(QuicError::NotInitial));
    let mut draft = good.clone();
    draft[1..5].copy_from_slice(&[0xff, 0, 0, 29]);
    assert_eq!(
        decrypt_initial(&draft),
        Err(QuicError::UnsupportedVersion(0xff00_001d))
    );
    assert_eq!(decrypt_initial(&good[..300]), Err(QuicError::Malformed));
    let mut long_cid = good.clone();
    long_cid[5] = 21;
    assert_eq!(decrypt_initial(&long_cid), Err(QuicError::Malformed));
    assert_eq!(decrypt_initial(&[]), Err(QuicError::NotInitial));
    assert_eq!(client_hello_from_initial(b"\xc0\x00\x00\x00\x01"), None);
}

#[test]
fn initial_frames_are_read_and_others_refused() {
    // PADDING, PING, ACK (1 range), ACK-ECN, CONNECTION_CLOSE, CRYPTO.
    let mut payload = vec![0x00, 0x01, 0x02, 0x05, 0x00, 0x01, 0x00, 0x01, 0x00];
    payload.extend([0x03, 0x05, 0x00, 0x00, 0x00, 0x01, 0x02, 0x03]);
    payload.extend([0x1c, 0x00, 0x06, 0x03, b'b', b'y', b'e']);
    payload.extend(crypto_frame(7, b"abc"));
    let frames = crypto_frames(&payload).unwrap();
    assert_eq!(frames, vec![(7, &b"abc"[..])]);
    assert_eq!(crypto_frames(&[0x08, 0x00]), Err(QuicError::Malformed)); // STREAM
    assert_eq!(
        crypto_frames(&[0x06, 0x00, 0x05, b'a']),
        Err(QuicError::Malformed)
    );
}

proptest! {
    #[test]
    fn random_datagrams_never_panic(bytes in proptest::collection::vec(any::<u8>(), 0..1300)) {
        let _ = decrypt_initial(&bytes);
        let _ = crypto_frames(&bytes);
        let _ = InitialReassembler::default().push(&bytes);
    }

    #[test]
    fn mutated_rfc_packets_never_panic(at in 0usize..1200, byte in any::<u8>(), cut in 0usize..1200) {
        let mut p = hex(RFC9001_CLIENT_INITIAL);
        p[at] = byte;
        p.truncate(cut.max(1));
        let _ = client_hello_from_initial(&p);
    }
}

/// The QUIC fixtures: every frame is Ethernet + IPv4 (20 bytes) + UDP, so the datagram starts at 42.
#[test]
fn quic_fixtures_name_their_flows() {
    use scribe_test_support::fixtures;
    for name in ["quic_initial", "quic_split_hello"] {
        let fixture = fixtures::all()
            .into_iter()
            .find(|f| f.name == name)
            .unwrap();
        let mut r = InitialReassembler::default();
        let mut result = Progress::NeedMore;
        for frame in &fixture.frames {
            assert_eq!(
                result,
                Progress::NeedMore,
                "{name}: hello before the last datagram"
            );
            result = r.push(&frame[42..]);
        }
        let Progress::Hello(hello) = result else {
            panic!("{name}: {result:?}")
        };
        assert_eq!(hello.sni.as_deref(), fixture.expected[0].hostname, "{name}");
        assert_eq!(hello.alpn, ["h3"]);
    }
    let split = fixtures::all()
        .into_iter()
        .find(|f| f.name == "quic_split_hello")
        .unwrap();
    assert_eq!(split.frames.len(), 3);
}
