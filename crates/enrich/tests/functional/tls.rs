//! Functional tests for `scribe_enrich::tls` (moved from `src/tls.rs`).

use scribe_core::Security;
use scribe_enrich::tls::*;

#[test]
fn detects_tls_handshake() {
    assert_eq!(
        detect_security(&[0x16, 0x03, 0x01, 0x02, 0x00]),
        Security::Tls
    );
}

#[test]
fn detects_plaintext_http() {
    assert_eq!(detect_security(b"GET / HTTP/1.1\r\n"), Security::Plaintext);
}

#[test]
fn empty_is_unknown() {
    assert_eq!(detect_security(&[]), Security::Unknown);
}

use scribe_test_support::packets::tls::{client_hello, client_hello_sni, ClientHelloOptions};

fn hello(sni: Option<&str>, tls13: bool, ech: bool) -> Vec<u8> {
    client_hello(&ClientHelloOptions {
        sni: sni.map(str::to_owned),
        tls13,
        ech,
        ..Default::default()
    })
}

#[test]
fn reads_sni_from_tls13_and_tls12() {
    let h = parse_client_hello(&client_hello_sni("api.example.com")).unwrap();
    assert_eq!(h.sni.as_deref(), Some("api.example.com"));
    assert!(h.tls13 && !h.ech);
    let h = parse_client_hello(&hello(Some("v6.example.com"), false, false)).unwrap();
    assert_eq!(h.sni.as_deref(), Some("v6.example.com"));
    assert!(!h.tls13);
}

#[test]
fn no_sni_and_ech() {
    let h = parse_client_hello(&hello(None, true, false)).unwrap();
    assert_eq!(h.sni, None);
    let h = parse_client_hello(&hello(Some("public.example.com"), true, true)).unwrap();
    assert_eq!(h.sni.as_deref(), Some("public.example.com"));
    assert!(h.ech, "ECH flag set; the name is only the outer one");
}

#[test]
fn names_are_normalised_and_checked() {
    let h = parse_client_hello(&client_hello_sni("API.Example.COM.")).unwrap();
    assert_eq!(h.sni.as_deref(), Some("api.example.com"));
    for bad in [
        "",
        "a..example.com",
        "white space.example.com",
        "x/y.example.com",
    ] {
        let h = parse_client_hello(&client_hello_sni(bad)).unwrap();
        assert_eq!(h.sni, None, "{bad:?}");
    }
}

#[test]
fn a_hello_split_over_two_records_is_reassembled() {
    let one = client_hello_sni("split.example.com");
    let handshake = &one[5..];
    let (a, b) = handshake.split_at(40);
    let mut two = vec![0x16, 0x03, 0x01];
    two.extend((a.len() as u16).to_be_bytes());
    two.extend(a);
    two.extend([0x16, 0x03, 0x01]);
    two.extend((b.len() as u16).to_be_bytes());
    two.extend(b);
    assert_eq!(parse_sni(&two).as_deref(), Some("split.example.com"));
}

#[test]
fn every_prefix_is_incomplete_never_a_panic() {
    let full = client_hello_sni("trunc.example.com");
    for n in 0..full.len() {
        match parse_client_hello(&full[..n]) {
            Err(HelloError::Incomplete) => {}
            other => panic!("prefix {n}: {other:?}"),
        }
    }
    assert!(parse_client_hello(&full).is_ok());
}

#[test]
fn other_bytes_are_not_a_client_hello() {
    assert_eq!(
        parse_client_hello(b"GET / HTTP/1.1\r\n"),
        Err(HelloError::NotClientHello)
    );
    let mut server_hello = client_hello_sni("x.example.com");
    server_hello[5] = 0x02;
    assert_eq!(
        parse_client_hello(&server_hello),
        Err(HelloError::NotClientHello)
    );
    let mut bad_len = client_hello_sni("x.example.com");
    let ext_at = bad_len.len() - 30;
    bad_len[ext_at] = 0xff;
    assert!(parse_client_hello(&bad_len).is_err() || parse_sni(&bad_len).is_none());
}

#[test]
fn reads_alpn() {
    let rec = client_hello(&ClientHelloOptions {
        sni: Some("alpn.example.com".into()),
        tls13: true,
        alpn: vec!["h2".into(), "http/1.1".into()],
        ..Default::default()
    });
    let h = parse_client_hello(&rec).unwrap();
    assert_eq!(h.alpn, ["h2", "http/1.1"]);
    assert_eq!(h.sni.as_deref(), Some("alpn.example.com"));
}
