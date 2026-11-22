//! The enricher: security, ECH flag and host-name order.

use std::sync::Arc;
use std::time::Duration;

use scribe_core::Security;
use scribe_enrich::Enricher;
use scribe_test_support::packets::tls::{client_hello, client_hello_sni, ClientHelloOptions};
use scribe_test_support::{flow, FakeClock};

fn enricher() -> Enricher {
    Enricher::new(Arc::new(FakeClock::default()), 100)
}

#[test]
fn sni_names_a_tls_flow() {
    let e = enricher();
    let mut obs = flow("192.0.2.10:443")
        .payload(&client_hello_sni("api.example.com"))
        .observe();
    obs.event.security = Security::Unknown;
    e.enrich(&mut obs);
    assert_eq!(obs.event.security, Security::Tls);
    assert_eq!(obs.event.hostname.as_deref(), Some("api.example.com"));
    assert!(!obs.event.ech && !obs.event.unresolved());
}

#[test]
fn ech_sets_the_flag_and_the_flow_counts_as_unresolved() {
    let e = enricher();
    let hello = client_hello(&ClientHelloOptions {
        sni: Some("public.example.com".into()),
        tls13: true,
        ech: true,
        ..Default::default()
    });
    let mut obs = flow("192.0.2.12:443").payload(&hello).observe();
    e.enrich(&mut obs);
    assert_eq!(obs.event.hostname.as_deref(), Some("public.example.com"));
    assert!(obs.event.ech && obs.event.unresolved());
}

#[test]
fn host_header_names_a_plaintext_flow() {
    let e = enricher();
    let mut obs = flow("192.0.2.20:80")
        .http_get("http://plain.example.com/a")
        .observe();
    obs.event.hostname = None;
    e.enrich(&mut obs);
    assert_eq!(obs.event.security, Security::Plaintext);
    assert_eq!(obs.event.hostname.as_deref(), Some("plain.example.com"));
}

#[test]
fn sni_beats_the_dns_cache_and_dns_fills_the_gap() {
    let mut e = enricher();
    e.observe_dns_answer(
        "old.example.com",
        "192.0.2.10".parse().unwrap(),
        Duration::from_secs(60),
    );
    let mut with_sni = flow("192.0.2.10:443")
        .payload(&client_hello_sni("api.example.com"))
        .observe();
    e.enrich(&mut with_sni);
    assert_eq!(with_sni.event.hostname.as_deref(), Some("api.example.com"));

    let no_sni = client_hello(&ClientHelloOptions {
        tls13: true,
        ..Default::default()
    });
    let mut from_dns = flow("192.0.2.10:443").payload(&no_sni).observe();
    e.enrich(&mut from_dns);
    assert_eq!(from_dns.event.hostname.as_deref(), Some("old.example.com"));
}

#[test]
fn a_sensor_name_is_kept_when_nothing_better_is_seen() {
    let e = enricher();
    let mut obs = flow("192.0.2.10:443")
        .host("api.example.com")
        .tls()
        .observe();
    e.enrich(&mut obs);
    assert_eq!(obs.event.hostname.as_deref(), Some("api.example.com"));
}

#[test]
fn nameless_flows_stay_unresolved() {
    let e = enricher();
    let mut obs = flow("198.51.100.7:8443")
        .payload(b"\x00\x01binary")
        .observe();
    e.enrich(&mut obs);
    assert_eq!(obs.event.security, Security::Plaintext);
    assert_eq!(obs.event.hostname, None);
    assert!(obs.event.unresolved());
}

#[test]
fn a_quic_initial_names_a_udp_flow() {
    use scribe_core::Protocol;
    use scribe_test_support::packets::quic::{hex, RFC9001_CLIENT_INITIAL};
    let e = enricher();
    let mut obs = flow("192.0.2.40:443")
        .udp()
        .payload(&hex(RFC9001_CLIENT_INITIAL))
        .observe();
    e.enrich(&mut obs);
    assert_eq!(obs.event.proto, Protocol::Quic);
    assert_eq!(obs.event.security, Security::Quic);
    assert_eq!(obs.event.hostname.as_deref(), Some("example.com"));

    let mut other = flow("192.0.2.41:443").udp().payload(b"\x40short").observe();
    e.enrich(&mut other);
    assert_eq!(other.event.proto, Protocol::Udp);
    assert_eq!(other.event.hostname, None);
}

#[test]
fn udp_is_classified_from_its_first_datagram() {
    use scribe_test_support::packets::dns;
    use scribe_test_support::packets::quic::{client_initials, RFC_DCID};
    let e = enricher();
    let mut query = flow("192.0.2.53:53")
        .udp()
        .payload(&dns::query(1, "a.example.com", dns::TYPE_A))
        .observe();
    query.event.security = Security::Unknown;
    e.enrich(&mut query);
    assert_eq!(query.event.security, Security::Plaintext);

    // The first of several Initials: QUIC, name still unknown until the pipeline joins them.
    let hello = client_hello(&ClientHelloOptions {
        sni: Some("big.example.com".into()),
        tls13: true,
        ..Default::default()
    });
    let first = &client_initials(&RFC_DCID, &hello[5..], 60)[0];
    let mut quic = flow("192.0.2.40:443").udp().payload(first).observe();
    quic.event.security = Security::Unknown;
    e.enrich(&mut quic);
    assert_eq!(quic.event.security, Security::Quic);
    assert_eq!(quic.event.hostname, None);
}
