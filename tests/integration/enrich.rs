//! DNS answers → enrichment → a later flow without SNI (fixtures `dns_cname_then_tls`,
//! `dns_aaaa_then_tls`), built from the same packet builders as the fixtures.

use std::net::{Ipv4Addr, Ipv6Addr};
use std::sync::Arc;

use scribe_enrich::Enricher;
use scribe_test_support::packets::dns::{response, Answer, TYPE_A, TYPE_AAAA};
use scribe_test_support::packets::tls::{client_hello, ClientHelloOptions};
use scribe_test_support::{flow, FakeClock};

fn no_sni_hello() -> Vec<u8> {
    client_hello(&ClientHelloOptions {
        tls13: true,
        ..Default::default()
    })
}

#[test]
fn dns_answer_names_a_later_flow() {
    let mut e = Enricher::new(Arc::new(FakeClock::default()), 1_000);
    let cname = response(
        1,
        "cdn.example.com",
        TYPE_A,
        &[
            Answer::Cname("cdn.example.com", "edge.example.net"),
            Answer::A("edge.example.net", Ipv4Addr::new(192, 0, 2, 50)),
        ],
        300,
    );
    assert_eq!(e.observe_dns_response(&cname), 1);
    let aaaa = response(
        2,
        "v6.example.com",
        TYPE_AAAA,
        &[Answer::Aaaa(
            "v6.example.com",
            "2001:db8::50".parse::<Ipv6Addr>().unwrap(),
        )],
        300,
    );
    assert_eq!(e.observe_dns_response(&aaaa), 1);

    let mut v4 = flow("192.0.2.50:443").payload(&no_sni_hello()).observe();
    e.enrich(&mut v4);
    assert_eq!(v4.event.hostname.as_deref(), Some("cdn.example.com"));
    let mut v6 = flow("[2001:db8::50]:443")
        .payload(&no_sni_hello())
        .observe();
    e.enrich(&mut v6);
    assert_eq!(v6.event.hostname.as_deref(), Some("v6.example.com"));
}
