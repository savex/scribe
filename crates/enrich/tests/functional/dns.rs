//! DNS responses and the IP → name cache.

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::sync::Arc;
use std::time::Duration;

use scribe_enrich::dns::*;
use scribe_test_support::packets::dns::{query, response, Answer as A, TYPE_A, TYPE_AAAA};
use scribe_test_support::FakeClock;

fn cache(clock: &FakeClock) -> DnsCache {
    DnsCache::new(Arc::new(clock.clone()), 1_000)
}

fn ip(s: &str) -> IpAddr {
    s.parse().unwrap()
}

#[test]
fn a_and_aaaa_answers_map_to_the_name() {
    let r = parse_response(&response(
        7,
        "API.example.com",
        TYPE_A,
        &[A::A("api.example.com", Ipv4Addr::new(192, 0, 2, 10))],
        300,
    ))
    .unwrap();
    assert_eq!((r.id, r.question.as_str()), (7, "api.example.com"));
    let clock = FakeClock::default();
    let mut c = cache(&clock);
    assert_eq!(c.observe(&r), 1);
    assert_eq!(c.lookup(&ip("192.0.2.10")), Some("api.example.com"));

    let v6 = parse_response(&response(
        8,
        "v6.example.com",
        TYPE_AAAA,
        &[A::Aaaa(
            "v6.example.com",
            "2001:db8::50".parse::<Ipv6Addr>().unwrap(),
        )],
        60,
    ))
    .unwrap();
    c.observe(&v6);
    assert_eq!(c.lookup(&ip("2001:db8::50")), Some("v6.example.com"));
}

#[test]
fn cname_chains_map_back_to_the_queried_name_with_the_shortest_ttl() {
    let r = parse_response(&response(
        9,
        "cdn.example.com",
        TYPE_A,
        &[
            A::Cname("cdn.example.com", "edge.example.net"),
            A::Cname("edge.example.net", "pop1.example.net"),
            A::A("pop1.example.net", Ipv4Addr::new(192, 0, 2, 50)),
            A::A("unrelated.example.net", Ipv4Addr::new(192, 0, 2, 99)),
        ],
        120,
    ))
    .unwrap();
    let clock = FakeClock::default();
    let mut c = cache(&clock);
    assert_eq!(c.observe(&r), 1, "only answers on the chain");
    assert_eq!(c.lookup(&ip("192.0.2.50")), Some("cdn.example.com"));
    assert_eq!(c.lookup(&ip("192.0.2.99")), None);
    clock.advance(Duration::from_secs(119));
    assert!(c.lookup(&ip("192.0.2.50")).is_some());
    clock.advance(Duration::from_secs(1));
    assert_eq!(c.lookup(&ip("192.0.2.50")), None, "expired after the TTL");
    c.purge_expired();
    assert!(c.is_empty());
}

#[test]
fn compressed_names_are_followed() {
    // Hand-built: question api.example.com, answer owner is a pointer to it (0xc00c).
    let mut msg = vec![0, 1, 0x81, 0x80, 0, 1, 0, 1, 0, 0, 0, 0];
    for label in ["api", "example", "com"] {
        msg.push(label.len() as u8);
        msg.extend(label.as_bytes());
    }
    msg.extend([0, 0, 1, 0, 1]);
    msg.extend([0xc0, 0x0c, 0, 1, 0, 1, 0, 0, 0, 60, 0, 4, 192, 0, 2, 10]);
    let r = parse_response(&msg).unwrap();
    assert_eq!(r.answers[0].name, "api.example.com");
    assert_eq!(r.answers[0].record, Record::A(Ipv4Addr::new(192, 0, 2, 10)));
}

#[test]
fn queries_failures_and_garbage_are_rejected() {
    assert_eq!(
        parse_response(&query(1, "a.example.com", TYPE_A)),
        Err(DnsError::NotResponse)
    );
    let mut nx = response(2, "missing.example.com", TYPE_A, &[], 60);
    nx[3] |= 3;
    assert_eq!(parse_response(&nx), Err(DnsError::Failed(3)));
    // A pointer to itself: loop.
    let mut lp = vec![0, 1, 0x81, 0x80, 0, 1, 0, 0, 0, 0, 0, 0];
    lp.extend([0xc0, 0x0c, 0, 1, 0, 1]);
    assert_eq!(parse_response(&lp), Err(DnsError::Malformed));
    let full = response(
        3,
        "cut.example.com",
        TYPE_A,
        &[A::A("cut.example.com", Ipv4Addr::new(192, 0, 2, 1))],
        60,
    );
    for n in 0..full.len() {
        assert!(parse_response(&full[..n]).is_err(), "prefix {n}");
    }
}

#[test]
fn the_cache_is_bounded_and_caps_ttls() {
    let clock = FakeClock::default();
    let mut c = DnsCache::new(Arc::new(clock.clone()), 2);
    c.insert(ip("192.0.2.1"), "a.example.com", Duration::from_secs(10));
    c.insert(ip("192.0.2.2"), "b.example.com", Duration::from_secs(20));
    c.insert(ip("192.0.2.3"), "c.example.com", Duration::from_secs(30));
    assert_eq!(c.len(), 2);
    assert_eq!(
        c.lookup(&ip("192.0.2.1")),
        None,
        "the entry expiring first went"
    );
    c.insert(
        ip("192.0.2.4"),
        "d.example.com",
        Duration::from_secs(7 * 86_400),
    );
    clock.advance(MAX_TTL);
    assert_eq!(c.lookup(&ip("192.0.2.4")), None, "TTLs are capped at a day");
}
