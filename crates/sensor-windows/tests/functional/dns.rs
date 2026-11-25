use std::net::IpAddr;
use std::sync::Arc;
use std::time::{Duration, SystemTime};

use scribe_core::FlowKind;
use scribe_enrich::Enricher;
use scribe_sensor_windows::dns::{observation, response, MAX_ANSWERS};
use scribe_sensor_windows::DnsQuery;
use scribe_test_support::{flow, FakeClock};

fn query(name: &str, status: u32, results: &str) -> DnsQuery {
    DnsQuery {
        name: name.into(),
        qtype: 1,
        status,
        results: results.into(),
    }
}

#[test]
fn answers_reach_the_dns_cache_under_the_queried_name() {
    let clock = Arc::new(FakeClock::at_unix(1_800_000_000));
    let mut enricher = Enricher::new(clock.clone(), 100);
    let q = query(
        "cdn.example.com",
        0,
        "type: 5 edge.example.net;192.0.2.50;2001:db8::50;",
    );
    let obs = observation(&q, SystemTime::UNIX_EPOCH).unwrap();
    assert_eq!(obs.event.kind, FlowKind::DnsResponse);
    assert_eq!(enricher.observe_dns_response(obs.head.as_ref().unwrap()), 2);
    for dst in ["192.0.2.50:443", "[2001:db8::50]:443"] {
        let mut f = flow(dst).observe();
        enricher.enrich(&mut f);
        assert_eq!(
            f.event.hostname.as_deref(),
            Some("cdn.example.com"),
            "{dst}"
        );
    }
    // ETW gives no TTL: answers last DNS_TTL (300 s).
    clock.advance(Duration::from_secs(301));
    let mut f = flow("192.0.2.50:443").observe();
    enricher.enrich(&mut f);
    assert_eq!(f.event.hostname, None);
}

#[test]
fn failed_or_empty_queries_and_odd_names_give_no_message() {
    assert!(
        response(&query("a.example.com", 9003, "")).is_none(),
        "NXDOMAIN"
    );
    assert!(response(&query("a.example.com", 0, "type: 5 b.example.net;")).is_none());
    assert!(response(&query("", 0, "192.0.2.1;")).is_none());
    assert!(response(&query(
        &format!("{}.example.com", "x".repeat(64)),
        0,
        "192.0.2.1;"
    ))
    .is_none());
    assert!(
        response(&query("bücher.example", 0, "192.0.2.1;")).is_none(),
        "not punycode"
    );
    assert!(
        response(&query("a.example.com.", 0, "192.0.2.1;")).is_some(),
        "trailing dot"
    );
}

#[test]
fn long_answers_are_capped_to_fit_the_head() {
    let many: String = (0..200).map(|i| format!("2001:db8::{i:x};")).collect();
    let obs = observation(&query("many.example.com", 0, &many), SystemTime::UNIX_EPOCH).unwrap();
    let msg = obs.head.unwrap();
    assert!(msg.len() <= scribe_core::HEAD_MAX);
    assert_eq!(u16::from_be_bytes([msg[6], msg[7]]) as usize, MAX_ANSWERS);
    let _: IpAddr = "2001:db8::1".parse().unwrap();
}
