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

// ---- INT-09: every pcap fixture through the pcap sensor's replay and the daemon pipeline ----
//
// Covers FUN-E02 / E03 / E05 and FUN-M05 on real captures: the sensor's decoder and flow tracker
// (`scribe_sensor_pcap::flows::replay`), then enrichment, QUIC holding, the URL module (query
// "full") and the policy, exactly as `scribed` runs them.

use std::collections::BTreeMap;
use std::net::SocketAddr;

use scribe_core::{FlowKind, Mode, Protocol, Security};
use scribe_daemon::modules::ModuleHost;
use scribe_daemon::pipeline::Pipeline;
use scribe_module_api::{ConfigDoc, Module};
use scribe_policy::{Policy, PolicyConfig};
use scribe_sensor_pcap::flows::{replay, TrackerOptions};
use scribe_storage_api::StoredEvent;
use scribe_test_support::{fixtures, RecordingEmitter};

#[derive(Debug, PartialEq)]
struct Seen {
    proto: &'static str,
    dst: SocketAddr,
    hostname: Option<String>,
    security: &'static str,
    url: Option<String>,
    ech: bool,
    kind: &'static str,
}

fn pipeline() -> Pipeline {
    let clock: Arc<dyn scribe_core::Clock> = Arc::new(FakeClock::default());
    let modules: Vec<Box<dyn Module>> = vec![Box::new(scribe_module_url::UrlModule::default())];
    let mut host = ModuleHost::new(
        modules,
        &ConfigDoc::new("[modules.url]\nquery = \"full\"\n"),
    )
    .unwrap();
    for (_, started) in host.start(
        clock.clone(),
        |_| Arc::new(RecordingEmitter::default()),
        BTreeMap::new(),
    ) {
        started.unwrap();
    }
    let policy = Policy::new(
        PolicyConfig {
            mode: Mode::Learn,
            ..Default::default()
        },
        clock.clone(),
    );
    Pipeline::new(
        clock.clone(),
        "default",
        Enricher::new(clock, 1_000),
        host,
        policy,
    )
}

fn seen(e: &scribe_core::FlowEvent) -> Seen {
    Seen {
        proto: match e.proto {
            Protocol::Tcp => "tcp",
            Protocol::Udp => "udp",
            Protocol::Quic => "quic",
        },
        dst: SocketAddr::new(e.dst_ip, e.dst_port),
        hostname: e.hostname.clone(),
        security: match e.security {
            Security::Tls => "tls",
            Security::Quic => "quic",
            Security::Plaintext => "plaintext",
            Security::Unknown => "unknown",
        },
        url: e.notes.get_str("url").map(str::to_owned),
        ech: e.ech,
        kind: match e.kind {
            FlowKind::NewFlow => "new_flow",
            FlowKind::Payload => "payload",
            FlowKind::Close => "close",
            FlowKind::DnsResponse => "dns_response",
        },
    }
}

#[test]
fn pcap_to_enriched_flows() {
    let all = fixtures::all();
    assert!(all.len() >= 16);
    for fixture in &all {
        let observations = replay(&fixture.pcap(), TrackerOptions::default())
            .unwrap_or_else(|e| panic!("{}: {e}", fixture.name));
        let mut p = pipeline();
        let mut flows = Vec::new();
        let mut keep = |w: scribe_daemon::pipeline::Writes| {
            for e in w.events {
                if let StoredEvent::Flow(f) = e {
                    flows.push(seen(&f));
                }
            }
        };
        for obs in observations {
            keep(p.process(obs));
        }
        keep(p.flush());
        let expected: Vec<Seen> = fixture
            .expected
            .iter()
            .map(|f| Seen {
                proto: f.proto,
                dst: f.dst,
                hostname: f.hostname.map(str::to_owned),
                security: f.security,
                url: f.url.map(str::to_owned),
                ech: f.ech,
                kind: f.kind,
            })
            .collect();
        assert_eq!(flows, expected, "fixture {}", fixture.name);
    }
}
