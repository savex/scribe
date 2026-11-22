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

// ---- Every pcap fixture through enrichment and the URL module (FUN-E02/E03/E05, FUN-M05) ----
//
// A minimal stand-in for the phase 5 pipeline: Ethernet / IPv4 / IPv6 / TCP / UDP headers only,
// client = sender of a flow's first frame, TCP segments ordered by sequence number. A TLS
// ClientHello is joined across segments; plaintext segments are one observation each (the first
// `new_flow`, later ones `payload`); QUIC Initials go through one reassembler per flow; DNS
// responses feed the DNS cache.

use std::collections::BTreeMap;
use std::net::{IpAddr, SocketAddr};

use scribe_core::{FlowKind, Observation, Protocol, Security};
use scribe_enrich::{quic::Progress, InitialReassembler};
use scribe_module_api::{ConfigDoc, FlowContext, Module};
use scribe_module_url::UrlModule;
use scribe_test_support::fixtures;
use scribe_test_support::module_context;

struct Packet {
    tcp: bool,
    src: SocketAddr,
    dst: SocketAddr,
    seq: u32,
    payload: Vec<u8>,
}

fn decode(frame: &[u8]) -> Option<Packet> {
    let ip = frame.get(14..)?;
    let ethertype = u16::from_be_bytes([*frame.get(12)?, *frame.get(13)?]);
    let (proto, src, dst, rest) = match ethertype {
        0x0800 => {
            let ihl = usize::from(ip.first()? & 0x0f) * 4;
            let total = usize::from(u16::from_be_bytes([*ip.get(2)?, *ip.get(3)?]));
            let src: [u8; 4] = ip.get(12..16)?.try_into().ok()?;
            let dst: [u8; 4] = ip.get(16..20)?.try_into().ok()?;
            (
                *ip.get(9)?,
                IpAddr::from(src),
                IpAddr::from(dst),
                ip.get(ihl..total)?,
            )
        }
        0x86dd => {
            let src: [u8; 16] = ip.get(8..24)?.try_into().ok()?;
            let dst: [u8; 16] = ip.get(24..40)?.try_into().ok()?;
            (
                *ip.get(6)?,
                IpAddr::from(src),
                IpAddr::from(dst),
                ip.get(40..)?,
            )
        }
        _ => return None,
    };
    let port = |at: usize| Some(u16::from_be_bytes([*rest.get(at)?, *rest.get(at + 1)?]));
    let (sport, dport) = (port(0)?, port(2)?);
    let (seq, payload) = match proto {
        6 => {
            let off = usize::from(rest.get(12)? >> 4) * 4;
            if off < 20 {
                return None;
            }
            (
                u32::from_be_bytes(rest.get(4..8)?.try_into().ok()?),
                rest.get(off..)?,
            )
        }
        17 => (0, rest.get(8..)?),
        _ => return None,
    };
    Some(Packet {
        tcp: proto == 6,
        src: SocketAddr::new(src, sport),
        dst: SocketAddr::new(dst, dport),
        seq,
        payload: payload.to_vec(),
    })
}

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

fn run(fixture: &fixtures::Fixture) -> Vec<Seen> {
    // Flows in order of first appearance: (client, server) -> packets from the client.
    let mut order: Vec<(SocketAddr, SocketAddr, bool)> = Vec::new();
    let mut from_client: BTreeMap<(SocketAddr, SocketAddr), Vec<Packet>> = BTreeMap::new();
    let mut enricher = Enricher::new(Arc::new(FakeClock::default()), 1_000);
    let mut url = UrlModule::default();
    url.configure(&ConfigDoc::new("[modules.url]\nquery = \"full\"\n"))
        .unwrap();
    let (ctx, _) = module_context(&FakeClock::default());
    url.start(ctx).unwrap();

    let mut client_side: BTreeMap<(SocketAddr, SocketAddr), (SocketAddr, SocketAddr)> =
        BTreeMap::new();
    for frame in &fixture.frames {
        let Some(p) = decode(frame) else { continue };
        let key = (p.src.min(p.dst), p.src.max(p.dst));
        let (client, server) = *client_side.entry(key).or_insert_with(|| {
            order.push((p.src, p.dst, p.tcp));
            (p.src, p.dst)
        });
        if p.src == client {
            from_client.entry((client, server)).or_default().push(p);
        } else if !p.tcp && p.src.port() == 53 {
            enricher.observe_dns_response(&p.payload);
        }
    }

    let mut seen = Vec::new();
    for (client, server, tcp) in order {
        let mut packets = from_client.remove(&(client, server)).unwrap_or_default();
        packets.retain(|p| !p.payload.is_empty());
        let heads: Vec<Vec<u8>> = if !tcp {
            packets.into_iter().map(|p| p.payload).collect()
        } else {
            packets.sort_by_key(|p| p.seq);
            let segments: Vec<Vec<u8>> = packets.into_iter().map(|p| p.payload).collect();
            if segments.first().is_some_and(|s| s[0] == 0x16) {
                vec![segments.concat()]
            } else {
                segments
            }
        };
        let mut quic = InitialReassembler::default();
        let mut quic_hello = None;
        for (i, head) in heads.iter().enumerate() {
            if !tcp && i > 0 {
                continue; // later datagrams only feed the reassembler below
            }
            let mut obs = scribe_test_support::flow(&server.to_string())
                .payload(head)
                .observe();
            obs.event.src = client;
            obs.event.proto = if tcp { Protocol::Tcp } else { Protocol::Udp };
            obs.event.security = Security::Unknown;
            obs.event.hostname = None;
            obs.event.kind = if i == 0 {
                FlowKind::NewFlow
            } else {
                FlowKind::Payload
            };
            enricher.enrich(&mut obs);
            if !tcp && obs.event.security == Security::Quic && obs.event.hostname.is_none() {
                for d in &heads {
                    if let Progress::Hello(h) = quic.push(d) {
                        quic_hello = Some(h);
                    }
                }
                if let Some(h) = quic_hello.take() {
                    Enricher::apply_hello(&mut obs.event, h);
                }
            }
            seen.push(observed(&obs, &url));
        }
    }
    seen
}

fn observed(obs: &Observation, url: &UrlModule) -> Seen {
    let e = &obs.event;
    let note = url.flow_hook().unwrap().on_flow(&FlowContext {
        event: e,
        head: obs.head.as_deref(),
    });
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
        url: note.note.and_then(|v| v.as_str().map(str::to_owned)),
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
fn every_fixture_gives_its_expected_flows() {
    let all = fixtures::all();
    assert!(all.len() >= 16);
    for fixture in &all {
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
        assert_eq!(run(fixture), expected, "fixture {}", fixture.name);
    }
}
