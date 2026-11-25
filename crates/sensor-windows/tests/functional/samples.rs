//! FUN-SN03: `testdata/events/windows-etw/*.json`: ETW events (through the bytes Windows
//! delivers), with or without a pcap fixture's packets, give the expected observations, and the
//! DNS answers reach the flows through the DNS cache.

use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use scribe_core::{Clock, FlowKind, Observation, Protocol, Security};
use scribe_enrich::Enricher;
use scribe_process::join::Owners;
use scribe_sensor_pcap::flows::{replay, TrackerOptions};
use scribe_sensor_windows::events::{DNS_QUERY_COMPLETED, KERNEL_NETWORK};
use scribe_sensor_windows::{dns, DnsQuery, EtwFlows, NetEvent, NetKind};
use scribe_test_support::{testdata, FakeClock};
use serde::Deserialize;

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Sample {
    source: String,
    status: String,
    #[allow(dead_code)]
    description: String,
    events: Vec<RawEvent>,
    packets: Option<String>,
    observations: Vec<Expected>,
    enriched: Vec<Enriched>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct RawEvent {
    event: String,
    pid: u32,
    #[serde(default)]
    exe: Option<String>,
    #[serde(default)]
    src: Option<SocketAddr>,
    #[serde(default)]
    dst: Option<SocketAddr>,
    #[serde(default)]
    name: Option<String>,
    #[serde(default)]
    qtype: Option<u32>,
    #[serde(default)]
    status: Option<u32>,
    #[serde(default)]
    results: Option<String>,
    /// Milliseconds since the first event.
    #[serde(default)]
    at_ms: u64,
}

#[derive(Deserialize, Debug)]
#[serde(deny_unknown_fields)]
struct Expected {
    pid: Option<u32>,
    #[serde(default)]
    process_path: Option<String>,
    proto: String,
    #[serde(default)]
    dst: Option<SocketAddr>,
    kind: String,
    #[serde(default)]
    head: Option<bool>,
}

#[derive(Deserialize, Debug)]
#[serde(deny_unknown_fields)]
struct Enriched {
    dst_ip: std::net::IpAddr,
    dst_port: u16,
    hostname: Option<String>,
    #[serde(default)]
    security: Option<String>,
}

fn kind_name(k: FlowKind) -> &'static str {
    match k {
        FlowKind::NewFlow => "new_flow",
        FlowKind::Payload => "payload",
        FlowKind::Close => "close",
        FlowKind::DnsResponse => "dns_response",
    }
}

fn proto_name(p: Protocol) -> &'static str {
    match p {
        Protocol::Tcp => "tcp",
        Protocol::Udp => "udp",
        Protocol::Quic => "quic",
    }
}

fn security_name(s: Security) -> String {
    format!("{s:?}").to_lowercase()
}

fn check(name: &str) {
    let dir = testdata("events/windows-etw");
    let text = std::fs::read_to_string(dir.join(name)).unwrap();
    let sample: Sample = serde_json::from_str(&text).unwrap();
    assert_eq!(sample.source, "windows-etw");
    assert_eq!(sample.status, "synthetic");
    let _ = KERNEL_NETWORK;

    let exes: HashMap<u32, String> = sample
        .events
        .iter()
        .filter_map(|e| Some((e.pid, e.exe.clone()?)))
        .collect();
    let clock = Arc::new(FakeClock::at_unix(1_800_000_000));
    let start = clock.now();
    let mut owners = Owners::new(clock.clone(), Box::new(move |pid| exes.get(&pid).cloned()));
    let mut flows = EtwFlows::new();
    let mut got: Vec<Observation> = Vec::new();

    for raw in &sample.events {
        let now = start + Duration::from_millis(raw.at_ms);
        clock.set(now);
        if raw.event == "dns_query" {
            let q = DnsQuery {
                name: raw.name.clone().unwrap(),
                qtype: raw.qtype.unwrap_or(1),
                status: raw.status.unwrap_or(0),
                results: raw.results.clone().unwrap_or_default(),
            };
            // Through the bytes Windows delivers.
            let back = DnsQuery::parse(&q.to_bytes()).unwrap();
            assert_eq!(back, q);
            let _ = DNS_QUERY_COMPLETED;
            got.extend(dns::observation(&back, now));
            continue;
        }
        let kind = match raw.event.as_str() {
            "tcp_connect" => NetKind::TcpConnect,
            "udp_send" => NetKind::UdpSend,
            other => panic!("{name}: unknown event {other}"),
        };
        let e = NetEvent {
            kind,
            pid: raw.pid,
            src: raw.src.unwrap(),
            dst: raw.dst.unwrap(),
        };
        let (id, bytes) = e.to_bytes();
        let e = NetEvent::parse(id, &bytes).unwrap().unwrap();
        owners.record(&e.connection());
        if sample.packets.is_none() {
            if let Some(mut obs) = flows.observe(&e, now) {
                assert!(owners.attribute(&mut obs), "{name}: no owner for {e:?}");
                got.push(obs);
            }
        }
    }
    if let Some(packets) = &sample.packets {
        let bytes = std::fs::read(dir.join(packets)).unwrap();
        for mut obs in replay(&bytes, TrackerOptions::default()).unwrap() {
            if obs.event.kind != FlowKind::DnsResponse {
                owners.attribute(&mut obs);
            }
            if obs.event.kind != FlowKind::Close {
                got.push(obs);
            }
        }
    }

    assert_eq!(
        got.len(),
        sample.observations.len(),
        "{name}: {:#?}",
        got.iter().map(|o| &o.event).collect::<Vec<_>>()
    );
    for (i, (o, want)) in got.iter().zip(&sample.observations).enumerate() {
        let e = &o.event;
        let at = format!("{name} observation {i}: {e:?}");
        assert_eq!(kind_name(e.kind), want.kind, "{at}");
        assert_eq!(proto_name(e.proto), want.proto, "{at}");
        assert_eq!(e.pid, want.pid, "{at}");
        if let Some(path) = &want.process_path {
            assert_eq!(e.process_path.as_deref(), Some(path.as_str()), "{at}");
        }
        if let Some(dst) = want.dst {
            assert_eq!(SocketAddr::new(e.dst_ip, e.dst_port), dst, "{at}");
        }
        if let Some(head) = want.head {
            assert_eq!(o.head.as_ref().is_some_and(|h| !h.is_empty()), head, "{at}");
        }
    }

    // Enrichment: DNS answers into the cache, then the flows get their names.
    let mut enricher = Enricher::new(clock.clone(), 100);
    for o in got.iter().filter(|o| o.event.kind == FlowKind::DnsResponse) {
        enricher.observe_dns_response(o.head.as_ref().unwrap());
    }
    for want in &sample.enriched {
        let mut flow = got
            .iter()
            .find(|o| {
                o.event.kind == FlowKind::NewFlow
                    && o.event.dst_ip == want.dst_ip
                    && o.event.dst_port == want.dst_port
            })
            .unwrap_or_else(|| panic!("{name}: no flow to {want:?}"))
            .clone();
        enricher.enrich(&mut flow);
        assert_eq!(flow.event.hostname, want.hostname, "{name}: {want:?}");
        if let Some(security) = &want.security {
            assert_eq!(
                &security_name(flow.event.security),
                security,
                "{name}: {want:?}"
            );
        }
    }
}

#[test]
fn etw_samples_decode() {
    let mut names: Vec<String> = std::fs::read_dir(testdata("events/windows-etw"))
        .unwrap()
        .map(|e| e.unwrap().file_name().to_string_lossy().into_owned())
        .filter(|n| n.ends_with(".json"))
        .collect();
    names.sort();
    assert_eq!(
        names,
        [
            "dns_client_query.json",
            "kernel_network_tcp_connect.json",
            "kernel_network_udp_v6.json"
        ]
    );
    for name in names {
        check(&name);
    }
}
