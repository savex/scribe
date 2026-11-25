//! FUN-SN02: `testdata/events/linux-ebpf/*.json`: kernel records and the packets of a pcap
//! fixture, joined, give the expected observations.

use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::Arc;

use scribe_core::{FlowKind, Observation, Protocol};
use scribe_sensor_linux::{Owners, Record, RecordKind};
use scribe_sensor_pcap::flows::{replay, TrackerOptions};
use scribe_test_support::{testdata, FakeClock};
use serde::Deserialize;

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Sample {
    source: String,
    status: String,
    #[allow(dead_code)]
    description: String,
    records: Vec<RawRecord>,
    packets: String,
    observations: Vec<Expected>,
    #[allow(dead_code)]
    enriched: Vec<serde_json::Value>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct RawRecord {
    kind: String,
    tgid: u32,
    pid: u32,
    uid: u32,
    comm: String,
    exe: String,
    cgroup_id: u64,
    src: SocketAddr,
    dst: SocketAddr,
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

fn check(name: &str) {
    let dir = testdata("events/linux-ebpf");
    let text = std::fs::read_to_string(dir.join(name)).unwrap();
    let sample: Sample = serde_json::from_str(&text).unwrap();
    assert_eq!(sample.source, "linux-ebpf");
    assert_eq!(sample.status, "synthetic");

    let exes: HashMap<u32, String> = sample
        .records
        .iter()
        .map(|r| (r.tgid, r.exe.clone()))
        .collect();
    let clock = Arc::new(FakeClock::at_unix(1_800_000_000));
    let mut owners = Owners::new(clock, Box::new(move |pid| exes.get(&pid).cloned()));
    for raw in &sample.records {
        let record = Record {
            kind: match raw.kind.as_str() {
                "tcp_connect" => RecordKind::TcpConnect,
                "udp_send" => RecordKind::UdpSend,
                other => panic!("{name}: unknown record kind {other}"),
            },
            ts_ns: 0,
            cgroup_id: raw.cgroup_id,
            tgid: raw.tgid,
            pid: raw.pid,
            uid: raw.uid,
            comm: raw.comm.clone(),
            src: raw.src,
            dst: raw.dst,
        };
        // Through the bytes the kernel would write.
        let parsed = Record::parse(&record.to_bytes()).unwrap();
        owners.record(&parsed);
    }

    let bytes = std::fs::read(dir.join(&sample.packets)).unwrap();
    let mut got: Vec<Observation> = replay(&bytes, TrackerOptions::default()).unwrap();
    for obs in &mut got {
        if obs.event.kind != FlowKind::DnsResponse {
            owners.attribute(obs);
        }
    }
    // Closes carry the process of their flow too; the samples list the rest.
    for close in got.iter().filter(|o| o.event.kind == FlowKind::Close) {
        assert!(
            close.event.pid.is_some(),
            "{name}: close without a process: {:?}",
            close.event
        );
    }
    let got: Vec<&Observation> = got
        .iter()
        .filter(|o| o.event.kind != FlowKind::Close)
        .collect();
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
}

#[test]
fn ebpf_samples_decode() {
    let mut names: Vec<String> = std::fs::read_dir(testdata("events/linux-ebpf"))
        .unwrap()
        .map(|e| e.unwrap().file_name().to_string_lossy().into_owned())
        .filter(|n| n.ends_with(".json"))
        .collect();
    names.sort();
    assert_eq!(
        names,
        [
            "http_keepalive.json",
            "tcp_connect_v4.json",
            "udp_sendmsg_v6.json"
        ]
    );
    for name in names {
        check(&name);
    }
}
