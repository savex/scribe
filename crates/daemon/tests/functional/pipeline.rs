//! The pipeline: enrichment → modules → policy → writes, QUIC holding, DNS responses, storing.

use std::collections::BTreeMap;
use std::sync::Arc;
use std::time::Duration;

use scribe_core::{FlowKind, Mode, Observation, Protocol, Security};
use scribe_daemon::modules::ModuleHost;
use scribe_daemon::pipeline::{store, Pipeline, Store, QUIC_HOLD};
use scribe_enrich::Enricher;
use scribe_module_api::{ConfigDoc, Module};
use scribe_policy::{Policy, PolicyConfig};
use scribe_storage_api::{StateStore, StoredEvent};
use scribe_test_support::packets::dns::{response, Answer, TYPE_A};
use scribe_test_support::packets::quic::client_initials;
use scribe_test_support::packets::tls::{client_hello, ClientHelloOptions};
use scribe_test_support::{flow, FakeClock, MemoryStore, RecordingEmitter};

fn pipeline(mode: Mode, baseline: &[&str]) -> (Pipeline, FakeClock) {
    let clock = FakeClock::default();
    let dyn_clock: Arc<dyn scribe_core::Clock> = Arc::new(clock.clone());
    let modules: Vec<Box<dyn Module>> = vec![Box::new(scribe_module_url::UrlModule::default())];
    let mut host = ModuleHost::new(modules, &ConfigDoc::new("")).unwrap();
    for (_, started) in host.start(
        dyn_clock.clone(),
        |_| Arc::new(RecordingEmitter::default()),
        BTreeMap::new(),
    ) {
        started.unwrap();
    }
    let policy = Policy::new(
        PolicyConfig {
            mode,
            ..Default::default()
        },
        dyn_clock.clone(),
    )
    .with_baseline(baseline.iter().copied());
    let enricher = Enricher::new(dyn_clock.clone(), 1_000);
    (
        Pipeline::new(dyn_clock, "default", enricher, host, policy),
        clock,
    )
}

fn hello(sni: Option<&str>) -> Vec<u8> {
    client_hello(&ClientHelloOptions {
        sni: sni.map(Into::into),
        tls13: true,
        ..Default::default()
    })
}

fn new_flow(obs: Observation) -> Observation {
    let mut obs = obs;
    obs.event.kind = FlowKind::NewFlow;
    obs.event.security = Security::Unknown;
    obs
}

#[test]
fn a_tls_flow_is_named_stored_and_learned() {
    let (mut p, _) = pipeline(Mode::Learn, &[]);
    let obs = new_flow(
        flow("192.0.2.10:443")
            .bytes(512)
            .payload(&hello(Some("api.example.com")))
            .observe(),
    );
    let w = p.process(obs);
    assert_eq!(w.hosts.len(), 1);
    assert_eq!(w.hosts[0].name, "api.example.com");
    assert_eq!((w.hosts[0].connections, w.hosts[0].bytes_out), (1, 512));
    assert_eq!(w.hosts[0].security, Security::Tls);
    assert_eq!(w.baseline[0].host, "api.example.com");
    assert!(
        matches!(&w.events[0], StoredEvent::Flow(f) if f.hostname.as_deref() == Some("api.example.com"))
    );
    assert!(w.alerts.is_empty());
    assert_eq!((p.counters().flows, p.counters().baseline_added), (1, 1));
}

#[test]
fn dns_responses_name_later_flows_and_are_not_flows() {
    let (mut p, _) = pipeline(Mode::Alert, &["cdn.example.com"]);
    let answer = response(
        7,
        "cdn.example.com",
        TYPE_A,
        &[Answer::A("cdn.example.com", "192.0.2.50".parse().unwrap())],
        300,
    );
    let mut dns = flow("10.0.0.2:53").udp().payload(&answer).observe();
    dns.event.kind = FlowKind::DnsResponse;
    assert!(p.process(dns).is_empty());
    let w = p.process(new_flow(
        flow("192.0.2.50:443").payload(&hello(None)).observe(),
    ));
    assert_eq!(w.hosts[0].name, "cdn.example.com");
    assert!(w.alerts.is_empty(), "listed by its DNS name");
    assert_eq!((p.counters().dns_responses, p.counters().flows), (1, 1));
}

#[test]
fn a_caution_alert_brings_its_record_and_state() {
    let (mut p, _) = pipeline(Mode::Caution, &[]);
    let w = p.process(new_flow(
        flow("198.51.100.7:8443")
            .process(200, "/opt/agent/bin/agent")
            .payload(b"\x00\x01bin")
            .observe(),
    ));
    assert_eq!(w.alerts.len(), 1);
    assert_eq!(w.alerts[0].reason, "raw_ip");
    assert_eq!(w.alert_states[0].key, "198.51.100.7|/opt/agent/bin/agent");
    assert!(w
        .events
        .iter()
        .any(|e| matches!(e, StoredEvent::Alert(a) if a.dst_port == 8443)));
    assert_eq!(p.counters().alerts, 1);
}

#[test]
fn a_request_counts_and_carries_its_url() {
    let (mut p, _) = pipeline(Mode::Learn, &[]);
    let w = p.process(
        flow("192.0.2.20:80")
            .http_get("http://plain.example.com/a?x=1")
            .observe(),
    );
    assert_eq!(w.hosts[0].requests, 1);
    assert_eq!(
        w.hosts[0].connections, 0,
        "a payload is not a new connection"
    );
    let StoredEvent::Flow(f) = &w.events[0] else {
        panic!()
    };
    assert_eq!(
        f.notes.get_str("url"),
        Some("http://plain.example.com/a?x=<redacted>")
    );
    assert_eq!(p.counters().payloads, 1);
}

fn quic_datagrams(sni: &str) -> Vec<Observation> {
    let hello = &hello(Some(sni))[5..];
    client_initials(&[0x42; 8], hello, 60)
        .into_iter()
        .enumerate()
        .map(|(i, d)| {
            let mut o = flow("192.0.2.41:443").udp().payload(&d).observe();
            o.event.kind = if i == 0 {
                FlowKind::NewFlow
            } else {
                FlowKind::Payload
            };
            o.event.security = Security::Unknown;
            o
        })
        .collect()
}

#[test]
fn a_split_quic_hello_is_held_until_complete() {
    let (mut p, _) = pipeline(Mode::Caution, &["split.example.com"]);
    let datagrams = quic_datagrams("split.example.com");
    assert!(datagrams.len() >= 3);
    let (last, first) = datagrams.split_last().unwrap();
    for d in first {
        assert!(p.process(d.clone()).is_empty(), "held, not judged");
    }
    assert_eq!(p.held(), 1);
    let w = p.process(last.clone());
    assert_eq!(p.held(), 0);
    assert_eq!(w.hosts.len(), 1);
    assert_eq!(w.hosts[0].name, "split.example.com");
    assert_eq!(w.hosts[0].connections, 1);
    let StoredEvent::Flow(f) = &w.events[0] else {
        panic!()
    };
    assert_eq!((f.proto, f.security), (Protocol::Quic, Security::Quic));
    assert!(w.alerts.is_empty(), "named and listed, so no raw_ip alert");
    assert_eq!(p.counters().quic_unfinished, 0);
}

#[test]
fn a_held_quic_flow_is_judged_when_time_runs_out_or_it_closes() {
    let (mut p, clock) = pipeline(Mode::Learn, &[]);
    let datagrams = quic_datagrams("slow.example.com");
    assert!(p.process(datagrams[0].clone()).is_empty());
    assert!(p.tick().is_empty(), "still waiting");
    clock.advance(QUIC_HOLD);
    let w = p.tick();
    assert_eq!(w.hosts[0].name, "192.0.2.41", "judged without a name");
    assert_eq!(p.counters().quic_unfinished, 1);

    assert!(p.process(datagrams[0].clone()).is_empty());
    let mut close = flow("192.0.2.41:443").udp().close().observe();
    close.event.src = datagrams[0].event.src;
    let w = p.process(close);
    assert_eq!(w.hosts.len(), 1, "released by the close");
    assert_eq!(p.held(), 0);
}

#[test]
fn reset_counters_starts_over() {
    let (mut p, clock) = pipeline(Mode::Learn, &[]);
    p.process(new_flow(
        flow("192.0.2.10:443")
            .payload(&hello(Some("api.example.com")))
            .observe(),
    ));
    clock.advance(Duration::from_secs(60));
    p.reset_counters();
    assert_eq!(p.counters().flows, 0);
    assert_eq!(p.counters().since, clock_now(&clock));
}

fn clock_now(c: &FakeClock) -> std::time::SystemTime {
    scribe_core::Clock::now(c)
}

struct Doubles {
    state: MemoryStore,
    published: std::sync::Mutex<Vec<StoredEvent>>,
}

impl Store for Doubles {
    fn publish(&self, events: &[StoredEvent]) {
        self.published.lock().unwrap().extend_from_slice(events);
    }

    fn state(&self) -> &dyn StateStore {
        &self.state
    }
}

#[test]
fn store_applies_every_write() {
    let (mut p, _) = pipeline(Mode::Learn, &[]);
    let mut w = p.process(new_flow(
        flow("192.0.2.10:443")
            .payload(&hello(Some("api.example.com")))
            .observe(),
    ));
    p.policy_mut().set_mode(Mode::Alert);
    let alert = p.process(new_flow(
        flow("192.0.2.12:443")
            .payload(&hello(Some("docs.example.com")))
            .observe(),
    ));
    w.events.extend(alert.events);
    w.hosts.extend(alert.hosts);
    w.alert_states.extend(alert.alert_states);
    let doubles = Doubles {
        state: MemoryStore::default(),
        published: Default::default(),
    };
    let rt = tokio::runtime::Builder::new_current_thread()
        .build()
        .unwrap();
    let errors = rt.block_on(store(&doubles, p.profile(), &w));
    assert!(errors.is_empty(), "{errors:?}");
    assert_eq!(doubles.state.hosts().len(), 2);
    let baseline = rt.block_on(doubles.state.baseline("default")).unwrap();
    assert!(baseline.contains("api.example.com"));
    assert!(rt
        .block_on(doubles.state.get_alert_state("docs.example.com|"))
        .unwrap()
        .is_some());
    assert_eq!(doubles.published.lock().unwrap().len(), 3); // two flows, one alert
}

// ─── Run states (specs 8.5) ─────────────────────────────────────────────────

#[test]
fn hibernate_is_capped_alerts_and_drops_flows_until_it_ends() {
    use scribe_daemon::pipeline::DaemonState;
    let (p, clock) = pipeline(Mode::Alert, &[]);
    let mut p = p.with_max_hibernate(Some(Duration::from_secs(4 * 3600)));
    let w = p.hibernate(Some(Duration::from_secs(10 * 3600)), "admin");
    assert_eq!(w.alerts.len(), 1);
    assert_eq!(w.alerts[0].reason, "hibernated");
    assert_eq!(w.alerts[0].notes.get("daemon").unwrap()["caller"], "admin");
    assert!(w.events.iter().any(
        |e| matches!(e, StoredEvent::Audit(a) if a.message.starts_with("hibernate by admin until "))
    ));
    let DaemonState::Hibernating {
        until: Some(until), ..
    } = p.state().clone()
    else {
        panic!()
    };
    assert_eq!(
        until,
        clock_now(&clock) + Duration::from_secs(4 * 3600),
        "capped at max_hibernate"
    );

    let dropped = p.process(new_flow(
        flow("192.0.2.12:443")
            .payload(&hello(Some("docs.example.com")))
            .observe(),
    ));
    assert!(dropped.is_empty());
    assert_eq!(p.counters().dropped_hibernating, 1);

    let again = p.hibernate(Some(Duration::from_secs(60)), "other");
    assert!(again.alerts.is_empty(), "one alert per hibernation");
    assert!(
        matches!(&again.events[0], StoredEvent::Audit(a) if a.message.starts_with("hibernate extended by other"))
    );

    clock.advance(Duration::from_secs(61));
    assert!(p.wakeup_due());
    let w = p.tick();
    assert!(matches!(&w.events[0], StoredEvent::Audit(a) if a.message == "wakeup by timer"));
    assert_eq!(p.state(), &DaemonState::Running);
    assert_eq!(
        p.process(new_flow(
            flow("192.0.2.12:443")
                .payload(&hello(Some("docs.example.com")))
                .observe()
        ))
        .alerts
        .len(),
        1
    );
}

#[test]
fn wakeup_resumes_modules_and_does_nothing_when_running() {
    let (mut p, _) = pipeline(Mode::Learn, &[]);
    assert!(p.wakeup("admin").is_empty());
    p.hibernate(None, "admin");
    assert!(p
        .modules()
        .status()
        .iter()
        .all(|m| m.state == scribe_daemon::modules::RunState::Paused));
    let w = p.wakeup("admin");
    assert!(matches!(&w.events[0], StoredEvent::Audit(a) if a.message == "wakeup by admin"));
    assert!(p
        .modules()
        .status()
        .iter()
        .all(|m| m.state == scribe_daemon::modules::RunState::Running));
    let status = p.status();
    assert_eq!(status.state.name(), "running");
    assert_eq!(status.mode, Mode::Learn);
}

#[test]
fn unlimited_hibernation_has_no_end() {
    let (p, clock) = pipeline(Mode::Learn, &[]);
    let mut p = p.with_max_hibernate(None);
    p.hibernate(None, "admin");
    clock.advance(Duration::from_secs(365 * 86_400));
    assert!(!p.wakeup_due());
    assert!(p.is_hibernating());
}

#[test]
fn clear_caches_forgets_dns_answers() {
    let (mut p, _) = pipeline(Mode::Learn, &[]);
    let answer = response(
        1,
        "cdn.example.com",
        TYPE_A,
        &[Answer::A("cdn.example.com", "192.0.2.50".parse().unwrap())],
        300,
    );
    let mut dns = flow("10.0.0.2:53").udp().payload(&answer).observe();
    dns.event.kind = FlowKind::DnsResponse;
    p.process(dns);
    assert_eq!(p.status().dns_entries, 1);
    p.clear_caches();
    assert_eq!(p.status().dns_entries, 0);
}
