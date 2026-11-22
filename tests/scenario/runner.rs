//! Plays one `testdata/scenarios/*.yaml` file (format: `testdata/scenarios/README.md`).
//!
//! Until the daemon pipeline exists (plan phase 5), the runner stands in for it with the real
//! parts: `ModuleHost` with the built-in and test modules, the `Policy` engine, and a
//! `MemoryStore` for host counters through the `StateStore` API. Scenario features that need
//! phase 5 (hibernate, wakeup, reset, run states, runtime and per-process counters) are refused
//! with a clear message; their tests are marked `#[ignore]`.

use std::collections::{BTreeMap, HashMap};
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::{Duration, SystemTime};

use scribe_core::{Alert, Clock, FlowKind, HumanDuration, Mode, Observation};
use scribe_daemon::modules::ModuleHost;
use scribe_module_api::{ConfigDoc, Module};
use scribe_policy::{alert_key, Policy, PolicyConfig, ThreatSet};
use scribe_storage_api::{HostDelta, StateStore};
use scribe_test_support::{flow, FakeClock, MemoryStore, RecordingEmitter, TagModule, TicksModule};
use serde::Deserialize;

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Scenario {
    pub name: String,
    pub description: String,
    pub mode: Mode,
    pub learn_for: Option<String>,
    pub then: Option<Mode>,
    pub profile: String,
    #[serde(default)]
    pub baseline: Vec<String>,
    pub dedupe_window: Option<String>,
    pub max_hibernate: Option<String>,
    pub modules: Option<Vec<String>>,
    #[serde(default)]
    pub threat_list: Vec<String>,
    #[serde(default)]
    pub scores: BTreeMap<String, u8>,
    pub events: Vec<Event>,
    pub expect: Expect,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Event {
    pub at: String,
    pub dst: Option<String>,
    pub proto: Option<String>,
    pub host: Option<String>,
    pub security: Option<String>,
    #[serde(default)]
    pub ech: bool,
    pub head_bytes: Option<usize>,
    pub process: Option<String>,
    pub pid: Option<u32>,
    #[serde(default)]
    pub bytes: u64,
    pub kind: Option<String>,
    pub url: Option<String>,
    pub api: Option<Api>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Api {
    pub set_mode: Option<Mode>,
    pub ack: Option<usize>,
    pub baseline_add: Option<String>,
    pub baseline_rm: Option<String>,
    pub hibernate: Option<serde_yaml_ng::Value>,
    pub wakeup: Option<bool>,
    pub reset: Option<Vec<String>>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Expect {
    pub mode: Option<Mode>,
    pub run_state: Option<String>,
    pub alerts: Option<Vec<ExpectedAlert>>,
    pub baseline_added: Option<Vec<String>>,
    pub hosts: Option<BTreeMap<String, ExpectedHost>>,
    pub processes: Option<serde_yaml_ng::Value>,
    pub signals: Option<Vec<String>>,
    pub runtime: Option<serde_yaml_ng::Value>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ExpectedAlert {
    pub host: Option<String>,
    pub dst: Option<String>,
    pub process: Option<String>,
    pub reason: String,
    pub notes: Option<BTreeMap<String, String>>,
}

#[derive(Debug, Default, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ExpectedHost {
    pub connections: Option<u64>,
    pub requests: Option<u64>,
    pub bytes: Option<u64>,
    pub tls_seen: Option<bool>,
    pub plaintext_seen: Option<bool>,
    pub unresolved: Option<bool>,
}

/// A duration such as `30s` or `61m`; offsets may be zero, which config durations refuse.
fn duration(text: &str) -> Duration {
    if text
        .trim_start_matches('0')
        .chars()
        .next()
        .is_none_or(|c| !c.is_ascii_digit())
    {
        return Duration::ZERO;
    }
    text.parse::<HumanDuration>()
        .unwrap_or_else(|e| panic!("bad duration {text:?}: {e}"))
        .get()
}

pub fn load(name: &str) -> Scenario {
    let path = scribe_tests::testdata(&format!("scenarios/{name}.yaml"));
    let text = std::fs::read_to_string(&path).unwrap_or_else(|e| panic!("{}: {e}", path.display()));
    let scenario: Scenario =
        serde_yaml_ng::from_str(&text).unwrap_or_else(|e| panic!("{}: {e}", path.display()));
    assert_eq!(scenario.name, name, "name must match the file name");
    assert!(
        !scenario.description.trim().is_empty(),
        "{name}: description is empty"
    );
    // The policy engine holds one baseline: the active profile's.
    assert!(!scenario.profile.is_empty(), "{name}: profile is empty");
    scenario
}

/// Parts of a scenario the runner can't play before phase 5.
pub fn needs_phase_5(s: &Scenario) -> Vec<&'static str> {
    let mut out = Vec::new();
    for e in &s.events {
        if let Some(api) = &e.api {
            if api.hibernate.is_some() {
                out.push("api hibernate");
            }
            if api.wakeup.is_some() {
                out.push("api wakeup");
            }
            if api.reset.is_some() {
                out.push("api reset");
            }
        }
    }
    if s.max_hibernate.is_some() {
        out.push("max_hibernate");
    }
    if s.expect.run_state.is_some() {
        out.push("expect run_state");
    }
    if s.expect.runtime.is_some() {
        out.push("expect runtime");
    }
    if s.expect.processes.is_some() {
        out.push("expect processes (per-process counters)");
    }
    out
}

/// What a played scenario produced.
#[derive(Debug, Default)]
struct Outcome {
    alerts: Vec<Alert>,
    baseline_added: Vec<String>,
    signals: Vec<String>,
    unresolved: HashMap<String, bool>,
}

fn modules(ids: &[String]) -> Vec<Box<dyn Module>> {
    ids.iter()
        .map(|id| -> Box<dyn Module> {
            match id.as_str() {
                "url" => Box::new(scribe_module_url::UrlModule::default()),
                "tag" => Box::new(TagModule::default()),
                "ticks" => Box::new(TicksModule::default()),
                other => panic!("unknown module {other:?} in scenario"),
            }
        })
        .collect()
}

fn observation(e: &Event, now: SystemTime) -> Observation {
    let dst = e.dst.as_deref().expect("a flow event needs `dst`");
    let mut b = flow(dst).at(now).bytes(e.bytes);
    match e.proto.as_deref().unwrap_or("tcp") {
        "tcp" => {}
        "udp" => b = b.udp(),
        "quic" => b = b.quic(),
        other => panic!("unknown proto {other:?}"),
    }
    if let Some(host) = &e.host {
        b = b.host(host);
    }
    if let Some(process) = &e.process {
        b = b.process(e.pid.unwrap_or(1), process);
    }
    if e.ech {
        b = b.ech();
    }
    let kind = e.kind.as_deref().unwrap_or("new_flow");
    match kind {
        "new_flow" => {}
        "request" => {
            let url = e.url.as_deref().expect("a request event needs `url`");
            b = b.http_get(url);
        }
        "close" => b = b.close(),
        other => panic!("unknown kind {other:?}"),
    }
    match e.security.as_deref() {
        None if kind == "request" => {}
        None | Some("unknown") => {}
        Some("tls") => b = b.tls(),
        Some("plaintext") => b = b.plaintext(),
        Some("quic") => b = b.quic(),
        Some(other) => panic!("unknown security {other:?}"),
    }
    let mut obs = b.observe();
    if let Some(n) = e.head_bytes {
        obs = Observation::new(obs.event).with_head(&vec![0x16; n]);
    }
    if kind == "new_flow" {
        obs.event.kind = FlowKind::NewFlow;
    }
    obs
}

/// Play `s` and check every expectation; panics with the scenario name on a mismatch.
pub fn run(s: &Scenario) {
    let unsupported = needs_phase_5(s);
    assert!(
        unsupported.is_empty(),
        "scenario {} needs the daemon run states and counters of plan phase 5: {}",
        s.name,
        unsupported.join(", ")
    );
    let clock = FakeClock::default();
    let start = clock.now();
    let clock_dyn: Arc<dyn Clock> = Arc::new(clock.clone());

    let ids = s.modules.clone().unwrap_or_else(|| vec!["url".into()]);
    let mut host = ModuleHost::new(modules(&ids), &ConfigDoc::new("")).unwrap();
    for (id, started) in host.start(
        clock_dyn.clone(),
        |_| Arc::new(RecordingEmitter::default()),
        BTreeMap::new(),
    ) {
        started.unwrap_or_else(|e| panic!("module {id} did not start: {e}"));
    }

    let mut config = PolicyConfig {
        mode: s.mode,
        learn_for: s.learn_for.as_deref().map(duration),
        then: s.then.unwrap_or(Mode::Caution),
        ..Default::default()
    };
    if let Some(w) = &s.dedupe_window {
        config.dedupe_window = duration(w);
    }
    config.scores.modules = s.scores.clone();
    let mut threats = ThreatSet::default();
    for entry in &s.threat_list {
        assert!(
            threats.add_ip(entry) || threats.add_domain(entry),
            "bad threat entry {entry:?}"
        );
    }
    let mut policy = Policy::new(config, clock_dyn)
        .with_baseline(s.baseline.iter().cloned())
        .with_threats(threats);
    let store = MemoryStore::default();
    let rt = tokio::runtime::Builder::new_current_thread()
        .build()
        .unwrap();
    let mut out = Outcome::default();

    for e in &s.events {
        clock.set(start + duration(&e.at));
        if let Some(api) = &e.api {
            if let Some(mode) = api.set_mode {
                policy.set_mode(mode);
            }
            if let Some(i) = api.ack {
                let alert = out
                    .alerts
                    .get(i)
                    .unwrap_or_else(|| panic!("ack {i}: no such alert"));
                policy.acknowledge(alert);
            }
            if let Some(h) = &api.baseline_add {
                policy.add_to_baseline(h.clone());
            }
            if let Some(h) = &api.baseline_rm {
                policy.remove_from_baseline(h);
            }
            continue;
        }
        let mut obs = observation(e, clock.now());
        let (notes, signals) = host.on_flow(&obs);
        obs.event.notes.merge(notes);
        let reasons: Vec<String> = signals.into_iter().map(|s| s.reason).collect();
        for r in &reasons {
            if !out.signals.contains(r) {
                out.signals.push(r.clone());
            }
        }
        let d = policy.decide(&obs.event, &reasons);
        if let Some(h) = d.baseline_add.clone() {
            out.baseline_added.push(h);
        }
        if let Some(a) = d.alert.clone() {
            out.alerts.push(a);
        }
        if let Some(updated) = d.alert_update.clone() {
            let key = alert_key(&updated);
            let earlier = out
                .alerts
                .iter_mut()
                .rfind(|a| a.ts == updated.ts && alert_key(a) == key)
                .expect("an update for an alert that was raised");
            *earlier = updated;
        }
        if obs.event.kind != FlowKind::Close {
            let unresolved = obs.event.hostname.is_none() || obs.event.ech;
            *out.unresolved.entry(d.host.clone()).or_insert(false) |= unresolved;
            let delta = HostDelta {
                name: d.host.clone(),
                seen_at: obs.event.ts,
                connections: u64::from(obs.event.kind == FlowKind::NewFlow),
                requests: u64::from(obs.event.notes.get_str("url").is_some()),
                bytes_out: obs.event.bytes_out,
                security: obs.event.security,
            };
            rt.block_on(store.upsert_host(&delta)).unwrap();
        }
    }
    check(s, &policy, &store, &out);
}

fn check(s: &Scenario, policy: &Policy, store: &MemoryStore, out: &Outcome) {
    let name = &s.name;
    if let Some(mode) = s.expect.mode {
        assert_eq!(policy.mode(), mode, "{name}: mode");
    }
    if let Some(expected) = &s.expect.alerts {
        let got: Vec<String> = out.alerts.iter().map(describe).collect();
        assert_eq!(out.alerts.len(), expected.len(), "{name}: alerts {got:#?}");
        for (i, (a, e)) in out.alerts.iter().zip(expected).enumerate() {
            let dst = SocketAddr::new(a.dst_ip, a.dst_port).to_string();
            if e.reason == "hibernated" {
                panic!("{name}: daemon alerts need phase 5");
            }
            assert_eq!(a.reason, e.reason, "{name}: alert {i} reason, got {got:#?}");
            assert_eq!(a.host, e.host, "{name}: alert {i} host");
            assert_eq!(Some(dst), e.dst.clone(), "{name}: alert {i} dst");
            if let Some(p) = &e.process {
                assert_eq!(
                    a.process_path.as_ref(),
                    Some(p),
                    "{name}: alert {i} process"
                );
            }
            if let Some(notes) = &e.notes {
                for (module, value) in notes {
                    assert_eq!(
                        a.notes.get_str(module),
                        Some(value.as_str()),
                        "{name}: alert {i} note {module}"
                    );
                }
            }
        }
    }
    if let Some(expected) = &s.expect.baseline_added {
        assert_eq!(&out.baseline_added, expected, "{name}: baseline_added");
    }
    if let Some(expected) = &s.expect.signals {
        assert_eq!(&out.signals, expected, "{name}: signals");
    }
    if let Some(expected) = &s.expect.hosts {
        let hosts = store.hosts();
        for (key, e) in expected {
            let h = hosts
                .iter()
                .find(|h| &h.name == key)
                .unwrap_or_else(|| panic!("{name}: host {key} was not stored"));
            let field = |what: &str, got: u64, want: Option<u64>| {
                if let Some(want) = want {
                    assert_eq!(got, want, "{name}: {key} {what}");
                }
            };
            field("connections", h.conn_count, e.connections);
            field("requests", h.req_count, e.requests);
            field("bytes", h.bytes_out, e.bytes);
            if let Some(t) = e.tls_seen {
                assert_eq!(h.tls_seen, t, "{name}: {key} tls_seen");
            }
            if let Some(p) = e.plaintext_seen {
                assert_eq!(h.plaintext_seen, p, "{name}: {key} plaintext_seen");
            }
            if let Some(u) = e.unresolved {
                assert_eq!(
                    out.unresolved.get(key).copied(),
                    Some(u),
                    "{name}: {key} unresolved"
                );
            }
        }
    }
}

fn describe(a: &Alert) -> String {
    format!(
        "{} {}:{} {} {}",
        a.reason,
        a.host.as_deref().unwrap_or("-"),
        a.dst_port,
        a.process_path.as_deref().unwrap_or("-"),
        a.dst_ip
    )
}
