//! The policy engine: one [`Policy::decide`] call per observation (specs 8.1–8.3).
//!
//! | Flow | `learn` | `caution` | `alert` |
//! |---|---|---|---|
//! | Listed host, TLS / QUIC | record | record | record |
//! | Listed host, plaintext | record | alert `plaintext` | alert `plaintext` |
//! | Unlisted host, ordinary | record, add to baseline | record | alert `unlisted_host` |
//! | Unlisted host, non-ordinary | record, add to baseline | alert (top signal) | alert `unlisted_host` |
//!
//! A flow without a name is keyed by its destination IP. Alerts are deduplicated per host +
//! process: one per `dedupe_window`, none once acknowledged. A repeat inside the window that
//! brings new notes (the URL of a later request) adds them to the earlier alert.

use std::collections::{BTreeMap, HashMap, HashSet};
use std::sync::Arc;
use std::time::{Duration, SystemTime};

use scribe_core::{Alert, Clock, FlowEvent, FlowKind, Mode, Security};

use crate::signals::{self, UsualPorts};
use crate::threat::ThreatSet;

/// Scores of the built-in signals, plus module signals by their namespaced reason
/// (`tag.large_head`). 0 disables a signal; a module signal with no score counts 0.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Scores {
    pub raw_ip: u8,
    pub unusual_port: u8,
    pub high_entropy: u8,
    pub new_tld: u8,
    pub new_process: u8,
    pub threat_list: u8,
    pub modules: BTreeMap<String, u8>,
}

impl Default for Scores {
    fn default() -> Self {
        Self {
            raw_ip: 60,
            unusual_port: 30,
            high_entropy: 50,
            new_tld: 20,
            new_process: 25,
            threat_list: 100,
            modules: BTreeMap::new(),
        }
    }
}

/// Everything the engine needs from `[policy]` and `mode`, already checked by the config loader.
#[derive(Debug, Clone, PartialEq)]
pub struct PolicyConfig {
    pub mode: Mode,
    /// Learn mode ends after this long and switches to `then`.
    pub learn_for: Option<Duration>,
    pub then: Mode,
    pub dedupe_window: Duration,
    pub threshold: u8,
    pub scores: Scores,
    pub usual_ports: UsualPorts,
    pub entropy_min_length: usize,
    pub entropy_min_bits: f64,
}

impl Default for PolicyConfig {
    fn default() -> Self {
        Self {
            mode: Mode::Learn,
            learn_for: None,
            then: Mode::Caution,
            dedupe_window: Duration::from_secs(600),
            threshold: 50,
            scores: Scores::default(),
            usual_ports: UsualPorts::default(),
            entropy_min_length: 10,
            entropy_min_bits: 3.5,
        }
    }
}

/// What the engine decided for one observation. The caller stores it.
#[derive(Debug, Clone, Default, PartialEq)]
pub struct Decision {
    /// The host key: the host name, or the destination IP when there is none.
    pub host: String,
    /// The mode the flow was judged in.
    pub mode: Mode,
    /// Matching signals with their scores, highest first.
    pub signals: Vec<(String, u8)>,
    /// Sum of `signals`, capped at 100.
    pub score: u8,
    /// Learn mode: the host was added to the baseline.
    pub baseline_add: Option<String>,
    /// A new alert.
    pub alert: Option<Alert>,
    /// An earlier alert for the same host + process, now with this flow's new notes.
    pub alert_update: Option<Alert>,
    /// The mode changed before this flow was judged (learn time ran out).
    pub mode_changed: Option<Mode>,
}

#[derive(Debug, Clone)]
struct Raised {
    alert: Alert,
    acknowledged: bool,
}

pub struct Policy {
    config: PolicyConfig,
    clock: Arc<dyn Clock>,
    mode: Mode,
    learn_until: Option<SystemTime>,
    /// Set while the learn countdown is paused (hibernation).
    learn_paused_at: Option<SystemTime>,
    baseline: HashSet<String>,
    tlds: HashSet<String>,
    processes: HashSet<String>,
    threats: ThreatSet,
    raised: HashMap<String, Raised>,
}

/// The dedupe key of an alert: host + process.
pub fn alert_key(alert: &Alert) -> String {
    alert_key_for(
        alert.host.as_deref(),
        alert.dst_ip,
        alert.process_path.as_deref(),
    )
}

/// [`alert_key`] from an alert's parts (a stored `AlertRecord`): the host, or the destination IP
/// when there is no name, and the process.
pub fn alert_key_for(
    host: Option<&str>,
    dst_ip: std::net::IpAddr,
    process: Option<&str>,
) -> String {
    match host {
        Some(h) => key(h, process),
        None => key(&dst_ip.to_string(), process),
    }
}

/// The alert a stored dedupe key stands for, as far as the key tells: the host (or destination
/// IP) and the process. `alert_key` of the result is `key` again.
pub fn alert_from_key(key: &str, last_alerted: SystemTime) -> Alert {
    let (host, process) = key.split_once('|').unwrap_or((key, ""));
    let (host, dst_ip) = match host.parse::<std::net::IpAddr>() {
        Ok(ip) => (None, ip),
        Err(_) => (
            Some(host.to_owned()),
            std::net::IpAddr::V4(std::net::Ipv4Addr::UNSPECIFIED),
        ),
    };
    Alert {
        ts: last_alerted,
        host,
        dst_ip,
        dst_port: 0,
        process_path: (!process.is_empty()).then(|| process.to_owned()),
        score: 0,
        reason: String::new(),
        notes: Default::default(),
    }
}

fn key(host: &str, process: Option<&str>) -> String {
    format!("{host}|{}", process.unwrap_or(""))
}

impl Policy {
    pub fn new(config: PolicyConfig, clock: Arc<dyn Clock>) -> Self {
        let mode = config.mode;
        let mut policy = Self {
            mode,
            learn_until: None,
            learn_paused_at: None,
            config,
            clock,
            baseline: HashSet::new(),
            tlds: HashSet::new(),
            processes: HashSet::new(),
            threats: ThreatSet::default(),
            raised: HashMap::new(),
        };
        policy.start_learn_timer();
        policy
    }

    /// Hosts already on the active profile's baseline; their TLDs count as seen.
    pub fn with_baseline<I: IntoIterator<Item = S>, S: Into<String>>(mut self, hosts: I) -> Self {
        for host in hosts {
            self.add_to_baseline(host);
        }
        self
    }

    /// Processes that made connections before (from the state store).
    pub fn with_known_processes<I: IntoIterator<Item = S>, S: Into<String>>(
        mut self,
        paths: I,
    ) -> Self {
        self.processes.extend(paths.into_iter().map(Into::into));
        self
    }

    pub fn with_threats(mut self, threats: ThreatSet) -> Self {
        self.threats = threats;
        self
    }

    pub fn mode(&self) -> Mode {
        self.mode
    }

    /// When learn mode ends, if it is time-limited.
    pub fn learn_until(&self) -> Option<SystemTime> {
        self.learn_until
    }

    /// Stop the learn countdown (hibernation); [`Policy::resume_learn_timer`] adds the pause to it.
    pub fn pause_learn_timer(&mut self) {
        if self.learn_paused_at.is_none() {
            self.learn_paused_at = Some(self.clock.now());
        }
    }

    pub fn resume_learn_timer(&mut self) {
        if let Some(paused) = self.learn_paused_at.take() {
            let pause = self
                .clock
                .now()
                .duration_since(paused)
                .unwrap_or(Duration::ZERO);
            if let Some(until) = &mut self.learn_until {
                *until += pause;
            }
        }
    }

    pub fn config(&self) -> &PolicyConfig {
        &self.config
    }

    /// New settings from a config reload, from the next flow on. Mode, learn countdown, baseline,
    /// what was seen and alert state stay; change the mode with [`Policy::set_mode`].
    pub fn set_config(&mut self, config: PolicyConfig) {
        self.config = config;
    }

    pub fn set_threats(&mut self, threats: ThreatSet) {
        self.threats = threats;
    }

    /// The baseline of another profile (profile switch); TLDs seen so far stay seen.
    pub fn replace_baseline<I: IntoIterator<Item = S>, S: Into<String>>(&mut self, hosts: I) {
        self.baseline.clear();
        for host in hosts {
            self.add_to_baseline(host);
        }
    }

    /// Switch mode from the next flow on (`scribe mode`, the API). Learn mode restarts its timer;
    /// while the timer is paused (hibernation) the new countdown starts paused, from now.
    pub fn set_mode(&mut self, mode: Mode) {
        self.mode = mode;
        self.start_learn_timer();
        if self.learn_paused_at.is_some() {
            self.learn_paused_at = Some(self.clock.now());
        }
    }

    fn start_learn_timer(&mut self) {
        self.learn_until = match (self.mode, self.config.learn_for) {
            (Mode::Learn, Some(d)) => Some(self.clock.now() + d),
            _ => None,
        };
    }

    pub fn is_listed(&self, host: &str) -> bool {
        self.baseline.contains(&host.to_ascii_lowercase())
    }

    pub fn add_to_baseline(&mut self, host: impl Into<String>) -> bool {
        let host = host.into().to_ascii_lowercase();
        if let Some(tld) = signals::tld(&host) {
            self.tlds.insert(tld.to_owned());
        }
        self.baseline.insert(host)
    }

    pub fn remove_from_baseline(&mut self, host: &str) -> bool {
        self.baseline.remove(&host.to_ascii_lowercase())
    }

    /// Restore what was stored before a restart (specs 8.5): an acknowledged key stays silent; an
    /// unacknowledged one is deduplicated until its window ends. A key raised since start wins.
    pub fn restore_alert(&mut self, alert: Alert, acknowledged: bool) {
        self.raised.entry(alert_key(&alert)).or_insert(Raised {
            alert,
            acknowledged,
        });
    }

    /// Silence alerts for this alert's host + process for good.
    pub fn acknowledge(&mut self, alert: &Alert) {
        let key = alert_key(alert);
        let raised = self.raised.entry(key).or_insert_with(|| Raised {
            alert: alert.clone(),
            acknowledged: false,
        });
        raised.acknowledged = true;
    }

    /// Judge one observation. `module_signals` are the reasons the flow hooks returned.
    pub fn decide(&mut self, event: &FlowEvent, module_signals: &[String]) -> Decision {
        let now = self.clock.now();
        let mut decision = Decision::default();
        if self.learn_until.is_some_and(|until| now >= until) {
            self.mode = self.config.then;
            self.learn_until = None;
            decision.mode_changed = Some(self.mode);
        }
        decision.mode = self.mode;
        decision.host = match &event.hostname {
            Some(name) => name.to_ascii_lowercase(),
            None => event.dst_ip.to_string(),
        };
        if event.kind == FlowKind::Close {
            return decision;
        }
        let listed = self.is_listed(&decision.host);
        decision.signals = self.signals(event, &decision.host, module_signals);
        let total: u32 = decision.signals.iter().map(|(_, s)| u32::from(*s)).sum();
        decision.score = total.min(100) as u8;

        let plaintext = event.security == Security::Plaintext;
        let reason = match self.mode {
            Mode::Learn => None,
            Mode::Caution => {
                let score_alert =
                    !listed && decision.score > 0 && decision.score >= self.config.threshold;
                if score_alert {
                    decision.signals.first().map(|(r, _)| r.clone())
                } else if plaintext {
                    Some(signals::PLAINTEXT.to_owned())
                } else {
                    None
                }
            }
            Mode::Alert if !listed => Some(signals::UNLISTED_HOST.to_owned()),
            Mode::Alert if plaintext => Some(signals::PLAINTEXT.to_owned()),
            Mode::Alert => None,
        };
        if let Some(reason) = reason {
            let host = decision.host.clone();
            let score = decision.score;
            self.raise(event, &host, reason, score, now, &mut decision);
        }

        // Learn from the flow after judging it.
        if self.mode == Mode::Learn && !listed {
            self.add_to_baseline(decision.host.clone());
            decision.baseline_add = Some(decision.host.clone());
        }
        if let Some(tld) = signals::tld(&decision.host) {
            self.tlds.insert(tld.to_owned());
        }
        if let Some(path) = &event.process_path {
            self.processes.insert(path.clone());
        }
        decision
    }

    fn signals(
        &self,
        event: &FlowEvent,
        host: &str,
        module_signals: &[String],
    ) -> Vec<(String, u8)> {
        let s = &self.config.scores;
        let mut out: Vec<(String, u8)> = Vec::new();
        let mut add = |reason: &str, score: u8| {
            if score > 0 && !out.iter().any(|(r, _)| r == reason) {
                out.push((reason.to_owned(), score));
            }
        };
        if event.hostname.is_none() {
            add(signals::RAW_IP, s.raw_ip);
        }
        if !self
            .config
            .usual_ports
            .is_usual(event.proto, event.dst_port)
        {
            add(signals::UNUSUAL_PORT, s.unusual_port);
        }
        if event.hostname.is_some()
            && signals::high_entropy(
                host,
                self.config.entropy_min_length,
                self.config.entropy_min_bits,
            )
        {
            add(signals::HIGH_ENTROPY, s.high_entropy);
        }
        if signals::tld(host).is_some_and(|t| !self.tlds.contains(t)) {
            add(signals::NEW_TLD, s.new_tld);
        }
        if event
            .process_path
            .as_ref()
            .is_some_and(|p| !self.processes.contains(p))
        {
            add(signals::NEW_PROCESS, s.new_process);
        }
        if self.threats.matches_ip(event.dst_ip)
            || (event.hostname.is_some() && self.threats.matches_host(host))
        {
            add(signals::THREAT_LIST, s.threat_list);
        }
        for reason in module_signals {
            add(reason, s.modules.get(reason).copied().unwrap_or(0));
        }
        // Highest score first; ties keep the order above.
        out.sort_by_key(|s| std::cmp::Reverse(s.1));
        out
    }

    fn raise(
        &mut self,
        event: &FlowEvent,
        host: &str,
        reason: String,
        score: u8,
        now: SystemTime,
        decision: &mut Decision,
    ) {
        let key = key(host, event.process_path.as_deref());
        if let Some(raised) = self.raised.get_mut(&key) {
            if raised.acknowledged {
                return;
            }
            let age = now
                .duration_since(raised.alert.ts)
                .unwrap_or(Duration::ZERO);
            if age < self.config.dedupe_window {
                let new = event
                    .notes
                    .iter()
                    .any(|(m, v)| raised.alert.notes.get(m) != Some(v));
                if new {
                    raised.alert.notes.merge(event.notes.clone());
                    decision.alert_update = Some(raised.alert.clone());
                }
                return;
            }
        }
        let alert = Alert {
            ts: now,
            host: event.hostname.as_ref().map(|h| h.to_ascii_lowercase()),
            dst_ip: event.dst_ip,
            dst_port: event.dst_port,
            process_path: event.process_path.clone(),
            score: u32::from(score),
            reason,
            notes: event.notes.clone(),
        };
        self.raised.insert(
            key,
            Raised {
                alert: alert.clone(),
                acknowledged: false,
            },
        );
        decision.alert = Some(alert);
    }
}
