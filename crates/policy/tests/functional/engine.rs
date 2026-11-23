//! The engine: the specs 8.1 table, scores (specs 8.3), learn timer, dedupe, acknowledgement,
//! notes on alerts and module signals.

use std::sync::Arc;
use std::time::Duration;

use scribe_core::Mode;
use scribe_policy::{alert_key, Policy, PolicyConfig, ThreatFormat, ThreatSet};
use scribe_test_support::{flow, FakeClock, FlowBuilder};
use serde_json::json;

fn policy(mode: Mode, baseline: &[&str]) -> (Policy, FakeClock) {
    let clock = FakeClock::default();
    let config = PolicyConfig {
        mode,
        ..Default::default()
    };
    let p = Policy::new(config, Arc::new(clock.clone())).with_baseline(baseline.iter().copied());
    (p, clock)
}

fn tls(dst: &str, host: &str) -> FlowBuilder {
    flow(dst).host(host).tls()
}

fn reason(p: &mut Policy, f: FlowBuilder) -> Option<String> {
    p.decide(&f.build(), &[]).alert.map(|a| a.reason)
}

#[test]
fn learn_mode_adds_every_host_and_never_alerts() {
    let (mut p, _) = policy(Mode::Learn, &[]);
    let d = p.decide(&tls("192.0.2.10:443", "API.example.com").build(), &[]);
    assert_eq!(d.baseline_add.as_deref(), Some("api.example.com"));
    assert!(d.alert.is_none());
    let raw = p.decide(&flow("198.51.100.7:8443").plaintext().build(), &[]);
    assert_eq!(raw.baseline_add.as_deref(), Some("198.51.100.7"));
    assert!(raw.alert.is_none());
    assert!(p.is_listed("api.example.com"));
    let again = p.decide(&tls("192.0.2.10:443", "api.example.com").build(), &[]);
    assert_eq!(again.baseline_add, None, "already listed");
}

#[test]
fn caution_mode_follows_the_table() {
    let (mut p, _) = policy(Mode::Caution, &["api.example.com", "plain.example.com"]);
    // Listed, TLS: record.
    assert_eq!(
        reason(&mut p, tls("192.0.2.10:443", "api.example.com")),
        None
    );
    // Listed, plaintext: alert.
    assert_eq!(
        reason(
            &mut p,
            flow("192.0.2.20:80").host("plain.example.com").plaintext()
        )
        .as_deref(),
        Some("plaintext")
    );
    // Unlisted, ordinary (new process 25): record.
    assert_eq!(
        reason(
            &mut p,
            tls("192.0.2.12:443", "docs.example.com").process(100, "/usr/bin/curl")
        ),
        None
    );
    // Unlisted, non-ordinary: the top signal names the alert.
    let d = p.decide(
        &flow("198.51.100.7:8443")
            .tls()
            .process(200, "/opt/agent/bin/agent")
            .build(),
        &[],
    );
    let alert = d.alert.unwrap();
    assert_eq!(alert.reason, "raw_ip");
    assert_eq!(d.score, 100); // 60 + 30 + 25, capped
    assert_eq!(
        d.signals,
        vec![
            ("raw_ip".into(), 60),
            ("unusual_port".into(), 30),
            ("new_process".into(), 25)
        ]
    );
    assert_eq!(alert.host, None);
    assert_eq!(alert.score, 100);
}

#[test]
fn spec_8_3_examples_score_as_documented() {
    let (mut p, _) = policy(Mode::Caution, &["api.example.com"]);
    let entropy = p.decide(
        &tls("192.0.2.40:443", "x7qk2v9zr4tplm8w.example.net")
            .process(300, "/tmp/updater")
            .build(),
        &[],
    );
    assert_eq!(entropy.alert.unwrap().reason, "high_entropy");
    assert_eq!(entropy.score, 95); // 50 + 20 + 25

    let (mut p, _) = policy(Mode::Caution, &["api.example.com"]);
    let tld = p.decide(
        &tls("192.0.2.14:443", "shop.example.net")
            .process(500, "/usr/bin/fetch")
            .build(),
        &[],
    );
    assert_eq!(tld.score, 45); // 20 + 25: quiet
    assert!(tld.alert.is_none());

    let (mut p, _) = policy(Mode::Caution, &[]);
    let port = p.decide(
        &tls("192.0.2.13:8080", "tools.example.com")
            .process(400, "/opt/tool/bin/sync")
            .build(),
        &[],
    );
    assert_eq!(port.alert.unwrap().reason, "unusual_port"); // 30 + 25 + 20
}

#[test]
fn caution_prefers_the_score_reason_over_plaintext() {
    let (mut p, _) = policy(Mode::Caution, &[]);
    assert_eq!(
        reason(&mut p, flow("198.51.100.7:8443").plaintext()).as_deref(),
        Some("raw_ip")
    );
}

#[test]
fn alert_mode_alerts_on_unlisted_hosts_and_plaintext() {
    let (mut p, _) = policy(Mode::Alert, &["api.example.com", "public.example.com"]);
    assert_eq!(
        reason(&mut p, tls("192.0.2.10:443", "api.example.com")),
        None
    );
    assert_eq!(
        reason(&mut p, tls("[2001:db8::50]:443", "v6.example.com")).as_deref(),
        Some("unlisted_host")
    );
    // A nameless flow is keyed by IP and still reported as unlisted, not raw_ip.
    let d = p.decide(&flow("192.0.2.60:443").tls().build(), &[]);
    assert_eq!(d.host, "192.0.2.60");
    assert_eq!(d.alert.unwrap().reason, "unlisted_host");
    // An ECH outer name is matched like any name.
    assert_eq!(
        reason(&mut p, tls("192.0.2.12:443", "public.example.com").ech()),
        None
    );
    assert_eq!(
        reason(
            &mut p,
            flow("192.0.2.10:80").host("api.example.com").plaintext()
        )
        .as_deref(),
        Some("plaintext")
    );
}

#[test]
fn learn_ends_after_learn_for_and_switches_mode() {
    let clock = FakeClock::default();
    let config = PolicyConfig {
        learn_for: Some(Duration::from_secs(3600)),
        then: Mode::Caution,
        ..Default::default()
    };
    let mut p = Policy::new(config, Arc::new(clock.clone()));
    assert!(p.learn_until().is_some());
    clock.advance(Duration::from_secs(59 * 60));
    let d = p.decide(&tls("192.0.2.11:443", "cdn.example.com").build(), &[]);
    assert_eq!((d.mode, d.mode_changed), (Mode::Learn, None));
    clock.advance(Duration::from_secs(2 * 60));
    let d = p.decide(&flow("198.51.100.7:8443").plaintext().build(), &[]);
    assert_eq!(d.mode_changed, Some(Mode::Caution));
    assert_eq!(d.alert.unwrap().reason, "raw_ip");
    assert_eq!(d.baseline_add, None);
    assert_eq!(p.mode(), Mode::Caution);
    assert_eq!(p.learn_until(), None);
}

#[test]
fn a_mode_switch_applies_to_the_next_flow() {
    let (mut p, _) = policy(Mode::Learn, &[]);
    p.decide(&tls("192.0.2.10:443", "api.example.com").build(), &[]);
    p.set_mode(Mode::Alert);
    assert_eq!(
        reason(&mut p, tls("192.0.2.10:443", "api.example.com")),
        None
    );
    assert_eq!(
        reason(&mut p, tls("192.0.2.12:443", "docs.example.com")).as_deref(),
        Some("unlisted_host")
    );
}

#[test]
fn alerts_repeat_once_per_window_per_host_and_process() {
    let (mut p, clock) = policy(Mode::Alert, &[]);
    let curl = |pid| tls("192.0.2.12:443", "docs.example.com").process(pid, "/usr/bin/curl");
    assert!(reason(&mut p, curl(100)).is_some());
    clock.advance(Duration::from_secs(30));
    assert!(reason(&mut p, curl(100)).is_none());
    clock.advance(Duration::from_secs(9 * 60 - 30));
    assert!(
        reason(&mut p, curl(101)).is_none(),
        "same process path, other pid"
    );
    let wget = tls("192.0.2.12:443", "docs.example.com").process(102, "/usr/bin/wget");
    assert!(reason(&mut p, wget).is_some(), "other process");
    clock.advance(Duration::from_secs(2 * 60));
    assert!(
        reason(&mut p, curl(103)).is_some(),
        "window counts from the last alert"
    );
}

#[test]
fn acknowledged_alerts_stay_silent() {
    let (mut p, clock) = policy(Mode::Alert, &[]);
    let curl = || tls("192.0.2.12:443", "docs.example.com").process(100, "/usr/bin/curl");
    let alert = p.decide(&curl().build(), &[]).alert.unwrap();
    assert_eq!(alert_key(&alert), "docs.example.com|/usr/bin/curl");
    p.acknowledge(&alert);
    clock.advance(Duration::from_secs(3600));
    assert!(reason(&mut p, curl()).is_none());
    let wget = tls("192.0.2.12:443", "docs.example.com").process(102, "/usr/bin/wget");
    assert!(reason(&mut p, wget).is_some());
}

#[test]
fn a_repeat_with_new_notes_updates_the_earlier_alert() {
    let (mut p, clock) = policy(Mode::Caution, &["plain.example.com"]);
    let first = p
        .decide(
            &flow("192.0.2.20:80")
                .host("plain.example.com")
                .plaintext()
                .build(),
            &[],
        )
        .alert
        .unwrap();
    assert!(first.notes.is_empty());
    clock.advance(Duration::from_secs(1));
    let url = json!("http://plain.example.com/download?id=<redacted>");
    let request = flow("192.0.2.20:80")
        .host("plain.example.com")
        .plaintext()
        .note("url", url.clone())
        .build();
    let d = p.decide(&request, &[]);
    assert!(d.alert.is_none());
    let updated = d.alert_update.unwrap();
    assert_eq!(updated.ts, first.ts);
    assert_eq!(updated.notes.get("url"), Some(&url));
    // The same notes again change nothing.
    assert!(p.decide(&request, &[]).alert_update.is_none());
}

#[test]
fn module_signals_use_their_configured_score() {
    let clock = FakeClock::default();
    let mut config = PolicyConfig {
        mode: Mode::Caution,
        ..Default::default()
    };
    config.scores.modules.insert("tag.large_head".into(), 60);
    let mut p = Policy::new(config, Arc::new(clock));
    let event = tls("192.0.2.21:443", "upload.example.com")
        .process(100, "/usr/bin/curl")
        .build();
    let d = p.decide(&event, &["tag.large_head".into(), "tag.unscored".into()]);
    assert_eq!(d.alert.unwrap().reason, "tag.large_head");
    assert_eq!(d.signals[0], ("tag.large_head".into(), 60));
    assert!(
        d.signals.iter().all(|(r, _)| r != "tag.unscored"),
        "no score: ignored"
    );
}

#[test]
fn threat_lists_match_names_and_ips() {
    let mut threats = ThreatSet::default();
    threats.load(ThreatFormat::Domains, "evil.example.net\n");
    threats.load(ThreatFormat::Ips, "203.0.113.0/24\n");
    let clock = FakeClock::default();
    let config = PolicyConfig {
        mode: Mode::Caution,
        ..Default::default()
    };
    let mut p = Policy::new(config, Arc::new(clock))
        .with_threats(threats)
        .with_baseline(["example.com"]);
    assert_eq!(
        reason(&mut p, tls("198.51.100.66:443", "cdn.evil.example.net")).as_deref(),
        Some("threat_list")
    );
    assert_eq!(
        reason(&mut p, tls("203.0.113.9:443", "fine.example.com")).as_deref(),
        Some("threat_list")
    );
}

#[test]
fn scores_of_zero_disable_signals_and_close_events_are_ignored() {
    let clock = FakeClock::default();
    let mut config = PolicyConfig {
        mode: Mode::Caution,
        ..Default::default()
    };
    config.scores.raw_ip = 0;
    config.scores.unusual_port = 0;
    let mut p = Policy::new(config, Arc::new(clock));
    assert_eq!(reason(&mut p, flow("198.51.100.7:8443").tls()), None);
    let close = p.decide(&flow("198.51.100.7:8443").plaintext().close().build(), &[]);
    assert!(close.alert.is_none() && close.signals.is_empty());
    let quic = p.decide(
        &flow("192.0.2.40:443").host("q.example.com").quic().build(),
        &[],
    );
    assert!(quic.signals.iter().all(|(r, _)| r != "unusual_port"));
    assert_eq!(quic.host, "q.example.com");
}

#[test]
fn a_paused_learn_timer_ends_later_by_the_pause() {
    let clock = FakeClock::default();
    let config = PolicyConfig {
        learn_for: Some(Duration::from_secs(3600)),
        ..Default::default()
    };
    let mut p = Policy::new(config, Arc::new(clock.clone()));
    let end = p.learn_until().unwrap();
    clock.advance(Duration::from_secs(600));
    p.pause_learn_timer();
    clock.advance(Duration::from_secs(1800));
    p.pause_learn_timer(); // a second pause call changes nothing
    p.resume_learn_timer();
    assert_eq!(p.learn_until(), Some(end + Duration::from_secs(1800)));
    p.resume_learn_timer(); // nothing paused: no change
    assert_eq!(p.learn_until(), Some(end + Duration::from_secs(1800)));
}

#[test]
fn keys_turn_back_into_alerts() {
    use scribe_policy::alert_from_key;
    let t = std::time::SystemTime::UNIX_EPOCH;
    for key in [
        "docs.example.com|/usr/bin/curl",
        "198.51.100.7|",
        "2001:db8::1|/opt/a|b",
        "plain.example.com|",
    ] {
        let alert = alert_from_key(key, t);
        assert_eq!(alert_key(&alert), key, "{key}");
        assert_eq!(alert.ts, t);
    }
    let ip = alert_from_key("198.51.100.7|", t);
    assert_eq!((ip.host, ip.process_path), (None, None));
    let piped = alert_from_key("2001:db8::1|/opt/a|b", t);
    assert_eq!(piped.process_path.as_deref(), Some("/opt/a|b"));
}

#[test]
fn restored_states_keep_acknowledgements_and_the_dedupe_window() {
    use scribe_policy::alert_from_key;
    let (mut p, clock) = policy(Mode::Alert, &[]);
    let now = scribe_core::Clock::now(&clock);
    let acked = || tls("192.0.2.12:443", "docs.example.com").process(100, "/usr/bin/curl");
    let recent = || tls("192.0.2.13:443", "api.example.com").process(100, "/usr/bin/curl");
    let old = || tls("192.0.2.14:443", "old.example.com").process(100, "/usr/bin/curl");
    p.restore_alert(
        alert_from_key(
            "docs.example.com|/usr/bin/curl",
            now - Duration::from_secs(86_400),
        ),
        true,
    );
    p.restore_alert(
        alert_from_key(
            "api.example.com|/usr/bin/curl",
            now - Duration::from_secs(60),
        ),
        false,
    );
    p.restore_alert(
        alert_from_key(
            "old.example.com|/usr/bin/curl",
            now - Duration::from_secs(86_400),
        ),
        false,
    );
    assert!(
        reason(&mut p, acked()).is_none(),
        "acknowledged before the restart"
    );
    assert!(
        reason(&mut p, recent()).is_none(),
        "still inside its dedupe window"
    );
    assert!(reason(&mut p, old()).is_some(), "its window has passed");
    clock.advance(Duration::from_secs(86_400));
    assert!(
        reason(&mut p, recent()).is_some(),
        "the window ends as usual"
    );
    assert!(reason(&mut p, acked()).is_none(), "acknowledged for good");
}
