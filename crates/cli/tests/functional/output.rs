//! What `scribe` prints for people.

use std::collections::HashMap;

use scribe_api::pb;
use scribe_cli::output;

const T0: i64 = 1_700_000_000_000; // 2023-11-14T22:13:20Z

#[test]
fn tables_pad_every_column_but_the_last() {
    let text = output::table(
        &["A", "LONG HEADER", "C"],
        &[
            vec!["wide cell".into(), "x".into(), "end".into()],
            vec!["y".into(), "z".into(), "".into()],
        ],
    );
    assert_eq!(
        text,
        "A          LONG HEADER  C\nwide cell  x            end\ny          z\n"
    );
}

#[test]
fn sizes_read_in_binary_units() {
    assert_eq!(output::bytes(0), "0 B");
    assert_eq!(output::bytes(1023), "1023 B");
    assert_eq!(output::bytes(1536), "1.5 KiB");
    assert_eq!(output::bytes(7 * 1024 * 1024), "7.0 MiB");
}

fn status() -> pb::Status {
    pb::Status {
        api_version: 1,
        daemon_version: "0.1.0".into(),
        run_state: "running".into(),
        uptime_s: 93_600,
        config_path: "/etc/scribe/scribe.toml".into(),
        config_loaded_ms: T0,
        mode: "caution".into(),
        profile: "default".into(),
        sensor: Some(pb::Sensor {
            name: "pcap".into(),
            process_info: false,
            health: "fallback".into(),
            fallback: true,
            attribution: None,
        }),
        storage: Some(pb::Storage {
            state: Some(pb::StorageTarget {
                name: "state".into(),
                kind: "sqlite".into(),
                health: "ok".into(),
                detail: String::new(),
            }),
            sinks: vec![pb::StorageTarget {
                name: "central".into(),
                kind: "postgres".into(),
                health: "degraded".into(),
                detail: "spooling 1204 events (90000 bytes)".into(),
            }],
        }),
        counters_since_ms: T0,
        counters: Some(pb::Counters {
            flows: 18_342,
            flows_per_s: 2.4,
            events_per_s: 2.6,
            alerts: 2,
            new_hosts: 1,
            ..Default::default()
        }),
        critical: vec![pb::Critical {
            kind: "fallback_sensor".into(),
            detail: "pcap sensor in use: no process info".into(),
        }],
        modules: vec![
            pb::Module {
                id: "url".into(),
                version: 1,
                enabled: true,
                state: "running".into(),
                health: "ok".into(),
                ..Default::default()
            },
            pb::Module {
                id: "kperf".into(),
                version: 1,
                ..Default::default()
            },
        ],
        ..Default::default()
    }
}

#[test]
fn status_lists_critical_metrics_first() {
    let text = output::status(&status(), false);
    let lines: Vec<&str> = text.lines().collect();
    assert_eq!(lines[0], "scribed 0.1.0 (API 1): running, up 1d 2h");
    assert_eq!(
        lines[1],
        "! fallback_sensor: pcap sensor in use: no process info"
    );
    assert_eq!(lines[2], "mode       caution, profile default");
    for part in [
        "sensor     pcap, no process info, fallback",
        "config     /etc/scribe/scribe.toml, loaded 2023-11-14T22:13:20Z",
        "18342 flows (2.4/s), 2.6 events/s, 2 alerts, 1 new host",
        "storage    state: sqlite ok",
        "           sink central: postgres degraded (spooling 1204 events (90000 bytes))",
        "modules    url 1: running, ok",
        "           kperf 1: not enabled",
    ] {
        assert!(text.contains(part), "{part:?} missing in\n{text}");
    }
    let colored = output::status(&status(), true);
    assert!(colored.contains("\x1b[1;31m! fallback_sensor"), "{colored}");
}

#[test]
fn attribution_shows_the_hit_rate_and_table_reads() {
    let mut s = status();
    s.sensor = Some(pb::Sensor {
        name: "pcap+sockets".into(),
        process_info: true,
        health: "ok".into(),
        fallback: false,
        attribution: Some(pb::Attribution {
            attributed: 940,
            missed: 60,
            scans: 52,
            slow_scans: 0,
            last_scan_s: 0.003,
            max_scan_s: 0.012,
        }),
    });
    let text = output::status(&s, false);
    assert!(
        text.contains("process    940 of 1000 new flows (94%); socket table: 52 reads, last 3 ms, max 12 ms\n"),
        "{text}"
    );
    let native = pb::Attribution {
        attributed: 2,
        missed: 0,
        ..Default::default()
    };
    assert_eq!(
        output::attribution(&native),
        "2 of 2 new flows (100%)",
        "a native sensor reads no socket table"
    );
    let slow = pb::Attribution {
        attributed: 0,
        missed: 0,
        scans: 3,
        slow_scans: 2,
        last_scan_s: 0.08,
        max_scan_s: 0.12,
    };
    assert_eq!(
        output::attribution(&slow),
        "no new flows yet; socket table: 3 reads, last 80 ms, max 120 ms, 2 over budget"
    );
    assert!(!output::status(&status(), false).contains("process    "));
}

#[test]
fn hibernation_shows_since_until_and_who() {
    let s = pb::Status {
        run_state: "hibernating".into(),
        hibernating_since_ms: Some(T0),
        hibernating_until_ms: Some(T0 + 1_800_000),
        hibernated_by: "alice (uid 1000, pid 4242)".into(),
        ..status()
    };
    let text = output::status(&s, false);
    assert!(
        text.contains("hibernate  since 2023-11-14T22:13:20Z until 2023-11-14T22:43:20Z, by alice (uid 1000, pid 4242)"),
        "{text}"
    );
    assert_eq!(
        output::run_state(&s),
        "hibernating since 2023-11-14T22:13:20Z until 2023-11-14T22:43:20Z\n"
    );
    assert_eq!(output::run_state(&status()), "running\n");
}

#[test]
fn health_reads_as_one_line() {
    use pb::health_reply::Level;
    let reply = |level: Level, reasons: &[&str]| pb::HealthReply {
        level: level as i32,
        reasons: reasons.iter().map(|r| (*r).to_owned()).collect(),
    };
    assert_eq!(output::health(&reply(Level::Healthy, &[])), "healthy");
    assert_eq!(
        output::health(&reply(Level::Degraded, &["a", "b"])),
        "degraded: a; b"
    );
    assert_eq!(
        output::health(&reply(Level::Unspecified, &["x"])),
        "unhealthy: x"
    );
    assert_eq!(
        output::health_json("degraded", &["a".into()]).to_string(),
        r#"{"level":"degraded","reasons":["a"]}"#
    );
}

#[test]
fn hosts_show_counters_flags_and_processes() {
    let page = pb::HostPage {
        items: vec![pb::Host {
            name: "api.example.com".into(),
            on_list: true,
            last_seen_ms: T0,
            conn_count: 1532,
            bytes_out: 7 * 1024 * 1024,
            tls_seen: true,
            processes: vec!["/usr/bin/curl".into()],
            ..Default::default()
        }],
        total: Some(1),
    };
    let text = output::hosts(&page);
    let row = text.lines().nth(1).unwrap();
    for part in [
        "api.example.com",
        "1532",
        "7.0 MiB",
        "tls",
        "2023-11-14T22:13:20Z",
        "listed",
        "/usr/bin/curl",
    ] {
        assert!(row.contains(part), "{part:?} in {row:?}");
    }
    assert!(text.ends_with("1 host\n"), "{text}");
}

#[test]
fn alerts_carry_their_notes_below() {
    let page = pb::AlertPage {
        items: vec![pb::Alert {
            id: 2,
            ts_ms: T0,
            host: None,
            dst: "198.51.100.7:8443".into(),
            process_path: Some("/opt/agent/bin/agent".into()),
            score: 80,
            reason: "raw_ip".into(),
            acknowledged: false,
            notes: HashMap::from([("url".to_owned(), "http://198.51.100.7:8443/x".to_owned())]),
        }],
        total: Some(1),
    };
    let text = output::alerts(&page);
    let lines: Vec<&str> = text.lines().collect();
    assert!(lines[0].starts_with("ID  TIME"), "{text}");
    assert!(
        lines[1].starts_with("2   2023-11-14T22:13:20Z  80"),
        "{text}"
    );
    assert!(
        lines[1].contains("raw_ip") && lines[1].ends_with("no"),
        "{text}"
    );
    assert_eq!(lines[2], "    url: http://198.51.100.7:8443/x");
    assert_eq!(output::alerts(&pb::AlertPage::default()), "no alerts\n");
}

#[test]
fn baseline_edits_and_resets_say_what_changed() {
    let b = pb::Baseline {
        profile: "work".into(),
        entries: vec![pb::BaselineEntry {
            host: "api.example.com".into(),
            source: "manual".into(),
            added_at_ms: T0,
        }],
    };
    let text = output::baseline(&b);
    assert!(text.starts_with("profile work: 1 host\nHOST"), "{text}");
    assert!(
        text.contains("api.example.com  manual  2023-11-14T22:13:20Z"),
        "{text}"
    );
    let edit = pb::EditBaselineReply {
        added: vec!["a.example.com".into()],
        removed: vec![],
        unchanged: vec!["b.example.net".into()],
    };
    assert_eq!(
        output::edit(&edit),
        "added: a.example.com\nunchanged: b.example.net\n"
    );
    let reset = pb::ResetReply {
        done: vec!["config".into(), "counters".into()],
        applied: vec!["mode".into()],
        needs_restart: vec!["sensor".into()],
        status: None,
    };
    assert_eq!(
        output::reset(&reset),
        "reset: config, counters\nconfig applied: mode\nneeds a restart: sensor\n"
    );
}

#[test]
fn modules_list_every_built_module() {
    let list = pb::ModuleList {
        items: status().modules,
    };
    let text = output::modules(&list);
    assert!(
        text.lines()
            .nth(1)
            .unwrap()
            .starts_with("url     1        yes      running  ok"),
        "{text}"
    );
    assert!(text.contains("kperf   1        no"), "{text}");
}

#[test]
fn the_audit_report_names_each_problem() {
    let intact = pb::AuditReport {
        records: 42,
        first_seq: 1,
        last_seq: 42,
        sealed_seq: 42,
        problems: vec![],
    };
    assert_eq!(
        output::audit(&intact),
        "audit chain intact: 42 records, sequence 1 to 42 (last sealed 42)\n"
    );
    let problem = |kind: &str, seq, next| pb::AuditProblem {
        kind: kind.into(),
        seq,
        next,
    };
    let broken = pb::AuditReport {
        records: 40,
        first_seq: 5,
        last_seq: 44,
        sealed_seq: 46,
        problems: vec![
            problem("gap", 12, 15),
            problem("mismatch", 20, 0),
            problem("unlinked", 0, 0),
            problem("missing_tail", 44, 46),
        ],
    };
    assert_eq!(
        output::audit(&broken),
        "audit chain broken: 4 problems (40 records stored, sequence 5 to 44, last sealed 46)\n\
         \x20 gap: records 13 to 14 are missing\n\
         \x20 mismatch: record 20 doesn't carry the HMAC of record 19 (one of them was changed)\n\
         \x20 unlinked: a record without a chain link\n\
         \x20 missing tail: records 45 to 46 were sealed but are not stored\n\
         records before 5 are not stored (retention removes old records)\n"
    );
}

#[test]
fn hourly_counters_end_with_totals() {
    let hours = pb::HostHours {
        host: "api.example.com".into(),
        items: vec![
            pb::HostHour {
                hour_ms: 1_700_002_800_000,
                conn_count: 3,
                req_count: 0,
                bytes_out: 1536,
            },
            pb::HostHour {
                hour_ms: 1_700_006_400_000,
                conn_count: 1,
                req_count: 2,
                bytes_out: 512,
            },
        ],
    };
    assert_eq!(
        output::host_hours(&hours),
        "api.example.com\n\
         HOUR (UTC)            CONNS  REQUESTS  SENT\n\
         2023-11-14T23:00:00Z  3      0         1.5 KiB\n\
         2023-11-15T00:00:00Z  1      2         512 B\n\
         api.example.com over 2 hours: 4 connections, 2 requests, 2.0 KiB sent\n"
    );
    let empty = pb::HostHours {
        host: "quiet.example".into(),
        items: vec![],
    };
    assert_eq!(
        output::host_hours(&empty),
        "quiet.example: no traffic counted in this period\n"
    );
}
