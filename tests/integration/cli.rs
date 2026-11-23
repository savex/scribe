//! INT-12: the real `scribe` binary against a running daemon (the API helpers from `api.rs`).

use std::path::Path;
use std::process::Output;

use crate::api::{is_root, my_admin_group, two_flows, Daemon};
use scribe_api::pb;

const SCRIBE: &str = env!("CARGO_BIN_EXE_scribe-under-test");

/// Runs `scribe` against `socket` off the async runtime.
async fn scribe(socket: &Path, args: &[&str]) -> Output {
    let socket = socket.to_owned();
    let args: Vec<String> = args.iter().map(|a| (*a).to_owned()).collect();
    tokio::task::spawn_blocking(move || {
        std::process::Command::new(SCRIBE)
            .args(&args)
            .env("SCRIBE_SOCKET", &socket)
            .output()
            .unwrap()
    })
    .await
    .unwrap()
}

fn text(bytes: &[u8]) -> String {
    String::from_utf8_lossy(bytes).into_owned()
}

/// Asserts the exit code and returns stdout.
fn ok(out: &Output, code: i32) -> String {
    assert_eq!(
        out.status.code(),
        Some(code),
        "stdout: {}\nstderr: {}",
        text(&out.stdout),
        text(&out.stderr)
    );
    text(&out.stdout)
}

#[tokio::test(flavor = "multi_thread")]
async fn every_command_works_against_a_running_daemon() {
    let daemon = Daemon::start_with("caution", &my_admin_group(), two_flows()).await;
    let s = daemon.socket.clone();
    // Let both flows and the alert reach storage.
    crate::api::eventually(
        || async { text(&scribe(&s, &["alerts"]).await.stdout) },
        |out| out.contains("raw_ip"),
    )
    .await;

    let status = ok(&scribe(&s, &["status"]).await, 0);
    assert!(status.contains("(API 1): running, up "), "{status}");
    assert!(
        status.contains("mode       caution, profile default"),
        "{status}"
    );
    let daemon_status = ok(&scribe(&s, &["daemon", "status"]).await, 0);
    assert_eq!(
        daemon_status.lines().next(),
        status.lines().next(),
        "scribe status is the short form"
    );
    let json: serde_json::Value =
        serde_json::from_str(&ok(&scribe(&s, &["status", "--json"]).await, 0)).unwrap();
    assert_eq!(json["api_version"], 1);
    assert_eq!(json["counters"]["flows"], 2);

    let hosts = ok(&scribe(&s, &["hosts"]).await, 0);
    assert!(
        hosts.contains("api.example.com") && hosts.contains("/usr/bin/curl"),
        "{hosts}"
    );
    assert!(hosts.ends_with("2 hosts\n"), "{hosts}");
    let filtered: serde_json::Value = serde_json::from_str(&ok(
        &scribe(&s, &["hosts", "--filter", "198.51", "--json"]).await,
        0,
    ))
    .unwrap();
    assert_eq!(filtered["items"][0]["name"], "198.51.100.7");
    assert_eq!(filtered["items"][0]["unresolved"], true);

    let alerts: serde_json::Value =
        serde_json::from_str(&ok(&scribe(&s, &["alerts", "--json"]).await, 0)).unwrap();
    let id = alerts["items"][0]["id"].as_u64().unwrap().to_string();
    let acked = ok(&scribe(&s, &["alerts", "ack", &id]).await, 0);
    assert_eq!(acked, format!("alert {id} acknowledged\n"));
    let again = ok(&scribe(&s, &["alerts", "ack", &id]).await, 0);
    assert_eq!(again, format!("alert {id} was already acknowledged\n"));
    let missing = scribe(&s, &["alerts", "ack", "999999"]).await;
    ok(&missing, 1);
    assert!(
        text(&missing.stderr).contains("no alert 999999"),
        "{}",
        text(&missing.stderr)
    );

    let mode = ok(&scribe(&s, &["mode", "alert"]).await, 0);
    assert_eq!(mode, "mode: caution -> alert\n");

    let added = ok(
        &scribe(
            &s,
            &["baseline", "add", "api.example.com", "docs.example.net"],
        )
        .await,
        0,
    );
    assert_eq!(added, "added: api.example.com, docs.example.net\n");
    let removed = ok(
        &scribe(&s, &["baseline", "rm", "docs.example.net"]).await,
        0,
    );
    assert_eq!(removed, "removed: docs.example.net\n");
    let baseline = ok(&scribe(&s, &["baseline"]).await, 0);
    assert!(
        baseline.starts_with("profile default: 1 host\n"),
        "{baseline}"
    );
    assert!(baseline.contains("api.example.com  manual"), "{baseline}");

    let file = daemon.dir.path().join("export.json");
    let exported = scribe(&s, &["export", "-o", file.to_str().unwrap()]).await;
    ok(&exported, 0);
    assert!(
        text(&exported.stderr).contains("exported 2 hosts and 1 baseline entries"),
        "{}",
        text(&exported.stderr)
    );
    let doc: serde_json::Value =
        serde_json::from_str(&std::fs::read_to_string(&file).unwrap()).unwrap();
    assert_eq!(doc["hosts"].as_array().unwrap().len(), 2);
    assert_eq!(doc["baseline"][0]["host"], "api.example.com");
    {
        use std::os::unix::fs::PermissionsExt;
        let mode = std::fs::metadata(&file).unwrap().permissions().mode();
        assert_eq!(mode & 0o777, 0o600, "the export is private to its writer");
    }

    let modules = ok(&scribe(&s, &["modules"]).await, 0);
    assert!(
        modules.lines().nth(1).unwrap().starts_with("url "),
        "{modules}"
    );

    assert_eq!(ok(&scribe(&s, &["daemon", "health"]).await, 0), "healthy\n");
    let hibernating = ok(&scribe(&s, &["daemon", "sleep", "--for", "10m"]).await, 0);
    assert!(
        hibernating.starts_with("hibernating since "),
        "{hibernating}"
    );
    let health = ok(&scribe(&s, &["daemon", "health"]).await, 0);
    assert!(
        health.starts_with("degraded: hibernating since "),
        "{health}"
    );
    assert_eq!(ok(&scribe(&s, &["daemon", "wake"]).await, 0), "running\n");
    let reset = ok(&scribe(&s, &["daemon", "reset", "--counters"]).await, 0);
    assert_eq!(reset, "reset: counters\n");
    let reload = ok(&scribe(&s, &["daemon", "reset", "--config"]).await, 0);
    assert!(
        reload.starts_with("reset: config\nconfig applied: "),
        "{reload}"
    );

    daemon.stop().await;
    let gone = scribe(&s, &["status"]).await;
    ok(&gone, 1);
    assert!(
        text(&gone.stderr).contains("scribed is not running or its socket is not reachable"),
        "{}",
        text(&gone.stderr)
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn control_commands_outside_the_admin_group_exit_1() {
    let daemon = Daemon::start_with(
        "caution",
        "[api]\nadmin_group = 'scribe-test-no-such-group'",
        vec![],
    )
    .await;
    let s = daemon.socket.clone();
    let out = scribe(&s, &["daemon", "hibernate"]).await;
    if is_root() {
        ok(&out, 0);
    } else {
        ok(&out, 1);
        let stderr = text(&out.stderr);
        assert!(
            stderr.starts_with("scribe: permission denied: "),
            "{stderr}"
        );
        assert!(stderr.contains("scribe-test-no-such-group"), "{stderr}");
        ok(&scribe(&s, &["status"]).await, 0);
    }
    daemon.stop().await;
}

#[tokio::test(flavor = "multi_thread")]
async fn audit_verify_finds_deleted_and_edited_records() {
    let daemon = Daemon::start_with("caution", &my_admin_group(), vec![]).await;
    let s = daemon.socket.clone();
    // start (1), hibernate (2) + its alert (3), wakeup (4), reset (5)
    ok(
        &scribe(&s, &["daemon", "hibernate", "--for", "1m"]).await,
        0,
    );
    ok(&scribe(&s, &["daemon", "wakeup"]).await, 0);
    ok(&scribe(&s, &["daemon", "reset", "--counters"]).await, 0);
    let intact = ok(&scribe(&s, &["audit", "verify"]).await, 0);
    assert_eq!(
        intact,
        "audit chain intact: 5 records, sequence 1 to 5 (last sealed 5)\n"
    );
    let dir = daemon.stop().await;

    {
        let db = rusqlite::Connection::open(dir.path().join("events.db")).unwrap();
        // Drop the hibernate audit (2) and change the reset audit (5).
        db.execute(
            "DELETE FROM events WHERE id = (SELECT id FROM events WHERE kind = 'audit' AND payload LIKE '%hibernate by%')",
            [],
        )
        .unwrap();
        let changed = db
            .execute(
                "UPDATE events SET payload = replace(payload, 'runtime reset by', 'runtime reset for') WHERE kind = 'audit'",
                [],
            )
            .unwrap();
        assert!(changed > 0);
    }

    let daemon = Daemon::start_in(dir, "caution", &my_admin_group(), vec![]).await;
    let s = daemon.socket.clone();
    let out = scribe(&s, &["audit", "verify"]).await;
    let report = ok(&out, 1);
    assert!(
        report.starts_with("audit chain broken: 2 problems"),
        "{report}"
    );
    assert!(
        report.contains("gap: records 2 to 2 are missing"),
        "{report}"
    );
    assert!(
        report.contains("mismatch: record 6 doesn't carry the HMAC of record 5"),
        "the record after the edited one no longer matches: {report}"
    );
    let json: serde_json::Value =
        serde_json::from_str(&ok(&scribe(&s, &["audit", "verify", "--json"]).await, 1)).unwrap();
    assert_eq!(json["problems"].as_array().unwrap().len(), 2);
    let mut client = daemon.client().await;
    let direct = client
        .verify_audit(pb::VerifyAuditRequest {})
        .await
        .unwrap()
        .into_inner();
    assert_eq!(direct.problems[0].kind, "gap");
    daemon.stop().await;
}
