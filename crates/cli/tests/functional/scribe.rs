//! Runs the real `scribe` binary without a daemon.

use std::process::Command;

const SCRIBE: &str = env!("CARGO_BIN_EXE_scribe");

fn run(args: &[&str], socket: &str) -> (Option<i32>, String, String) {
    let out = Command::new(SCRIBE)
        .args(args)
        .env("SCRIBE_SOCKET", socket)
        .output()
        .unwrap();
    (
        out.status.code(),
        String::from_utf8_lossy(&out.stdout).into_owned(),
        String::from_utf8_lossy(&out.stderr).into_owned(),
    )
}

#[test]
fn an_absent_daemon_is_reported_with_exit_1() {
    let dir = tempfile::tempdir().unwrap();
    let socket = dir.path().join("api.sock");
    let socket = socket.to_str().unwrap();
    for args in [
        &["status"][..],
        &["hosts"],
        &["mode", "caution"],
        &["alerts"],
        &["daemon", "wakeup"],
    ] {
        let (code, _, stderr) = run(args, socket);
        assert_eq!(code, Some(1), "{args:?}: {stderr}");
        assert!(
            stderr.contains("scribed is not running or its socket is not reachable"),
            "{args:?}: {stderr}"
        );
        assert!(stderr.contains(socket), "{stderr}");
    }
}

#[test]
fn health_prints_unhealthy_and_exits_1_when_unreachable() {
    let dir = tempfile::tempdir().unwrap();
    let socket = dir.path().join("api.sock");
    let (code, stdout, _) = run(&["daemon", "health"], socket.to_str().unwrap());
    assert_eq!(code, Some(1));
    assert!(
        stdout.starts_with("unhealthy: scribed is not running"),
        "{stdout}"
    );
    let (code, stdout, _) = run(&["daemon", "health", "--json"], socket.to_str().unwrap());
    assert_eq!(code, Some(1));
    let value: serde_json::Value = serde_json::from_str(&stdout).unwrap();
    assert_eq!(value["level"], "unhealthy");
}

#[cfg(unix)]
#[test]
fn a_file_that_is_not_a_socket_is_refused() {
    let dir = tempfile::tempdir().unwrap();
    let fake = dir.path().join("api.sock");
    std::fs::write(&fake, "").unwrap();
    let (code, _, stderr) = run(&["status"], fake.to_str().unwrap());
    assert_eq!(code, Some(1));
    assert!(
        stderr.contains("is not a socket; refusing to talk to it"),
        "{stderr}"
    );
}

#[test]
fn usage_errors_exit_with_2() {
    for args in [&[][..], &["frobnicate"], &["mode", "paranoid"]] {
        let (code, _, stderr) = run(args, "/nonexistent/api.sock");
        assert_eq!(code, Some(2), "{args:?}: {stderr}");
    }
    let (_, _, stderr) = run(&["mode", "paranoid"], "/nonexistent/api.sock");
    assert!(stderr.contains("unknown mode 'paranoid'"), "{stderr}");
}
