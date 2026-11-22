//! The real `scribed` and `scribe` start, report their version and run.

use std::process::Command;

use scribe_tests::{assert_exit, shipped_config, text};

const SCRIBED: &str = env!("CARGO_BIN_EXE_scribed-under-test");
const SCRIBE: &str = env!("CARGO_BIN_EXE_scribe-under-test");

fn scribed(args: &[&str]) -> Command {
    let mut cmd = Command::new(SCRIBED);
    cmd.args(args)
        .env_remove("SCRIBE_CONFIG")
        .env_remove("SCRIBE_LOG");
    cmd
}

#[test]
fn scribed_prints_its_version() {
    for flag in ["--version", "-V"] {
        let out = scribed(&[flag]).output().unwrap();
        assert_exit(&out, 0);
        assert_eq!(
            text(&out.stdout),
            format!("scribed {}\n", scribe_core::VERSION)
        );
    }
}

#[test]
fn scribe_prints_its_version() {
    let expected = format!("scribe {}\n", scribe_core::VERSION);
    for args in [&["--version"][..], &["-V"], &["version"]] {
        let out = Command::new(SCRIBE).args(args).output().unwrap();
        assert_exit(&out, 0);
        assert_eq!(text(&out.stdout), expected, "{args:?}");
    }
}

#[test]
fn cli_definition_is_valid() {
    use clap::CommandFactory;
    scribe_cli::Cli::command().debug_assert();
}

#[test]
fn checks_the_shipped_config() {
    let out = scribed(&[
        "--check-config",
        "--config",
        shipped_config().to_str().unwrap(),
    ])
    .output()
    .unwrap();
    assert_exit(&out, 0);
    let stdout = text(&out.stdout);
    assert!(
        stdout.starts_with("# Effective scribed configuration"),
        "{stdout}"
    );
    assert!(stdout.contains("mode = \"learn\""), "{stdout}");
    assert!(
        stdout.contains("[modules]\nenabled = [\"url\"]"),
        "{stdout}"
    );
    assert!(
        stdout.contains("[modules.url]\nquery = \"redact_values\""),
        "{stdout}"
    );
}

#[cfg(unix)]
#[test]
fn runs_until_sigterm_and_stops_cleanly() {
    use std::time::{Duration, Instant};

    let dir = tempfile::tempdir().unwrap();
    let path = scribe_tests::write_config(dir.path(), "");
    let log = dir.path().join("scribed.log");
    let mut child = scribed(&["--config", path.to_str().unwrap()])
        .spawn()
        .unwrap();

    let deadline = Instant::now() + Duration::from_secs(15);
    while !std::fs::read_to_string(&log)
        .unwrap_or_default()
        .contains("waiting for a stop signal")
    {
        assert!(Instant::now() < deadline, "scribed did not start");
        assert!(child.try_wait().unwrap().is_none(), "scribed exited early");
        std::thread::sleep(Duration::from_millis(50));
    }

    let killed = Command::new("kill")
        .args(["-TERM", &child.id().to_string()])
        .status()
        .unwrap();
    assert!(killed.success());
    let status = child.wait().unwrap();
    assert_eq!(status.code(), Some(0));

    let log = std::fs::read_to_string(&log).unwrap();
    for expected in [
        "scribed starting",
        "data dir: ",
        "storage ready",
        "modules: url",
        "module url started",
        "stop signal received",
        "module url stopped",
        "scribed stopped",
    ] {
        assert!(log.contains(expected), "missing {expected:?} in:\n{log}");
    }
    assert!(dir.path().join("data").join("spool").is_dir());
    for db in ["state.db", "events.db"] {
        assert!(
            dir.path().join("data").join(db).is_file(),
            "{db} was not created"
        );
    }
}
