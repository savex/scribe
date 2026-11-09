//! Runs the real `scribed` binary.

use std::path::{Path, PathBuf};
use std::process::{Command, Output};

const SCRIBED: &str = env!("CARGO_BIN_EXE_scribed");

fn shipped_config() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("../../config/scribe.toml")
}

fn scribed(args: &[&str]) -> Command {
    let mut cmd = Command::new(SCRIBED);
    cmd.args(args)
        .env_remove("SCRIBE_CONFIG")
        .env_remove("SCRIBE_LOG");
    cmd
}

fn text(bytes: &[u8]) -> String {
    String::from_utf8_lossy(bytes).into_owned()
}

/// A config that keeps everything inside `dir` and logs to `dir/scribed.log`.
fn write_config(dir: &Path, extra: &str) -> PathBuf {
    let path = dir.join("scribe.toml");
    let config = format!(
        "data_dir = '{data}'\n{extra}\n[log]\nfile = '{log}'\nrotate = 'size'\n",
        data = dir.join("data").display(),
        log = dir.join("scribed.log").display(),
    );
    std::fs::write(&path, config).unwrap();
    path
}

fn assert_exit(output: &Output, code: i32) {
    assert_eq!(
        output.status.code(),
        Some(code),
        "stdout: {}\nstderr: {}",
        text(&output.stdout),
        text(&output.stderr)
    );
}

#[test]
fn prints_its_version() {
    for flag in ["--version", "-V"] {
        let out = scribed(&[flag]).output().unwrap();
        assert_exit(&out, 0);
        assert_eq!(
            text(&out.stdout),
            format!("scribed {}\n", scribe_core::VERSION)
        );
    }
}

/// The shipped file configures the URL module, so it needs a build with it.
#[cfg(feature = "url")]
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

#[cfg(feature = "url")]
#[test]
fn warns_about_the_deprecated_url_query() {
    let dir = tempfile::tempdir().unwrap();
    let path = write_config(dir.path(), "[privacy]\nurl_query = \"strip\"");
    let out = scribed(&["--check-config", "--config", path.to_str().unwrap()])
        .output()
        .unwrap();
    assert_exit(&out, 0);
    let stdout = text(&out.stdout);
    assert!(
        stdout.contains("# warning: privacy.url_query is deprecated"),
        "{stdout}"
    );
    assert!(stdout.contains("query = \"strip\""), "{stdout}");
}

#[test]
fn rejects_an_unknown_module() {
    let dir = tempfile::tempdir().unwrap();
    let path = write_config(dir.path(), "[modules]\nenabled = [\"kperf\"]");
    let out = scribed(&["--check-config", "--config", path.to_str().unwrap()])
        .output()
        .unwrap();
    assert_exit(&out, 2);
    let stderr = text(&out.stderr);
    assert!(stderr.contains("module \"kperf\" is not built"), "{stderr}");
    assert!(stderr.contains("line 3"), "{stderr}");
}

#[test]
fn rejects_a_bad_config_with_its_line() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("bad.toml");
    std::fs::write(&path, "mode = \"learn\"\nthreshold = 70\n").unwrap();
    let out = scribed(&["--check-config", "--config", path.to_str().unwrap()])
        .output()
        .unwrap();
    assert_exit(&out, 2);
    let stderr = text(&out.stderr);
    assert!(stderr.contains("line 2"), "{stderr}");
    assert!(stderr.contains("unknown field `threshold`"), "{stderr}");
}

#[test]
fn a_named_config_must_exist() {
    let out = scribed(&["--config", "/nonexistent/scribe.toml"])
        .output()
        .unwrap();
    assert_exit(&out, 2);
    assert!(text(&out.stderr).contains("named by --config"));
}

#[test]
fn reads_scribe_config_from_the_environment() {
    let dir = tempfile::tempdir().unwrap();
    let path = write_config(dir.path(), "profile = 'from-env'");
    let out = scribed(&["--check-config"])
        .env("SCRIBE_CONFIG", &path)
        .output()
        .unwrap();
    assert_exit(&out, 0);
    assert!(text(&out.stdout).contains("profile = \"from-env\""));
}

#[test]
fn usage_errors_exit_with_2() {
    let out = scribed(&["--bogus"]).output().unwrap();
    assert_exit(&out, 2);
}

#[test]
fn rejects_a_bad_log_filter() {
    let dir = tempfile::tempdir().unwrap();
    let path = write_config(dir.path(), "");
    let out = scribed(&["--config", path.to_str().unwrap()])
        .env("SCRIBE_LOG", "scribed=loud")
        .output()
        .unwrap();
    assert_exit(&out, 2);
    assert!(text(&out.stderr).contains("invalid log filter"));
}

#[cfg(unix)]
#[test]
fn runs_until_sigterm_and_stops_cleanly() {
    use std::time::{Duration, Instant};

    let dir = tempfile::tempdir().unwrap();
    let path = write_config(dir.path(), "");
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
        "storage backend is not implemented yet",
        "stop signal received",
        "scribed stopped",
    ] {
        assert!(log.contains(expected), "missing {expected:?} in:\n{log}");
    }
    #[cfg(feature = "url")]
    for expected in ["modules: url", "module url started", "module url stopped"] {
        assert!(log.contains(expected), "missing {expected:?} in:\n{log}");
    }
    assert!(dir.path().join("data").join("spool").is_dir());
}
