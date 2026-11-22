//! Runs the real `scribed` binary.

use std::path::{Path, PathBuf};
use std::process::{Command, Output};

const SCRIBED: &str = env!("CARGO_BIN_EXE_scribed");

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
