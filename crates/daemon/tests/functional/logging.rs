//! Functional tests for `scribe_daemon::logging` (moved from `src/logging.rs`).

use scribe_daemon::config::{LogFormat, LogSettings, Rotate};
use scribe_daemon::config::{LogLevel, LogOutput};
use scribe_daemon::logging::*;
use std::fs::{self};
use std::io::Write;
use std::path::{Path, PathBuf};

fn settings(file: Option<PathBuf>) -> LogSettings {
    LogSettings {
        level: LogLevel::Info,
        format: LogFormat::Text,
        output: LogOutput::File,
        file,
        rotate: Rotate::Size,
        max_size: 1 << 20,
        keep: 2,
    }
}

/// Logs through `s`, drops the logger to flush it, and returns all text written under `dir`.
fn log_and_read(s: &LogSettings, filter: Option<&str>, dir: &Path) -> (String, Vec<String>) {
    let setup = build(s, filter).unwrap();
    tracing::dispatcher::with_default(&setup.dispatch, || {
        tracing::debug!("debug line");
        tracing::info!(host = "api.example.com", "info line");
        tracing::warn!("warn line");
    });
    let warnings = setup.warnings.clone();
    drop(setup);
    let mut text = String::new();
    for entry in fs::read_dir(dir).unwrap() {
        let path = entry.unwrap().path();
        if path.is_file() {
            text.push_str(&fs::read_to_string(path).unwrap());
        }
    }
    (text, warnings)
}

#[test]
fn writes_text_at_the_configured_level() {
    let dir = tempfile::tempdir().unwrap();
    let s = settings(Some(dir.path().join("scribed.log")));
    let (text, warnings) = log_and_read(&s, None, dir.path());
    assert!(warnings.is_empty(), "{warnings:?}");
    assert!(
        text.contains("info line") && text.contains("api.example.com"),
        "{text}"
    );
    assert!(text.contains("warn line"));
    assert!(!text.contains("debug line"));
    assert!(!text.contains('\u{1b}'), "no colour codes in files");
}

#[test]
fn filter_override_wins() {
    let dir = tempfile::tempdir().unwrap();
    let s = settings(Some(dir.path().join("scribed.log")));
    let (text, _) = log_and_read(&s, Some("debug"), dir.path());
    assert!(text.contains("debug line"), "{text}");

    let dir = tempfile::tempdir().unwrap();
    let s = settings(Some(dir.path().join("scribed.log")));
    let (text, _) = log_and_read(&s, Some("warn"), dir.path());
    assert!(
        text.contains("warn line") && !text.contains("info line"),
        "{text}"
    );
}

#[test]
fn rejects_bad_filters() {
    let Err(err) = build(&settings(None), Some("scribed=loud")) else {
        panic!("the filter should be rejected");
    };
    assert!(
        err.to_string()
            .contains("invalid log filter \"scribed=loud\""),
        "{err}"
    );
}

#[test]
fn writes_json_lines() {
    let dir = tempfile::tempdir().unwrap();
    let mut s = settings(Some(dir.path().join("scribed.log")));
    s.format = LogFormat::Json;
    let (text, _) = log_and_read(&s, None, dir.path());
    let line = text.lines().find(|l| l.contains("info line")).unwrap();
    assert!(line.starts_with('{') && line.ends_with('}'), "{line}");
    assert!(line.contains("\"level\":\"INFO\""), "{line}");
    assert!(line.contains("\"host\":\"api.example.com\""), "{line}");
}

#[test]
fn daily_rotation_writes_dated_files() {
    let dir = tempfile::tempdir().unwrap();
    let mut s = settings(Some(dir.path().join("logs").join("scribed.log")));
    s.rotate = Rotate::Daily;
    let (text, warnings) = log_and_read(&s, None, &dir.path().join("logs"));
    assert!(warnings.is_empty(), "{warnings:?}");
    assert!(text.contains("info line"), "{text}");
    let names: Vec<String> = fs::read_dir(dir.path().join("logs"))
        .unwrap()
        .map(|e| e.unwrap().file_name().to_string_lossy().into_owned())
        .collect();
    assert!(
        names
            .iter()
            .any(|n| n.starts_with("scribed.") && n.ends_with(".log") && n != "scribed.log"),
        "{names:?}"
    );
}

#[test]
fn falls_back_to_stderr_when_the_file_cannot_be_written() {
    let dir = tempfile::tempdir().unwrap();
    let blocker = dir.path().join("not-a-dir");
    fs::write(&blocker, "").unwrap();
    let s = settings(Some(blocker.join("scribed.log")));
    let setup = build(&s, None).unwrap();
    assert_eq!(setup.warnings.len(), 1);
    assert!(
        setup.warnings[0].contains("logging to stderr instead"),
        "{:?}",
        setup.warnings
    );
}

#[test]
fn stderr_only_and_system_outputs_build() {
    assert!(build(&settings(None), None).unwrap().warnings.is_empty());

    let mut s = settings(None);
    s.output = LogOutput::System;
    let setup = build(&s, None).unwrap();
    // journald may be missing (containers, CI); then there is exactly one warning.
    assert!(setup.warnings.len() <= 1, "{:?}", setup.warnings);
}

#[test]
fn size_rotation_keeps_the_newest_files() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("scribed.log");
    let mut f = SizeRotatingFile::open(&path, 10, 2).unwrap();
    for chunk in ["aaaaaaaa\n", "bbbbbbbb\n", "cccccccc\n", "dddddddd\n"] {
        f.write_all(chunk.as_bytes()).unwrap();
    }
    f.flush().unwrap();
    assert_eq!(fs::read_to_string(&path).unwrap(), "dddddddd\n");
    assert_eq!(
        fs::read_to_string(dir.path().join("scribed.log.1")).unwrap(),
        "cccccccc\n"
    );
    assert_eq!(
        fs::read_to_string(dir.path().join("scribed.log.2")).unwrap(),
        "bbbbbbbb\n"
    );
    assert!(
        !dir.path().join("scribed.log.3").exists(),
        "only `keep` rotated files"
    );
}

#[test]
fn size_rotation_appends_to_an_existing_file() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("scribed.log");
    fs::write(&path, "old\n").unwrap();
    let mut f = SizeRotatingFile::open(&path, 1 << 20, 3).unwrap();
    f.write_all(b"new\n").unwrap();
    assert_eq!(fs::read_to_string(&path).unwrap(), "old\nnew\n");
}
