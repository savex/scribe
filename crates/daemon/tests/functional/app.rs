//! Functional tests for `scribe_daemon::app` (moved from `src/app.rs`).

use clap::Parser;
use scribe_core::platform::DefaultPaths;
use scribe_daemon::app::*;
use scribe_daemon::config::{self, Settings};
use scribe_daemon::config::{parse, resolve, HostFacts, Source};
use std::process::ExitCode;

fn settings_in(dir: &std::path::Path) -> Settings {
    let text = format!("data_dir = '{}'\n[log]\nfile = ''\n", dir.display());
    let source = Source::File("test.toml".into());
    let config = parse(&text, &source, &config::context()).unwrap();
    resolve(
        config,
        source,
        &DefaultPaths::current().unwrap(),
        &HostFacts,
    )
    .unwrap()
}

#[test]
fn serve_reports_folders_it_cannot_create() {
    let dir = tempfile::tempdir().unwrap();
    let blocker = dir.path().join("file");
    std::fs::write(&blocker, "").unwrap();
    let rt = tokio::runtime::Runtime::new().unwrap();
    let err = rt
        .block_on(serve(
            settings_in(&blocker.join("data")),
            std::future::ready(()),
        ))
        .unwrap_err();
    assert!(
        format!("{err:#}").contains("cannot create folder"),
        "{err:#}"
    );
}

#[test]
fn arguments() {
    let args =
        Args::try_parse_from(["scribed", "--config", "/etc/x.toml", "--check-config"]).unwrap();
    assert_eq!(
        args.config.as_deref(),
        Some(std::path::Path::new("/etc/x.toml"))
    );
    assert!(args.check_config);
    assert!(Args::try_parse_from(["scribed", "--bogus"]).is_err());
}

#[test]
fn config_errors_exit_with_2() {
    let code = run(
        Args::try_parse_from(["scribed", "--config", "/nonexistent/scribe.toml"]).unwrap(),
        None,
        None,
    );
    assert_eq!(code, ExitCode::from(EXIT_CONFIG));
}

fn settings_with(dir: &std::path::Path, extra: &str) -> Settings {
    let text = format!("data_dir = '{}'\n[log]\nfile = ''\n{extra}", dir.display());
    let source = Source::File("test.toml".into());
    let config = parse(&text, &source, &config::context()).unwrap();
    resolve(
        config,
        source,
        &DefaultPaths::current().unwrap(),
        &HostFacts,
    )
    .unwrap()
}

#[test]
fn threat_lists_load_from_files_under_data_dir() {
    let dir = tempfile::tempdir().unwrap();
    std::fs::create_dir(dir.path().join("threats")).unwrap();
    std::fs::write(
        dir.path().join("threats/d.txt"),
        "evil.example.net\nbad line here\n",
    )
    .unwrap();
    std::fs::write(dir.path().join("ips.txt"), "203.0.113.0/24\n").unwrap();
    let s = settings_with(
        dir.path(),
        "[[policy.threat_lists]]\nname = 'd'\npath = 'threats/d.txt'\nformat = 'domains'\n[[policy.threat_lists]]\nname = 'i'\npath = 'ips.txt'\nformat = 'ips'\n[[policy.threat_lists]]\nname = 'later'\nurl = 'https://example.com/list'\nformat = 'hosts'\n",
    );
    let set = load_threats(&s).unwrap();
    assert_eq!(set.len(), 2);
    assert!(set.matches_host("cdn.evil.example.net"));
    assert!(set.matches_ip("203.0.113.5".parse().unwrap()));
}

#[test]
fn a_missing_threat_list_stops_scribed() {
    let dir = tempfile::tempdir().unwrap();
    let s = settings_with(
        dir.path(),
        "[[policy.threat_lists]]\nname = 'gone'\npath = 'missing.txt'\nformat = 'domains'\n",
    );
    let err = load_threats(&s).unwrap_err();
    assert!(
        format!("{err:#}").contains("cannot read threat list \"gone\""),
        "{err:#}"
    );
    let rt = tokio::runtime::Runtime::new().unwrap();
    let err = rt.block_on(serve(s, std::future::ready(()))).unwrap_err();
    assert!(format!("{err:#}").contains("threat list"), "{err:#}");
}
