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
