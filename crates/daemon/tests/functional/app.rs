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

/// A native sensor that can't start hands over to the fallback.
#[test]
fn the_fallback_sensor_takes_over_when_the_native_one_fails() {
    use scribe_core::{Observation, Sensor, SensorError};
    use scribe_daemon::app::FallbackSensor;
    use scribe_test_support::FakeSensor;

    struct Broken;
    impl Sensor for Broken {
        fn name(&self) -> &'static str {
            "native"
        }
        fn has_process_info(&self) -> bool {
            true
        }
        fn start(&mut self, _out: std::sync::mpsc::Sender<Observation>) -> Result<(), SensorError> {
            Err(SensorError::Unsupported("not here"))
        }
        fn stop(&mut self) {}
    }

    let fallback = FakeSensor::new(vec![]).without_process_info();
    let mut s = FallbackSensor::new(Box::new(Broken), Box::new(fallback));
    assert_eq!((s.name(), s.has_process_info()), ("native", true));
    let (tx, _rx) = std::sync::mpsc::channel();
    s.start(tx.clone()).unwrap();
    assert_eq!((s.name(), s.has_process_info()), ("fake", false));
    s.stop();
    s.start(tx).unwrap(); // a restart goes straight to the fallback
    assert_eq!(s.name(), "fake");
}

#[test]
fn alert_outputs_follow_the_alerts_section() {
    let dir = tempfile::tempdir().unwrap();
    let clock: std::sync::Arc<dyn scribe_core::Clock> =
        std::sync::Arc::new(scribe_test_support::FakeClock::at_unix(1_800_000_000));
    let on = alert_outputs(&settings_in(dir.path()), clock.clone()).unwrap();
    assert_eq!(on.names(), ["log"]);
    let off = alert_outputs(
        &settings_with(dir.path(), "[alerts]\nlog = false\n"),
        clock.clone(),
    )
    .unwrap();
    assert!(off.names().is_empty());

    let key = dir.path().join("webhook.key");
    let hook = |secret: &std::path::Path| {
        format!(
            "[[alerts.webhooks]]\nname = \"ops\"\nurl = \"https://hooks.example.com/scribe\"\nsecret = '{}'\n",
            scribe_secrets::SecretRef::File(secret.to_owned())
        )
    };
    let missing = alert_outputs(&settings_with(dir.path(), &hook(&key)), clock.clone())
        .err()
        .unwrap();
    assert!(
        missing.starts_with("webhook \"ops\": cannot read its secret"),
        "{missing}"
    );
    scribe_secrets::read_or_create(&scribe_secrets::SecretRef::File(key.clone()), 32).unwrap();
    let both = alert_outputs(&settings_with(dir.path(), &hook(&key)), clock).unwrap();
    assert_eq!(both.names(), ["log", "ops"]);
    assert!(!machine_name().is_empty());
}

#[test]
fn set_secret_stores_piped_or_generated_keys() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("webhook.key");
    let reference = format!("file:{}", path.display());
    let r: scribe_secrets::SecretRef = reference.parse().unwrap();

    let said = set_secret(&reference, Some(b"s3cret\n".to_vec())).unwrap();
    assert_eq!(said, format!("stored the secret in {reference}"));
    assert_eq!(scribe_secrets::read(&r).unwrap().expose(), b"s3cret");

    let said = set_secret(&reference, None).unwrap();
    let key = said.lines().last().unwrap();
    assert_eq!(key.len(), 64);
    assert_eq!(scribe_secrets::read(&r).unwrap().expose(), key.as_bytes());

    assert!(set_secret(&reference, Some(b"\n".to_vec()))
        .unwrap_err()
        .contains("nothing on standard input"));
    assert!(set_secret("hunter2", Some(b"x".to_vec()))
        .unwrap_err()
        .contains("malformed secret reference"));
    let parsed =
        Args::try_parse_from(["scribed", "--set-secret", &reference, "--generate"]).unwrap();
    assert_eq!(parsed.set_secret.as_deref(), Some(reference.as_str()));
    assert!(parsed.generate);
    assert!(Args::try_parse_from(["scribed", "--generate"]).is_err());
    assert!(
        Args::try_parse_from(["scribed", "--set-secret", &reference, "--check-config"]).is_err()
    );
}
