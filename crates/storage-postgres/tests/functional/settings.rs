//! Connection settings without a database: the TLS rule, schema names, credentials.

use std::collections::HashMap;

use scribe_storage_api::{EventSink, Health, StorageError};
use scribe_storage_conformance::block_on;
use scribe_storage_postgres::{PostgresSink, Settings};

fn opts(url: &str) -> HashMap<String, String> {
    HashMap::from([("url".to_owned(), url.to_owned())])
}

fn config_error(o: &HashMap<String, String>) -> String {
    match Settings::from_options(o) {
        Err(StorageError::Config(m)) => m,
        Err(other) => panic!("expected a config error, got {other}"),
        Ok(_) => panic!("accepted"),
    }
}

#[test]
fn a_remote_server_always_gets_tls() {
    for url in [
        "postgres://scribe@db.example.com/history",
        "postgres://scribe@db.example.com/history?sslmode=prefer",
        "postgres://scribe@db.example.com/history?sslmode=require",
        "postgres://scribe@192.0.2.10:6543/history",
    ] {
        assert!(
            Settings::from_options(&opts(url)).unwrap().uses_tls(),
            "{url}"
        );
    }
    let err = config_error(&opts(
        "postgres://scribe@db.example.com/history?sslmode=disable",
    ));
    assert!(
        err.contains("sslmode=disable is only allowed for a server on this machine"),
        "{err}"
    );
}

#[test]
fn a_local_server_may_go_without_tls() {
    for url in [
        "postgres://scribe@localhost/history",
        "postgres://scribe@127.0.0.1:5432/history?sslmode=disable",
        "postgres://scribe@[::1]/history",
    ] {
        assert!(
            !Settings::from_options(&opts(url)).unwrap().uses_tls(),
            "{url}"
        );
    }
    assert!(
        Settings::from_options(&opts("postgres://scribe@localhost/h?sslmode=require"))
            .unwrap()
            .uses_tls()
    );
}

#[test]
fn bad_urls_schemas_and_credentials_are_config_errors() {
    assert!(config_error(&opts("not a url")).contains("url can't be read"));
    assert!(config_error(&HashMap::new()).contains("url"));
    let mut o = opts("postgres://scribe@localhost/h");
    o.insert("schema".into(), "Robert'); DROP TABLE events;--".into());
    assert!(config_error(&o).contains("schema"));
    let mut o = opts("postgres://scribe@localhost/h");
    o.insert("credentials".into(), "hunter2".into());
    assert!(config_error(&o).contains("credentials"));
}

#[test]
fn a_password_comes_from_the_credentials_reference() {
    let dir = tempfile::tempdir().unwrap();
    let key = dir.path().join("pg.key");
    let reference = format!("file:{}", key.display());
    scribe_secrets::store(&reference.parse().unwrap(), b"s3cret").unwrap();
    let mut o = opts("postgres://scribe@localhost/h");
    o.insert("credentials".into(), reference);
    let settings = Settings::from_options(&o).unwrap();
    assert!(!format!("{settings:?}").contains("s3cret"), "never printed");
}

#[test]
fn an_unreachable_server_is_reported_down() {
    // Port 1 on loopback: nothing listens there.
    let sink =
        PostgresSink::from_options("down", &opts("postgres://scribe@127.0.0.1:1/h")).unwrap();
    match block_on(sink.health()) {
        Health::Down(why) => assert!(why.contains("cannot connect"), "{why}"),
        other => panic!("{other:?}"),
    }
    assert!(matches!(
        block_on(sink.migrate()),
        Err(StorageError::Backend(_))
    ));
}
