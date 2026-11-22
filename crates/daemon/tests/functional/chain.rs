//! The audit / alert chain (NFR-18) and StrictModes start-up checks.

use std::time::{Duration, UNIX_EPOCH};

use scribe_daemon::chain::{verify, Chain, ChainProblem, KEY_FILE};
use scribe_storage_api::{AlertRecord, AuditRecord, StoredEvent};

fn audit(n: u64, message: &str) -> StoredEvent {
    StoredEvent::Audit(AuditRecord {
        ts: UNIX_EPOCH + Duration::from_secs(1_700_000_000 + n),
        message: message.into(),
        link: None,
    })
}

fn alert(n: u64) -> StoredEvent {
    StoredEvent::Alert(AlertRecord {
        ts: UNIX_EPOCH + Duration::from_secs(1_700_000_000 + n),
        host: Some("docs.example.com".into()),
        dst_ip: "192.0.2.12".parse().unwrap(),
        dst_port: 443,
        process_path: None,
        score: 0,
        reason: "unlisted_host".into(),
        notes: Default::default(),
        link: None,
    })
}

fn sealed(dir: &std::path::Path) -> (Chain, Vec<StoredEvent>) {
    let mut chain = Chain::open(dir).unwrap();
    let mut events = vec![
        audit(0, "scribed started"),
        alert(1),
        audit(2, "hibernate by admin"),
        audit(3, "wakeup by admin"),
    ];
    chain.seal(&mut events).unwrap();
    (chain, events)
}

#[test]
fn sealed_records_verify_and_continue_across_restarts() {
    let dir = tempfile::tempdir().unwrap();
    let (chain, mut events) = sealed(dir.path());
    assert_eq!(chain.seq(), 4);
    assert!(verify(chain.key(), &events).is_empty());
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let mode = std::fs::metadata(dir.path().join(KEY_FILE))
            .unwrap()
            .permissions()
            .mode();
        assert_eq!(mode & 0o777, 0o600);
    }
    drop(chain);

    let mut reopened = Chain::open(dir.path()).unwrap();
    assert_eq!(reopened.seq(), 4, "the chain continues after a restart");
    let mut more = vec![audit(4, "scribed started again")];
    reopened.seal(&mut more).unwrap();
    events.extend(more);
    assert!(verify(reopened.key(), &events).is_empty());
}

#[test]
fn deleted_and_edited_records_show_up() {
    let dir = tempfile::tempdir().unwrap();
    let (chain, events) = sealed(dir.path());

    let mut deleted = events.clone();
    deleted.remove(1);
    assert_eq!(
        verify(chain.key(), &deleted),
        [ChainProblem::Gap { after: 1, next: 3 }]
    );

    let mut edited = events.clone();
    if let StoredEvent::Audit(a) = &mut edited[2] {
        a.message = "nothing happened".into();
    }
    assert_eq!(
        verify(chain.key(), &edited),
        [ChainProblem::Mismatch { seq: 4 }]
    );

    let mut unlinked = events;
    unlinked.push(audit(9, "written before the chain"));
    assert_eq!(verify(chain.key(), &unlinked), [ChainProblem::Unlinked]);
}

#[test]
fn flows_are_not_part_of_the_chain() {
    let dir = tempfile::tempdir().unwrap();
    let mut chain = Chain::open(dir.path()).unwrap();
    let mut events = vec![StoredEvent::Flow(
        scribe_test_support::flow("192.0.2.10:443").build(),
    )];
    chain.seal(&mut events).unwrap();
    assert_eq!(chain.seq(), 0);
    assert!(!dir.path().join(scribe_daemon::chain::STATE_FILE).exists());
}

#[test]
fn the_chain_survives_the_storage_codec() {
    let dir = tempfile::tempdir().unwrap();
    let (chain, events) = sealed(dir.path());
    let decoded: Vec<StoredEvent> = events
        .iter()
        .map(|e| scribe_storage_api::codec::decode(scribe_storage_api::codec::encode(e)).unwrap())
        .collect();
    assert!(verify(chain.key(), &decoded).is_empty());
}

#[cfg(unix)]
#[test]
fn strict_modes_refuse_writable_config_and_data_dir() {
    use scribe_core::platform::DefaultPaths;
    use scribe_daemon::config::load_settings;
    use scribe_daemon::security::strict_modes;
    use std::os::unix::fs::PermissionsExt;
    let dir = tempfile::tempdir().unwrap();
    let data = dir.path().join("data");
    std::fs::create_dir(&data).unwrap();
    let config = dir.path().join("scribe.toml");
    std::fs::write(
        &config,
        format!("data_dir = '{}'\n[log]\nfile = ''\n", data.display()),
    )
    .unwrap();
    let _ = DefaultPaths::current();
    let settings = load_settings(Some(&config), None).unwrap();
    assert!(strict_modes(&settings).is_ok());

    std::fs::set_permissions(&config, std::fs::Permissions::from_mode(0o666)).unwrap();
    std::fs::set_permissions(&data, std::fs::Permissions::from_mode(0o777)).unwrap();
    let err = strict_modes(&settings).unwrap_err();
    assert!(
        err.contains("config file") && err.contains("mode 666"),
        "{err}"
    );
    assert!(
        err.contains("data_dir") && err.contains("chmod go-w"),
        "{err}"
    );
}
