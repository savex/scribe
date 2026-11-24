//! Functional tests for `scribe_secrets`.

use std::path::Path;

use scribe_secrets::{read, read_or_create, store, SecretError, SecretRef};

fn file(path: &Path) -> SecretRef {
    format!("file:{}", path.display()).parse().unwrap()
}

#[cfg(unix)]
fn chmod(path: &Path, mode: u32) {
    use std::os::unix::fs::PermissionsExt;
    std::fs::set_permissions(path, std::fs::Permissions::from_mode(mode)).unwrap();
}

#[test]
fn references_parse_and_print_back() {
    // `file:` and `dpapi:` need paths that are absolute on this system (a drive on Windows).
    let (key, blob) = if cfg!(windows) {
        (
            "C:/ProgramData/scribe/url_hash.key",
            "C:/ProgramData/scribe/pg.bin",
        )
    } else {
        ("/var/lib/scribe/url_hash.key", "/var/lib/scribe/pg.bin")
    };
    for text in [
        format!("file:{key}"),
        "keychain:scribe/postgres".to_owned(),
        format!("dpapi:{blob}"),
        "secret-service:scribe-postgres".to_owned(),
    ] {
        let r: SecretRef = text.parse().unwrap();
        assert_eq!(r.to_string(), text);
    }
    for bad in [
        "",
        "file:",
        "file:relative/key",
        "keychain:noslash",
        "keychain:/a",
        "env:X",
        "plain",
    ] {
        assert!(
            matches!(bad.parse::<SecretRef>(), Err(SecretError::Malformed(_))),
            "{bad}"
        );
    }
}

#[test]
fn other_systems_stores_are_unsupported() {
    let mut refs: Vec<(&str, &str)> = Vec::new();
    if !cfg!(target_os = "macos") {
        refs.push(("keychain:scribe/postgres", "keychain"));
    }
    if !cfg!(windows) {
        refs.push(("dpapi:/var/lib/scribe/w.dpapi", "dpapi"));
    }
    if !cfg!(target_os = "linux") {
        refs.push(("secret-service:scribe-webhook", "secret-service"));
    }
    for (text, backend) in refs {
        let r: SecretRef = text.parse().unwrap();
        assert_eq!(r.backend(), backend);
        assert!(
            matches!(read(&r), Err(SecretError::Unsupported(b)) if b == backend),
            "{text}"
        );
        assert!(matches!(
            read_or_create(&r, 32),
            Err(SecretError::Unsupported(_))
        ));
        assert!(matches!(store(&r, b"x"), Err(SecretError::Unsupported(_))));
    }
}

#[test]
fn store_replaces_a_file_secret_privately() {
    let dir = tempfile::tempdir().unwrap();
    let r = file(&dir.path().join("webhook.key"));
    store(&r, b"first").unwrap();
    assert_eq!(read(&r).unwrap().expose(), b"first");
    store(&r, b"second").unwrap();
    assert_eq!(read(&r).unwrap().expose(), b"second");
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let mode = std::fs::metadata(dir.path().join("webhook.key"))
            .unwrap()
            .permissions()
            .mode();
        assert_eq!(mode & 0o777, 0o600);
    }
    assert!(matches!(store(&r, b""), Err(SecretError::Store { .. })));
}

/// DPAPI needs no user interaction: a full round trip on every Windows run.
#[cfg(windows)]
#[test]
fn dpapi_round_trip_and_garbage() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("webhook.dpapi");
    let r: SecretRef = format!("dpapi:{}", path.display()).parse().unwrap();
    assert!(matches!(read(&r), Err(SecretError::NotFound(_))));
    let created = read_or_create(&r, 16).unwrap();
    assert_eq!(created.expose().len(), 32, "hex of 16 bytes");
    let sealed = std::fs::read(&path).unwrap();
    assert!(
        !sealed.windows(32).any(|w| w == created.expose()),
        "the file holds a sealed blob, not the key"
    );
    assert_eq!(read(&r).unwrap(), created);
    store(&r, b"replaced").unwrap();
    assert_eq!(read(&r).unwrap().expose(), b"replaced");
    std::fs::write(&path, b"not a dpapi blob").unwrap();
    assert!(matches!(read(&r), Err(SecretError::Store { .. })));
}

/// The keychain may ask the user for permission on a desktop, so the round trip runs only where
/// `SCRIBE_TEST_KEYCHAIN=1` says it is safe (the macOS CI runner). A missing item is always checked.
#[cfg(target_os = "macos")]
#[test]
fn keychain_items_round_trip() {
    let account = format!("test-{}", std::process::id());
    let r = SecretRef::Keychain {
        service: "scribe-test".into(),
        account: account.clone(),
    };
    if std::env::var_os("SCRIBE_TEST_KEYCHAIN").is_none() {
        let missing = SecretRef::Keychain {
            service: "scribe-test-never-created".into(),
            account,
        };
        assert!(matches!(read(&missing), Err(SecretError::NotFound(_))));
        return;
    }
    let _ = scribe_secrets::delete_keychain_item("scribe-test", &account);
    assert!(matches!(read(&r), Err(SecretError::NotFound(_))));
    let created = read_or_create(&r, 16).unwrap();
    assert_eq!(read(&r).unwrap(), created);
    store(&r, b"replaced").unwrap();
    assert_eq!(read(&r).unwrap().expose(), b"replaced");
    scribe_secrets::delete_keychain_item("scribe-test", &account).unwrap();
    assert!(matches!(read(&r), Err(SecretError::NotFound(_))));
}

/// Without a session bus (CI, a system service) the store reports what is missing; with a keyring,
/// a label never stored is not found.
#[cfg(target_os = "linux")]
#[test]
fn secret_service_explains_a_missing_bus() {
    let r: SecretRef = format!(
        "secret-service:scribe-test-never-created-{}",
        std::process::id()
    )
    .parse()
    .unwrap();
    match read(&r) {
        Err(SecretError::Store { reference, why }) => {
            assert!(reference.starts_with("secret-service:"), "{reference}");
            assert!(!why.is_empty());
        }
        Err(SecretError::NotFound(_)) => {}
        other => panic!("unexpected {other:?}"),
    }
}

#[test]
fn a_missing_file_is_not_found() {
    let dir = tempfile::tempdir().unwrap();
    assert!(matches!(
        read(&file(&dir.path().join("none"))),
        Err(SecretError::NotFound(_))
    ));
}

#[test]
fn a_key_is_created_once_and_read_back() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("url_hash.key");
    let first = read_or_create(&file(&path), 32).unwrap();
    assert_eq!(first.expose().len(), 64);
    assert!(first.expose().iter().all(|b| b.is_ascii_hexdigit()));
    assert_eq!(read_or_create(&file(&path), 32).unwrap(), first);
    assert_eq!(read(&file(&path)).unwrap(), first);
    assert!(!format!("{first:?}").contains(std::str::from_utf8(first.expose()).unwrap()));
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let mode = std::fs::metadata(&path).unwrap().permissions().mode() & 0o777;
        assert_eq!(mode, 0o600);
    }
    let left: Vec<_> = std::fs::read_dir(dir.path()).unwrap().collect();
    assert_eq!(left.len(), 1, "no temp file left behind");
}

#[test]
fn one_trailing_newline_is_dropped() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("pg");
    std::fs::write(&path, "s3cret\r\n").unwrap();
    #[cfg(unix)]
    chmod(&path, 0o600);
    assert_eq!(read(&file(&path)).unwrap().expose(), b"s3cret");
}

#[cfg(unix)]
#[test]
fn files_others_can_read_or_change_are_refused() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("pg");
    std::fs::write(&path, "s3cret").unwrap();
    for mode in [0o644, 0o620, 0o604] {
        chmod(&path, mode);
        let err = read(&file(&path)).unwrap_err();
        assert!(
            matches!(err, SecretError::Insecure { .. }),
            "{mode:o}: {err}"
        );
        assert!(err.to_string().contains("use 600"), "{err}");
    }
    chmod(&path, 0o400);
    assert!(read(&file(&path)).is_ok());
}

#[cfg(unix)]
#[test]
fn keys_are_not_created_in_a_shared_directory() {
    let dir = tempfile::tempdir().unwrap();
    chmod(dir.path(), 0o777);
    let err = read_or_create(&file(&dir.path().join("k")), 32).unwrap_err();
    assert!(matches!(err, SecretError::Insecure { .. }), "{err}");
}

#[test]
fn empty_files_and_directories_are_refused() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("empty");
    std::fs::write(&path, "\n").unwrap();
    #[cfg(unix)]
    chmod(&path, 0o600);
    assert!(matches!(
        read(&file(&path)),
        Err(SecretError::Insecure { .. })
    ));
    assert!(matches!(
        read(&file(dir.path())),
        Err(SecretError::Insecure { .. })
    ));
}
