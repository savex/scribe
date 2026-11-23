//! Functional tests for `scribe_secrets`.

use std::path::Path;

use scribe_secrets::{read, read_or_create, SecretError, SecretRef};

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
fn os_stores_are_not_supported_yet() {
    let r: SecretRef = "keychain:scribe/postgres".parse().unwrap();
    assert!(matches!(
        read(&r),
        Err(SecretError::Unsupported("keychain"))
    ));
    assert!(matches!(
        read_or_create(&r, 32),
        Err(SecretError::Unsupported("keychain"))
    ));
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
