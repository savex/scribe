//! Service integration: dropping privileges, systemd notifications, the packaging files.

use std::path::PathBuf;

fn packaging(rel: &str) -> String {
    let path = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../../packaging")
        .join(rel);
    std::fs::read_to_string(&path).unwrap_or_else(|e| panic!("{}: {e}", path.display()))
}

#[test]
fn service_files_run_scribed_the_way_it_expects() {
    let unit = packaging("linux/scribed.service");
    assert!(unit.contains("Type=notify"));
    assert!(unit.contains("ExecStart=/usr/bin/scribed --config /etc/scribe/scribe.toml"));
    assert!(unit.contains("ExecReload=/bin/kill -HUP $MAINPID"));
    let plist = packaging("macos/io.github.savex.scribed.plist");
    assert!(plist.contains("<string>/usr/local/bin/scribed</string>"));
    assert!(plist.contains("<string>--config</string>"));
    let ps1 = packaging("windows/install-service.ps1");
    assert!(ps1.contains("--service"));
    assert!(ps1.contains(scribe_daemon::service::WINDOWS_SERVICE));
}

#[cfg(unix)]
mod unix {
    use scribe_daemon::privileges::drop_to;

    fn me() -> String {
        // SAFETY: getpwuid returns a pointer into static storage or null; checked.
        unsafe {
            let pw = libc::getpwuid(libc::geteuid());
            assert!(!pw.is_null());
            std::ffi::CStr::from_ptr((*pw).pw_name)
                .to_string_lossy()
                .into_owned()
        }
    }

    #[test]
    fn unknown_users_are_refused() {
        let dir = tempfile::tempdir().unwrap();
        let err = drop_to("no-such-user-scribe-test", dir.path()).unwrap_err();
        assert!(err.contains("no such user"), "{err}");
    }

    #[test]
    fn running_as_the_user_already_is_fine() {
        let dir = tempfile::tempdir().unwrap();
        drop_to(&me(), dir.path()).unwrap();
    }

    #[test]
    fn data_dir_must_belong_to_the_user() {
        // SAFETY: no preconditions.
        if unsafe { libc::geteuid() } == 0 {
            return; // as root the owner check below would pass for root itself
        }
        let dir = tempfile::tempdir().unwrap();
        let err = drop_to("root", dir.path()).unwrap_err();
        assert!(err.contains("chown -R root"), "{err}");
    }
}

#[cfg(target_os = "linux")]
#[test]
fn systemd_notifications_reach_the_socket() {
    use std::os::unix::net::UnixDatagram;
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("notify.sock");
    let socket = UnixDatagram::bind(&path).unwrap();
    scribe_daemon::service::notify_socket(path.as_os_str(), "READY=1\nSTATUS=capturing").unwrap();
    let mut buf = [0u8; 64];
    let n = socket.recv(&mut buf).unwrap();
    assert_eq!(&buf[..n], b"READY=1\nSTATUS=capturing");
}
