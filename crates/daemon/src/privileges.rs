//! Dropping root after start-up (`[daemon] user`, Unix): storage, the audit chain and the sensor
//! are opened as root, then scribed continues as the given user. `data_dir` must belong to that
//! user, so files created later (spool, rotated logs) stay writable.
//!
//! A sensor restarted after hibernation runs with the lower privileges; capture needs capabilities
//! the user keeps (e.g. `cap_net_raw` for pcap) until the privilege split of phases 7–9.

use std::path::Path;

/// Switch the process to `user` (groups, gid, then uid) and check root can't be regained.
/// Running as that user already is fine.
#[cfg(unix)]
pub fn drop_to(user: &str, data_dir: &Path) -> Result<(), String> {
    use std::ffi::CString;
    use std::os::unix::fs::MetadataExt;

    let name = CString::new(user).map_err(|_| format!("bad user name {user:?}"))?;
    let (uid, gid) = lookup(&name).ok_or_else(|| format!("no such user: {user}"))?;
    let owner = std::fs::metadata(data_dir)
        .map_err(|e| format!("{}: {e}", data_dir.display()))?
        .uid();
    if owner != uid {
        return Err(format!(
            "data_dir {} belongs to uid {owner}, not to {user} (uid {uid}); run `chown -R {user} {}`",
            data_dir.display(),
            data_dir.display()
        ));
    }
    // SAFETY: plain libc calls with valid arguments; results are checked.
    unsafe {
        if libc::geteuid() == uid && libc::getegid() == gid {
            return Ok(());
        }
        if libc::initgroups(name.as_ptr(), gid as _) != 0 {
            return Err(format!(
                "initgroups for {user}: {}",
                std::io::Error::last_os_error()
            ));
        }
        if libc::setgid(gid) != 0 {
            return Err(format!("setgid {gid}: {}", std::io::Error::last_os_error()));
        }
        if libc::setuid(uid) != 0 {
            return Err(format!("setuid {uid}: {}", std::io::Error::last_os_error()));
        }
        if uid != 0 && libc::setuid(0) == 0 {
            return Err("still able to become root after dropping privileges".into());
        }
    }
    Ok(())
}

#[cfg(unix)]
fn lookup(name: &std::ffi::CStr) -> Option<(libc::uid_t, libc::gid_t)> {
    let mut pwd: libc::passwd = unsafe { std::mem::zeroed() };
    let mut buf = vec![0 as libc::c_char; 16 * 1024];
    let mut result: *mut libc::passwd = std::ptr::null_mut();
    // SAFETY: buffers are valid for the call; `result` is checked before use.
    let rc = unsafe {
        libc::getpwnam_r(
            name.as_ptr(),
            &mut pwd,
            buf.as_mut_ptr(),
            buf.len(),
            &mut result,
        )
    };
    (rc == 0 && !result.is_null()).then_some((pwd.pw_uid, pwd.pw_gid))
}

#[cfg(not(unix))]
pub fn drop_to(user: &str, _data_dir: &Path) -> Result<(), String> {
    Err(format!(
        "daemon.user = {user:?}: dropping privileges is not supported on this system (the service account is set by the installer)"
    ))
}
