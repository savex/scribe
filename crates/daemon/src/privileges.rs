//! Dropping root after start-up (`[daemon] user`, Unix): storage, the audit chain and the sensor
//! are opened as root, then scribed continues as the given user. `data_dir` must belong to that
//! user, so files created later (spool, rotated logs) stay writable.
//!
//! On Linux one thread, the [`Keeper`], keeps the capabilities capture needs (`CAP_BPF`,
//! `CAP_PERFMON`, `CAP_NET_RAW`) and nothing else; a sensor started again after hibernation is
//! started there. Capabilities belong to threads, so every other thread, the async runtime's
//! included, has none. The locked-memory limit is raised while still root, for kernels before
//! 5.11 that count BPF maps against it. Elsewhere a restarted sensor runs as the user.

use std::path::Path;
use std::sync::mpsc;

type Job = Box<dyn FnOnce() + Send>;

/// The thread that kept the capture capabilities after the drop (Linux).
pub struct Keeper {
    jobs: mpsc::Sender<Job>,
    kept: Vec<&'static str>,
}

impl std::fmt::Debug for Keeper {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Keeper").field("kept", &self.kept).finish()
    }
}

impl Keeper {
    /// The capabilities the thread holds, e.g. `["cap_net_raw", "cap_perfmon", "cap_bpf"]`.
    pub fn kept(&self) -> &[&'static str] {
        &self.kept
    }

    /// Runs `f` on the keeper thread (threads it starts inherit the capabilities) and waits for
    /// it. A panic in `f` comes back as a panic here.
    pub fn run<R: Send + 'static>(&self, f: impl FnOnce() -> R + Send + 'static) -> R {
        let (tx, rx) = mpsc::sync_channel(1);
        let job: Job = Box::new(move || {
            let _ = tx.send(std::panic::catch_unwind(std::panic::AssertUnwindSafe(f)));
        });
        self.jobs
            .send(job)
            .expect("the capability keeper thread is gone");
        match rx.recv().expect("the capability keeper thread is gone") {
            Ok(r) => r,
            Err(panic) => std::panic::resume_unwind(panic),
        }
    }
}

/// Switch the process to `user` (groups, gid, then uid) and check root can't be regained.
/// Running as that user already is fine. On Linux, when scribed was root, returns the thread that
/// kept the capture capabilities.
#[cfg(unix)]
pub fn drop_to(user: &str, data_dir: &Path) -> Result<Option<Keeper>, String> {
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
            return Ok(None);
        }
    }
    #[cfg(target_os = "linux")]
    let keeper = linux::prepare()?;
    // SAFETY: as above.
    unsafe {
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
    #[cfg(target_os = "linux")]
    return keeper.finish().map(Some);
    #[cfg(not(target_os = "linux"))]
    Ok(None)
}

#[cfg(target_os = "linux")]
mod linux {
    //! Capabilities with the raw `capget` / `capset` calls (version 3: two 32-bit words).

    use std::sync::mpsc;

    use super::{Job, Keeper};

    const CAP_NET_RAW: u32 = 13;
    const CAP_PERFMON: u32 = 38;
    const CAP_BPF: u32 = 39;
    const KEEP: [(u32, &str); 3] = [
        (CAP_NET_RAW, "cap_net_raw"),
        (CAP_PERFMON, "cap_perfmon"),
        (CAP_BPF, "cap_bpf"),
    ];
    const VERSION_3: u32 = 0x2008_0522;

    #[repr(C)]
    struct Header {
        version: u32,
        pid: libc::c_int,
    }

    #[repr(C)]
    #[derive(Clone, Copy, Default)]
    struct Data {
        effective: u32,
        permitted: u32,
        inheritable: u32,
    }

    fn get() -> std::io::Result<[Data; 2]> {
        let mut h = Header {
            version: VERSION_3,
            pid: 0,
        };
        let mut d = [Data::default(); 2];
        // SAFETY: header and two data words, as capget(2) version 3 expects.
        let rc = unsafe { libc::syscall(libc::SYS_capget, &mut h, d.as_mut_ptr()) };
        if rc == 0 {
            Ok(d)
        } else {
            Err(std::io::Error::last_os_error())
        }
    }

    fn set(d: &[Data; 2]) -> std::io::Result<()> {
        let mut h = Header {
            version: VERSION_3,
            pid: 0,
        };
        // SAFETY: as in `get`; capset only reads the data.
        let rc = unsafe { libc::syscall(libc::SYS_capset, &mut h, d.as_ptr()) };
        if rc == 0 {
            Ok(())
        } else {
            Err(std::io::Error::last_os_error())
        }
    }

    fn has(d: &[Data; 2], cap: u32) -> bool {
        d[(cap / 32) as usize].permitted & (1 << (cap % 32)) != 0
    }

    /// Before the uid changes: a thread that will keep its permitted set through it.
    pub struct Pending {
        go: mpsc::SyncSender<()>,
        done: mpsc::Receiver<Result<Keeper, String>>,
    }

    pub fn prepare() -> Result<Pending, String> {
        raise_memlock();
        let (ready_tx, ready_rx) = mpsc::sync_channel::<Result<(), String>>(1);
        let (go_tx, go_rx) = mpsc::sync_channel::<()>(1);
        let (done_tx, done_rx) = mpsc::sync_channel(1);
        std::thread::Builder::new()
            .name("scribe-caps".into())
            .spawn(move || {
                // SAFETY: prctl with an integer argument.
                if unsafe { libc::prctl(libc::PR_SET_KEEPCAPS, 1, 0, 0, 0) } != 0 {
                    let e = std::io::Error::last_os_error();
                    let _ = ready_tx.send(Err(format!("PR_SET_KEEPCAPS: {e}")));
                    return;
                }
                let _ = ready_tx.send(Ok(()));
                if go_rx.recv().is_err() {
                    return; // the drop failed
                }
                let (jobs_tx, jobs_rx) = mpsc::channel::<Job>();
                let kept = narrow();
                // SAFETY: as above.
                unsafe { libc::prctl(libc::PR_SET_KEEPCAPS, 0, 0, 0, 0) };
                let _ = done_tx.send(kept.map(|kept| Keeper {
                    jobs: jobs_tx,
                    kept,
                }));
                for job in jobs_rx {
                    job();
                }
            })
            .map_err(|e| format!("cannot start the capability thread: {e}"))?;
        ready_rx
            .recv()
            .map_err(|_| "the capability thread ended".to_owned())??;
        Ok(Pending {
            go: go_tx,
            done: done_rx,
        })
    }

    impl Pending {
        /// After the uid changed on every thread.
        pub fn finish(self) -> Result<Keeper, String> {
            self.go
                .send(())
                .map_err(|_| "the capability thread ended".to_owned())?;
            self.done
                .recv()
                .map_err(|_| "the capability thread ended".to_owned())?
        }
    }

    /// Keeps only the capture capabilities, permitted and effective, on this thread.
    fn narrow() -> Result<Vec<&'static str>, String> {
        let now = get().map_err(|e| format!("capget: {e}"))?;
        let mut want = [Data::default(); 2];
        let mut kept = Vec::new();
        for (cap, name) in KEEP {
            if has(&now, cap) {
                let w = &mut want[(cap / 32) as usize];
                w.permitted |= 1 << (cap % 32);
                w.effective |= 1 << (cap % 32);
                kept.push(name);
            }
        }
        set(&want).map_err(|e| format!("capset: {e}"))?;
        // Kernels before 5.8 don't know CAP_BPF / CAP_PERFMON and drop them silently.
        let after = get().map_err(|e| format!("capget: {e}"))?;
        kept.retain(|name| KEEP.iter().any(|(cap, n)| n == name && has(&after, *cap)));
        Ok(kept)
    }

    /// BPF maps count against RLIMIT_MEMLOCK before 5.11; as root it can be lifted for good.
    fn raise_memlock() {
        let unlimited = libc::rlimit {
            rlim_cur: libc::RLIM_INFINITY,
            rlim_max: libc::RLIM_INFINITY,
        };
        // SAFETY: a valid rlimit.
        if unsafe { libc::setrlimit(libc::RLIMIT_MEMLOCK, &unlimited) } != 0 {
            tracing::debug!(
                "RLIMIT_MEMLOCK not raised: {}",
                std::io::Error::last_os_error()
            );
        }
    }
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
pub fn drop_to(user: &str, _data_dir: &Path) -> Result<Option<Keeper>, String> {
    Err(format!(
        "daemon.user = {user:?}: dropping privileges is not supported on this system (the service account is set by the installer)"
    ))
}
