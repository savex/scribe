//! FUN-SN03: Kernel-Process events (start, stop, rundown) give each process's Win32 path, with no
//! rights over the process.

use std::time::{Duration, SystemTime};

use scribe_sensor_windows::processes::{
    MAX_PROCESSES, PROCESS_RUNDOWN, PROCESS_START, PROCESS_STOP, STOPPED_TTL,
};
use scribe_sensor_windows::{DevicePaths, EventError, ProcEvent, ProcKind, Processes};

const CURL: &str = r"\Device\HarddiskVolume3\Windows\System32\curl.exe";

fn devices() -> DevicePaths {
    DevicePaths::new([
        (r"\Device\HarddiskVolume3".to_owned(), "C:".to_owned()),
        (r"\Device\HarddiskVolume31".to_owned(), "D:".to_owned()),
    ])
}

fn start(pid: u32, image: &str) -> ProcEvent {
    ProcEvent {
        kind: ProcKind::Start,
        pid,
        image: Some(image.to_owned()),
    }
}

#[test]
fn process_events_round_trip() {
    for e in [
        start(4321, CURL),
        ProcEvent {
            kind: ProcKind::Rundown,
            pid: 77,
            image: Some(CURL.to_owned()),
        },
        ProcEvent {
            kind: ProcKind::Stop,
            pid: 4321,
            image: None,
        },
    ] {
        let (id, bytes) = e.to_bytes();
        assert_eq!(ProcEvent::parse(id, &bytes).unwrap(), Some(e));
    }
    assert_eq!(start(1, CURL).to_bytes().0, PROCESS_START);
    assert_eq!(ProcEvent::parse(5, &[0; 64]).unwrap(), None);
}

#[test]
fn process_start_version_0_without_flags() {
    // Windows 7 layout: ImageName right after SessionID.
    let mut b = 4321u32.to_le_bytes().to_vec();
    b.extend_from_slice(&[0; 8]);
    b.extend_from_slice(&4u32.to_le_bytes());
    b.extend_from_slice(&1u32.to_le_bytes());
    for u in CURL.encode_utf16() {
        b.extend_from_slice(&u.to_le_bytes());
    }
    b.extend_from_slice(&[0, 0]);
    let e = ProcEvent::parse(PROCESS_START, &b).unwrap().unwrap();
    assert_eq!(e.image.as_deref(), Some(CURL));
    let e = ProcEvent::parse(PROCESS_RUNDOWN, &b).unwrap().unwrap();
    assert_eq!((e.kind, e.pid), (ProcKind::Rundown, 4321));
}

#[test]
fn process_events_short_or_without_image() {
    assert_eq!(
        ProcEvent::parse(PROCESS_START, &[0; 10]),
        Err(EventError::Short {
            id: PROCESS_START,
            len: 10,
            need: 22
        })
    );
    assert!(ProcEvent::parse(PROCESS_STOP, &[1, 0]).is_err());
    // `System` and friends: no NT path, no image (and a missing NUL is not one either).
    let (id, b) = start(4, "System").to_bytes();
    assert_eq!(ProcEvent::parse(id, &b).unwrap().unwrap().image, None);
    let (id, mut b) = start(9, CURL).to_bytes();
    b.truncate(30);
    assert_eq!(ProcEvent::parse(id, &b).unwrap().unwrap().image, None);
}

#[test]
fn device_paths_to_win32() {
    let d = devices();
    assert_eq!(d.win32(CURL), r"C:\Windows\System32\curl.exe");
    // The longest name isn't taken for a prefix of another.
    assert_eq!(
        d.win32(r"\Device\HarddiskVolume31\tools\app.exe"),
        r"D:\tools\app.exe"
    );
    assert_eq!(
        d.win32(r"\device\harddiskvolume3\x.exe"),
        r"C:\x.exe",
        "device names compare without case"
    );
    assert_eq!(d.win32(r"\??\C:\x.exe"), r"C:\x.exe");
    assert_eq!(
        d.win32(r"\Device\Mup\server\share\x.exe"),
        r"\Device\Mup\server\share\x.exe",
        "unknown devices stay as they are"
    );
}

#[test]
fn processes_keep_paths_after_stop_for_a_while() {
    let t0 = SystemTime::UNIX_EPOCH + Duration::from_secs(1_800_000_000);
    let mut p = Processes::new(devices());
    p.apply(&start(4321, CURL), t0);
    p.apply(
        &ProcEvent {
            kind: ProcKind::Rundown,
            pid: 77,
            image: Some(r"\Device\HarddiskVolume3\a.exe".to_owned()),
        },
        t0,
    );
    assert_eq!(p.path(4321), Some(r"C:\Windows\System32\curl.exe"));
    assert_eq!(p.path(77), Some(r"C:\a.exe"));
    assert_eq!(p.path(5), None);

    let stop = ProcEvent {
        kind: ProcKind::Stop,
        pid: 4321,
        image: None,
    };
    p.apply(&stop, t0);
    assert_eq!(
        p.path(4321),
        Some(r"C:\Windows\System32\curl.exe"),
        "a late connection still gets its path"
    );
    // The pid is reused by a new process.
    p.apply(&start(4321, r"\Device\HarddiskVolume3\b.exe"), t0);
    assert_eq!(p.path(4321), Some(r"C:\b.exe"));

    // Full: stopped processes older than STOPPED_TTL go first.
    p.apply(&stop, t0);
    let later = t0 + STOPPED_TTL + Duration::from_secs(1);
    for pid in 100_000..100_000 + MAX_PROCESSES as u32 - 2 {
        p.apply(&start(pid, CURL), later);
    }
    assert_eq!(p.len(), MAX_PROCESSES);
    p.apply(&start(9, CURL), later);
    assert_eq!(p.path(4321), None);
    assert_eq!(p.path(77), Some(r"C:\a.exe"));
    assert_eq!(p.len(), MAX_PROCESSES);
}
