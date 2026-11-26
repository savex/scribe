//! Process paths from ETW, so scribed needs no rights over other processes (it can run as
//! `NT SERVICE\scribed`, which can't open another user's process to read its path).
//!
//! **Microsoft-Windows-Kernel-Process** (`{22FB2CD6-0E7B-422B-A0C7-2FAD1FD0E716}`, keyword
//! `WINEVENT_KEYWORD_PROCESS` 0x10):
//!
//! | Event | Meaning | Fields used |
//! |---|---|---|
//! | 1 | process started | `ProcessID` u32 first, `ImageName` (UTF-16, NUL-terminated) after a run of fixed fields that grows with the event version |
//! | 2 | process stopped | `ProcessID` u32 |
//! | 15 | process rundown (one per running process when the session asks for its state) | as event 1 |
//!
//! `ImageName` is an NT path (`\Device\HarddiskVolume3\Windows\System32\curl.exe`);
//! [`DevicePaths`] turns it into the Win32 path `QueryFullProcessImageNameW` returns. The fields
//! before it differ by version: `CreateTime`, `ParentProcessID`, `SessionID` (version 0, Windows
//! 7); `Flags` (1); process sequence numbers, token elevation and a mandatory-label SID (Windows
//! 10 and later). So the parser takes the first NT path in the data (`\Device\`, `\??\`,
//! `\SystemRoot\`), the first string field of every version.

use std::collections::HashMap;
use std::time::{Duration, SystemTime};

use crate::events::EventError;

/// `Microsoft-Windows-Kernel-Process`.
pub const KERNEL_PROCESS: &str = "22FB2CD6-0E7B-422B-A0C7-2FAD1FD0E716";
/// `WINEVENT_KEYWORD_PROCESS`: process start, stop and rundown only.
pub const KEYWORD_PROCESS: u64 = 0x10;

pub const PROCESS_START: u16 = 1;
pub const PROCESS_STOP: u16 = 2;
pub const PROCESS_RUNDOWN: u16 = 15;

/// A stopped process's path is kept this long, for its connections reported late.
pub const STOPPED_TTL: Duration = Duration::from_secs(60);
/// Most processes remembered; stopped ones go first, then all.
pub const MAX_PROCESSES: usize = 65_536;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ProcKind {
    Start,
    Stop,
    Rundown,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProcEvent {
    pub kind: ProcKind,
    pub pid: u32,
    /// The NT path; `None` for a stop, and for processes without an image file (`System`,
    /// `Registry`, `MemCompression`).
    pub image: Option<String>,
}

/// How an `ImageName` starts.
const NT_PREFIXES: [&str; 3] = ["\\Device\\", "\\??\\", "\\SystemRoot\\"];

/// The offset of the first NT path in `data` after the process id.
fn image_offset(data: &[u8]) -> Option<usize> {
    let prefixes: Vec<Vec<u8>> = NT_PREFIXES
        .iter()
        .map(|p| p.encode_utf16().flat_map(u16::to_le_bytes).collect())
        .collect();
    (4..data.len()).find(|&at| prefixes.iter().any(|p| data[at..].starts_with(p)))
}

/// A NUL-terminated UTF-16LE string at `at`, or `None` without the NUL.
fn utf16z(b: &[u8], at: usize) -> Option<String> {
    let mut units = Vec::new();
    let mut i = at;
    loop {
        let pair = b.get(i..i + 2)?;
        let u = u16::from_le_bytes([pair[0], pair[1]]);
        if u == 0 {
            return Some(String::from_utf16_lossy(&units));
        }
        units.push(u);
        i += 2;
    }
}

impl ProcEvent {
    /// Reads a Kernel-Process event; `Ok(None)` for the events the sensor doesn't use.
    pub fn parse(id: u16, data: &[u8]) -> Result<Option<Self>, EventError> {
        let kind = match id {
            PROCESS_START => ProcKind::Start,
            PROCESS_STOP => ProcKind::Stop,
            PROCESS_RUNDOWN => ProcKind::Rundown,
            _ => return Ok(None),
        };
        let need = if kind == ProcKind::Stop { 4 } else { 22 };
        if data.len() < need {
            return Err(EventError::Short {
                id,
                len: data.len(),
                need,
            });
        }
        let pid = u32::from_le_bytes(data[0..4].try_into().expect("4 bytes"));
        let image = match kind {
            ProcKind::Stop => None,
            _ => image_offset(data).and_then(|at| utf16z(data, at)),
        };
        Ok(Some(Self { kind, pid, image }))
    }

    /// The event id and user data Windows 10 and later would deliver (for tests and replays).
    pub fn to_bytes(&self) -> (u16, Vec<u8>) {
        let id = match self.kind {
            ProcKind::Start => PROCESS_START,
            ProcKind::Stop => PROCESS_STOP,
            ProcKind::Rundown => PROCESS_RUNDOWN,
        };
        let mut b = Vec::new();
        b.extend_from_slice(&self.pid.to_le_bytes());
        if self.kind != ProcKind::Stop {
            b.extend_from_slice(&7u64.to_le_bytes()); // ProcessSequenceNumber
            b.extend_from_slice(&0u64.to_le_bytes()); // CreateTime
            b.extend_from_slice(&4u32.to_le_bytes()); // ParentProcessID
            b.extend_from_slice(&3u64.to_le_bytes()); // ParentProcessSequenceNumber
            b.extend_from_slice(&1u32.to_le_bytes()); // SessionID
            b.extend_from_slice(&0u32.to_le_bytes()); // Flags
            b.extend_from_slice(&1u32.to_le_bytes()); // ProcessTokenElevationType
            b.extend_from_slice(&0u32.to_le_bytes()); // ProcessTokenIsElevated
                                                      // MandatoryLabel: S-1-16-8192 (medium integrity).
            b.extend_from_slice(&[1, 1, 0, 0, 0, 0, 0, 16, 0, 0x20, 0, 0]);
            for u in self.image.as_deref().unwrap_or("").encode_utf16() {
                b.extend_from_slice(&u.to_le_bytes());
            }
            b.extend_from_slice(&[0, 0]);
            b.extend_from_slice(&[0; 8]); // ImageChecksum, TimeDateStamp
        }
        (id, b)
    }
}

/// NT device names of the drives (`\Device\HarddiskVolume3` → `C:`), from `QueryDosDeviceW`.
#[derive(Debug, Clone, Default)]
pub struct DevicePaths {
    drives: Vec<(String, String)>,
}

impl DevicePaths {
    /// From `(device, drive)` pairs, e.g. `("\Device\HarddiskVolume3", "C:")`.
    pub fn new(drives: impl IntoIterator<Item = (String, String)>) -> Self {
        Self {
            drives: drives.into_iter().collect(),
        }
    }

    /// The drives of this machine (letters with no device are left out), and `\SystemRoot` (early
    /// system processes such as `smss.exe`).
    #[cfg(windows)]
    pub fn system() -> Self {
        use windows_sys::Win32::Storage::FileSystem::QueryDosDeviceW;
        let mut drives = Vec::new();
        for letter in b'A'..=b'Z' {
            let drive = format!("{}:", letter as char);
            let name: Vec<u16> = drive.encode_utf16().chain(std::iter::once(0)).collect();
            let mut buf = vec![0u16; 1024];
            // SAFETY: a NUL-terminated name and a buffer of the given length.
            let n = unsafe { QueryDosDeviceW(name.as_ptr(), buf.as_mut_ptr(), buf.len() as u32) };
            if n == 0 {
                continue;
            }
            // The first of the NUL-separated targets.
            let end = buf.iter().position(|&u| u == 0).unwrap_or(n as usize);
            drives.push((String::from_utf16_lossy(&buf[..end]), drive));
        }
        if let Some(root) = std::env::var_os("SystemRoot") {
            drives.push((
                r"\SystemRoot".to_owned(),
                root.to_string_lossy().into_owned(),
            ));
        }
        Self { drives }
    }

    /// The Win32 path for an NT path; unknown devices are left as they are.
    pub fn win32(&self, nt: &str) -> String {
        if let Some(rest) = nt.strip_prefix(r"\??\") {
            return rest.to_owned();
        }
        for (device, drive) in &self.drives {
            let Some(head) = nt.get(..device.len()) else {
                continue;
            };
            let rest = &nt[device.len()..];
            if head.eq_ignore_ascii_case(device) && rest.starts_with('\\') {
                return format!("{drive}{rest}");
            }
        }
        nt.to_owned()
    }
}

/// Each running process's path, from the start and rundown events.
#[derive(Debug, Default)]
pub struct Processes {
    devices: DevicePaths,
    /// pid → Win32 path and when the process stopped.
    paths: HashMap<u32, (String, Option<SystemTime>)>,
}

impl Processes {
    pub fn new(devices: DevicePaths) -> Self {
        Self {
            devices,
            paths: HashMap::new(),
        }
    }

    pub fn apply(&mut self, e: &ProcEvent, now: SystemTime) {
        match e.kind {
            ProcKind::Start | ProcKind::Rundown => {
                let Some(image) = &e.image else { return };
                if self.paths.len() >= MAX_PROCESSES && !self.paths.contains_key(&e.pid) {
                    self.prune(now);
                }
                self.paths.insert(e.pid, (self.devices.win32(image), None));
            }
            ProcKind::Stop => {
                if let Some((_, stopped)) = self.paths.get_mut(&e.pid) {
                    *stopped = Some(now);
                }
            }
        }
    }

    fn prune(&mut self, now: SystemTime) {
        self.paths.retain(|_, (_, stopped)| {
            stopped.is_none_or(|t| now.duration_since(t).unwrap_or_default() < STOPPED_TTL)
        });
        if self.paths.len() >= MAX_PROCESSES {
            self.paths.clear();
        }
    }

    /// The process's path, also for a while after it stopped.
    pub fn path(&self, pid: u32) -> Option<&str> {
        self.paths.get(&pid).map(|(p, _)| p.as_str())
    }

    pub fn len(&self) -> usize {
        self.paths.len()
    }

    pub fn is_empty(&self) -> bool {
        self.paths.is_empty()
    }
}
