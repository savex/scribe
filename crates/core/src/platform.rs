//! OS-specific defaults and facts: default paths, total RAM, volume size and free space.
//!
//! Default locations (decided, see the conventions skill):
//!
//! | OS | Config file | Data directory | Log file |
//! |---|---|---|---|
//! | Linux | `/etc/scribe/scribe.toml` | `/var/lib/scribe` | `/var/log/scribe/scribed.log` |
//! | macOS | `/Library/Application Support/scribe/scribe.toml` | `/Library/Application Support/scribe` | `/var/log/scribe/scribed.log` |
//! | Windows | `<install dir>\scribe.toml` | `<install dir>\data` | `<install dir>\logs\scribed.log` |
//!
//! `<install dir>` is the folder holding `scribed.exe`. Other Unix systems use the Linux layout.

use std::io;
use std::path::{Path, PathBuf};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Os {
    Linux,
    MacOs,
    Windows,
}

impl Os {
    pub const fn current() -> Self {
        if cfg!(target_os = "macos") {
            Os::MacOs
        } else if cfg!(windows) {
            Os::Windows
        } else {
            Os::Linux
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DefaultPaths {
    pub config_file: PathBuf,
    pub data_dir: PathBuf,
    pub log_file: PathBuf,
}

impl DefaultPaths {
    /// Defaults for `os`. On Windows everything sits next to the program at `exe`.
    pub fn for_os(os: Os, exe: &Path) -> Self {
        match os {
            Os::Linux => Self {
                config_file: PathBuf::from("/etc/scribe/scribe.toml"),
                data_dir: PathBuf::from("/var/lib/scribe"),
                log_file: PathBuf::from("/var/log/scribe/scribed.log"),
            },
            Os::MacOs => {
                let base = PathBuf::from("/Library/Application Support/scribe");
                Self {
                    config_file: base.join("scribe.toml"),
                    data_dir: base,
                    log_file: PathBuf::from("/var/log/scribe/scribed.log"),
                }
            }
            Os::Windows => {
                let dir = exe.parent().unwrap_or_else(|| Path::new("."));
                Self {
                    config_file: dir.join("scribe.toml"),
                    data_dir: dir.join("data"),
                    log_file: dir.join("logs").join("scribed.log"),
                }
            }
        }
    }

    /// Defaults for this OS and this program.
    pub fn current() -> io::Result<Self> {
        Ok(Self::for_os(Os::current(), &std::env::current_exe()?))
    }
}

/// Total physical memory in bytes.
pub fn total_memory() -> io::Result<u64> {
    imp::total_memory()
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct VolumeSpace {
    pub total: u64,
    pub available: u64,
}

/// Size and free space of the volume holding `path`. A path that doesn't exist yet is measured
/// at its nearest existing parent.
pub fn volume_space(path: &Path) -> io::Result<VolumeSpace> {
    let existing = path
        .ancestors()
        .find(|p| !p.as_os_str().is_empty() && p.exists())
        .ok_or_else(|| {
            io::Error::new(
                io::ErrorKind::NotFound,
                format!("no existing folder above {}", path.display()),
            )
        })?;
    let stats = fs4::statvfs(existing)?;
    Ok(VolumeSpace {
        total: stats.total_space(),
        available: stats.available_space(),
    })
}

/// `MemTotal` from `/proc/meminfo`, in bytes.
#[cfg_attr(not(target_os = "linux"), allow(dead_code))]
fn parse_meminfo(meminfo: &str) -> Option<u64> {
    let line = meminfo.lines().find(|l| l.starts_with("MemTotal:"))?;
    let kib: u64 = line.split_whitespace().nth(1)?.parse().ok()?;
    kib.checked_mul(1024)
}

#[cfg(target_os = "linux")]
mod imp {
    use std::io;

    pub fn total_memory() -> io::Result<u64> {
        let meminfo = std::fs::read_to_string("/proc/meminfo")?;
        super::parse_meminfo(&meminfo).ok_or_else(|| {
            io::Error::new(
                io::ErrorKind::InvalidData,
                "MemTotal not found in /proc/meminfo",
            )
        })
    }
}

#[cfg(target_os = "macos")]
mod imp {
    use std::io;

    pub fn total_memory() -> io::Result<u64> {
        let mut value: u64 = 0;
        let mut len = std::mem::size_of::<u64>();
        // SAFETY: `hw.memsize` is a 64-bit integer; `value` and `len` describe a buffer of that size.
        let rc = unsafe {
            libc::sysctlbyname(
                c"hw.memsize".as_ptr(),
                (&mut value as *mut u64).cast(),
                &mut len,
                std::ptr::null_mut(),
                0,
            )
        };
        if rc == 0 {
            Ok(value)
        } else {
            Err(io::Error::last_os_error())
        }
    }
}

#[cfg(windows)]
mod imp {
    use std::io;

    use windows_sys::Win32::System::SystemInformation::{GlobalMemoryStatusEx, MEMORYSTATUSEX};

    pub fn total_memory() -> io::Result<u64> {
        // SAFETY: MEMORYSTATUSEX is plain integers, so all-zero is valid; dwLength is set as the API requires.
        let mut status: MEMORYSTATUSEX = unsafe { std::mem::zeroed() };
        status.dwLength = std::mem::size_of::<MEMORYSTATUSEX>() as u32;
        // SAFETY: `status` is a valid, writable MEMORYSTATUSEX.
        if unsafe { GlobalMemoryStatusEx(&mut status) } != 0 {
            Ok(status.ullTotalPhys)
        } else {
            Err(io::Error::last_os_error())
        }
    }
}

#[cfg(not(any(target_os = "linux", target_os = "macos", windows)))]
mod imp {
    use std::io;

    pub fn total_memory() -> io::Result<u64> {
        Err(io::Error::new(
            io::ErrorKind::Unsupported,
            "total memory is not available on this OS",
        ))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    mod functional {
        use super::*;

        #[test]
        fn linux_defaults() {
            let p = DefaultPaths::for_os(Os::Linux, Path::new("/usr/bin/scribed"));
            assert_eq!(p.config_file, Path::new("/etc/scribe/scribe.toml"));
            assert_eq!(p.data_dir, Path::new("/var/lib/scribe"));
            assert_eq!(p.log_file, Path::new("/var/log/scribe/scribed.log"));
        }

        #[test]
        fn macos_defaults() {
            let p = DefaultPaths::for_os(Os::MacOs, Path::new("/usr/local/bin/scribed"));
            assert_eq!(
                p.config_file,
                Path::new("/Library/Application Support/scribe/scribe.toml")
            );
            assert_eq!(p.data_dir, Path::new("/Library/Application Support/scribe"));
            assert_eq!(p.log_file, Path::new("/var/log/scribe/scribed.log"));
        }

        #[test]
        fn windows_defaults_sit_next_to_the_program() {
            // Separators are the host's; the rule under test is "relative to the program's folder".
            let exe = Path::new("/opt/scribe/scribed.exe");
            let p = DefaultPaths::for_os(Os::Windows, exe);
            assert_eq!(p.config_file, Path::new("/opt/scribe").join("scribe.toml"));
            assert_eq!(p.data_dir, Path::new("/opt/scribe").join("data"));
            assert_eq!(
                p.log_file,
                Path::new("/opt/scribe").join("logs").join("scribed.log")
            );
        }

        #[test]
        fn current_matches_this_os() {
            let current = DefaultPaths::current().unwrap();
            let exe = std::env::current_exe().unwrap();
            assert_eq!(current, DefaultPaths::for_os(Os::current(), &exe));
        }

        #[test]
        fn reads_total_memory() {
            let bytes = total_memory().unwrap();
            assert!(bytes > 256 << 20, "implausible RAM size {bytes}");
        }

        #[test]
        fn measures_volumes_including_missing_paths() {
            let dir = std::env::temp_dir();
            let space = volume_space(&dir).unwrap();
            assert!(space.total > 0 && space.available <= space.total);

            let missing = dir.join("scribe-does-not-exist").join("spool");
            assert_eq!(volume_space(&missing).unwrap().total, space.total);
        }

        #[test]
        fn relative_paths_without_an_existing_parent_fail() {
            let err = volume_space(Path::new("no-such-folder-for-scribe")).unwrap_err();
            assert_eq!(err.kind(), io::ErrorKind::NotFound);
        }

        #[test]
        fn parses_meminfo() {
            let sample = "MemTotal:       16314356 kB\nMemFree:          151416 kB\n";
            assert_eq!(parse_meminfo(sample), Some(16_314_356 * 1024));
            assert_eq!(parse_meminfo("MemFree: 1 kB\n"), None);
            assert_eq!(parse_meminfo("MemTotal: lots kB\n"), None);
        }
    }
}
