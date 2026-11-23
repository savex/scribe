//! libpcap / Npcap, loaded at run time with `libloading`: nothing links against it, so builds need
//! no SDK and `scribed` starts (without this sensor) where the library is missing.
//!
//! Library names: macOS `libpcap.A.dylib` (part of the system), Linux `libpcap.so.1` (package
//! `libpcap0.8` / `libpcap`), Windows Npcap's `wpcap.dll` in `System32\Npcap`. `SCRIBE_LIBPCAP`
//! names another file.

use std::ffi::{c_char, c_int, c_uint, c_void, CStr, CString};
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::sync::{Arc, OnceLock};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use libloading::Library;

const ERRBUF_SIZE: usize = 256;
pub const PCAP_ERROR_PERM_DENIED: c_int = -8;
pub const PCAP_IF_LOOPBACK: u32 = 0x1;
pub const PCAP_IF_UP: u32 = 0x2;
pub const PCAP_IF_RUNNING: u32 = 0x4;

#[repr(C)]
struct PcapIf {
    next: *mut PcapIf,
    name: *mut c_char,
    description: *mut c_char,
    addresses: *mut PcapAddr,
    flags: u32,
}

#[repr(C)]
struct PcapAddr {
    next: *mut PcapAddr,
    addr: *mut u8,
    netmask: *mut u8,
    broadaddr: *mut u8,
    dstaddr: *mut u8,
}

#[repr(C)]
struct BpfProgram {
    bf_len: c_uint,
    bf_insns: *mut c_void,
}

/// `struct timeval` as libpcap's packet header carries it.
#[cfg(windows)]
#[repr(C)]
struct TimeVal {
    sec: i32,
    usec: i32,
}

#[cfg(target_os = "macos")]
#[repr(C)]
struct TimeVal {
    sec: i64,
    usec: i32,
}

#[cfg(not(any(windows, target_os = "macos")))]
#[repr(C)]
struct TimeVal {
    sec: std::ffi::c_long,
    usec: std::ffi::c_long,
}

#[repr(C)]
struct PktHdr {
    ts: TimeVal,
    caplen: u32,
    len: u32,
}

type Pcap = c_void;

struct Api {
    _lib: Library,
    findalldevs: unsafe extern "C" fn(*mut *mut PcapIf, *mut c_char) -> c_int,
    freealldevs: unsafe extern "C" fn(*mut PcapIf),
    create: unsafe extern "C" fn(*const c_char, *mut c_char) -> *mut Pcap,
    set_snaplen: unsafe extern "C" fn(*mut Pcap, c_int) -> c_int,
    set_promisc: unsafe extern "C" fn(*mut Pcap, c_int) -> c_int,
    set_timeout: unsafe extern "C" fn(*mut Pcap, c_int) -> c_int,
    set_immediate_mode: unsafe extern "C" fn(*mut Pcap, c_int) -> c_int,
    set_buffer_size: unsafe extern "C" fn(*mut Pcap, c_int) -> c_int,
    activate: unsafe extern "C" fn(*mut Pcap) -> c_int,
    compile: unsafe extern "C" fn(*mut Pcap, *mut BpfProgram, *const c_char, c_int, u32) -> c_int,
    setfilter: unsafe extern "C" fn(*mut Pcap, *mut BpfProgram) -> c_int,
    freecode: unsafe extern "C" fn(*mut BpfProgram),
    next_ex: unsafe extern "C" fn(*mut Pcap, *mut *mut PktHdr, *mut *const u8) -> c_int,
    setnonblock: unsafe extern "C" fn(*mut Pcap, c_int, *mut c_char) -> c_int,
    datalink: unsafe extern "C" fn(*mut Pcap) -> c_int,
    geterr: unsafe extern "C" fn(*mut Pcap) -> *mut c_char,
    close: unsafe extern "C" fn(*mut Pcap),
}

/// A loaded libpcap.
#[derive(Clone)]
pub struct Lib(Arc<Api>);

fn candidates() -> Vec<String> {
    if let Ok(path) = std::env::var("SCRIBE_LIBPCAP") {
        return vec![path];
    }
    if cfg!(target_os = "macos") {
        vec!["libpcap.A.dylib".into(), "/usr/lib/libpcap.A.dylib".into()]
    } else if cfg!(windows) {
        let root = std::env::var("SystemRoot").unwrap_or_else(|_| "C:\\Windows".into());
        vec![
            format!("{root}\\System32\\Npcap\\wpcap.dll"),
            "wpcap.dll".into(),
        ]
    } else {
        vec![
            "libpcap.so.1".into(),
            "libpcap.so.0.8".into(),
            "libpcap.so".into(),
        ]
    }
}

/// Npcap's wpcap.dll needs Packet.dll from its own folder.
#[cfg(windows)]
fn open_library(path: &str) -> Result<Library, libloading::Error> {
    const LOAD_WITH_ALTERED_SEARCH_PATH: u32 = 0x8;
    // SAFETY: loading Npcap runs its initialisers; nothing else to uphold.
    unsafe {
        libloading::os::windows::Library::load_with_flags(path, LOAD_WITH_ALTERED_SEARCH_PATH)
            .map(Library::from)
    }
}

#[cfg(not(windows))]
fn open_library(path: &str) -> Result<Library, libloading::Error> {
    // SAFETY: loading libpcap runs its initialisers; nothing else to uphold.
    unsafe { Library::new(path) }
}

impl Lib {
    /// Load libpcap once per process.
    pub fn load() -> Result<Lib, String> {
        static LIB: OnceLock<Result<Lib, String>> = OnceLock::new();
        LIB.get_or_init(Self::load_uncached).clone()
    }

    fn load_uncached() -> Result<Lib, String> {
        let mut tried = Vec::new();
        for path in candidates() {
            match open_library(&path) {
                Ok(lib) => return Self::bind(lib).map_err(|e| format!("{path}: {e}")),
                Err(e) => tried.push(format!("{path}: {e}")),
            }
        }
        Err(format!(
            "libpcap not found ({}); install libpcap (Linux) or Npcap (Windows), or set SCRIBE_LIBPCAP",
            tried.join("; ")
        ))
    }

    fn bind(lib: Library) -> Result<Lib, libloading::Error> {
        // SAFETY: the symbol types match libpcap's documented C signatures; the library stays
        // loaded as long as `Api` lives.
        unsafe {
            macro_rules! sym {
                ($name:literal) => {
                    *lib.get(concat!($name, "\0").as_bytes())?
                };
            }
            let api = Api {
                findalldevs: sym!("pcap_findalldevs"),
                freealldevs: sym!("pcap_freealldevs"),
                create: sym!("pcap_create"),
                set_snaplen: sym!("pcap_set_snaplen"),
                set_promisc: sym!("pcap_set_promisc"),
                set_timeout: sym!("pcap_set_timeout"),
                set_immediate_mode: sym!("pcap_set_immediate_mode"),
                set_buffer_size: sym!("pcap_set_buffer_size"),
                activate: sym!("pcap_activate"),
                compile: sym!("pcap_compile"),
                setfilter: sym!("pcap_setfilter"),
                freecode: sym!("pcap_freecode"),
                next_ex: sym!("pcap_next_ex"),
                setnonblock: sym!("pcap_setnonblock"),
                datalink: sym!("pcap_datalink"),
                geterr: sym!("pcap_geterr"),
                close: sym!("pcap_close"),
                _lib: lib,
            };
            Ok(Lib(Arc::new(api)))
        }
    }

    /// Every capture device with its flags and addresses.
    pub fn devices(&self) -> Result<Vec<Device>, String> {
        let mut errbuf = [0 as c_char; ERRBUF_SIZE];
        let mut list: *mut PcapIf = std::ptr::null_mut();
        // SAFETY: valid out-pointer and error buffer; the list is freed below.
        let rc = unsafe { (self.0.findalldevs)(&mut list, errbuf.as_mut_ptr()) };
        if rc != 0 {
            return Err(errbuf_text(&errbuf));
        }
        let mut out = Vec::new();
        let mut node = list;
        // SAFETY: libpcap's linked list stays valid until pcap_freealldevs.
        unsafe {
            while !node.is_null() {
                let d = &*node;
                let mut addresses = Vec::new();
                let mut a = d.addresses;
                while !a.is_null() {
                    if let Some(ip) = sockaddr_ip((*a).addr) {
                        addresses.push(ip);
                    }
                    a = (*a).next;
                }
                out.push(Device {
                    name: cstr(d.name),
                    description: cstr(d.description),
                    flags: d.flags,
                    addresses,
                });
                node = d.next;
            }
            (self.0.freealldevs)(list);
        }
        Ok(out)
    }

    /// Open `device` for capture of TCP and UDP: non-blocking reads, no promiscuous mode.
    ///
    /// Non-blocking because a blocking read doesn't always return at its timeout (Linux with
    /// immediate mode waits for a packet), and `stop` must not wait for traffic.
    pub fn open(&self, device: &str) -> Result<Handle, OpenError> {
        let name = CString::new(device).map_err(|_| OpenError::Other("bad device name".into()))?;
        let mut errbuf = [0 as c_char; ERRBUF_SIZE];
        let api = &self.0;
        // SAFETY: plain libpcap calls on a handle we own; it's closed on every error path and by
        // Handle's Drop.
        unsafe {
            let p = (api.create)(name.as_ptr(), errbuf.as_mut_ptr());
            if p.is_null() {
                return Err(OpenError::Other(errbuf_text(&errbuf)));
            }
            let handle = Handle {
                lib: self.clone(),
                p,
            };
            (api.set_snaplen)(p, 65_535);
            (api.set_promisc)(p, 0);
            (api.set_timeout)(p, 100);
            (api.set_immediate_mode)(p, 1);
            (api.set_buffer_size)(p, 8 << 20);
            let rc = (api.activate)(p);
            if rc == PCAP_ERROR_PERM_DENIED {
                return Err(OpenError::Permission(handle.error()));
            }
            if rc < 0 {
                return Err(OpenError::Other(handle.error()));
            }
            let filter = CString::new("tcp or udp").expect("no NUL");
            let mut prog = BpfProgram {
                bf_len: 0,
                bf_insns: std::ptr::null_mut(),
            };
            // 0xffffffff = PCAP_NETMASK_UNKNOWN (only matters for broadcast filters).
            if (api.compile)(p, &mut prog, filter.as_ptr(), 1, 0xffff_ffff) != 0 {
                return Err(OpenError::Other(handle.error()));
            }
            let set = (api.setfilter)(p, &mut prog);
            (api.freecode)(&mut prog);
            if set != 0 {
                return Err(OpenError::Other(handle.error()));
            }
            if (api.setnonblock)(p, 1, errbuf.as_mut_ptr()) != 0 {
                return Err(OpenError::Other(errbuf_text(&errbuf)));
            }
            Ok(handle)
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum OpenError {
    Permission(String),
    Other(String),
}

/// A capture device as `pcap_findalldevs` lists it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Device {
    pub name: String,
    pub description: String,
    pub flags: u32,
    pub addresses: Vec<IpAddr>,
}

impl Device {
    pub fn is_loopback(&self) -> bool {
        self.flags & PCAP_IF_LOOPBACK != 0
    }

    /// Up and running (older libpcap and Npcap leave these flags unset: then any device counts).
    pub fn is_up(&self) -> bool {
        self.flags & (PCAP_IF_UP | PCAP_IF_RUNNING) == (PCAP_IF_UP | PCAP_IF_RUNNING)
            || self.flags & (PCAP_IF_UP | PCAP_IF_RUNNING) == 0
    }
}

/// An open capture.
pub struct Handle {
    lib: Lib,
    p: *mut Pcap,
}

// SAFETY: a pcap_t may move between threads; it is only used by one thread at a time.
unsafe impl Send for Handle {}

/// What one read gave.
pub enum Next<'a> {
    Packet { ts: SystemTime, data: &'a [u8] },
    Timeout,
    Error(String),
}

impl Handle {
    pub fn linktype(&self) -> i32 {
        // SAFETY: valid open handle.
        unsafe { (self.lib.0.datalink)(self.p) }
    }

    fn error(&self) -> String {
        // SAFETY: valid handle; geterr returns a NUL-terminated buffer owned by the handle.
        unsafe { cstr((self.lib.0.geterr)(self.p)) }
    }

    /// The next packet, or `Timeout` at once when none is waiting.
    pub fn read(&mut self) -> Next<'_> {
        let mut hdr: *mut PktHdr = std::ptr::null_mut();
        let mut data: *const u8 = std::ptr::null();
        // SAFETY: valid handle and out-pointers; the data stays valid until the next call, which
        // the borrow of `self` enforces.
        unsafe {
            match (self.lib.0.next_ex)(self.p, &mut hdr, &mut data) {
                1 if !hdr.is_null() && !data.is_null() => {
                    let h = &*hdr;
                    let secs = u64::try_from(h.ts.sec).unwrap_or(0);
                    let micros = u64::try_from(h.ts.usec).unwrap_or(0);
                    Next::Packet {
                        ts: UNIX_EPOCH + Duration::from_secs(secs) + Duration::from_micros(micros),
                        data: std::slice::from_raw_parts(data, h.caplen as usize),
                    }
                }
                0 | 1 => Next::Timeout,
                _ => Next::Error(self.error()),
            }
        }
    }
}

impl Drop for Handle {
    fn drop(&mut self) {
        // SAFETY: closed exactly once.
        unsafe { (self.lib.0.close)(self.p) }
    }
}

fn errbuf_text(buf: &[c_char]) -> String {
    // SAFETY: libpcap writes a NUL-terminated message into the buffer.
    unsafe { CStr::from_ptr(buf.as_ptr()) }
        .to_string_lossy()
        .into_owned()
}

/// # Safety
/// `p` is null or a NUL-terminated string.
unsafe fn cstr(p: *const c_char) -> String {
    if p.is_null() {
        String::new()
    } else {
        CStr::from_ptr(p).to_string_lossy().into_owned()
    }
}

/// The address family field of a `sockaddr`: BSDs and macOS have a length byte first.
const fn family_offset() -> (usize, bool) {
    if cfg!(any(
        target_os = "macos",
        target_os = "freebsd",
        target_os = "openbsd",
        target_os = "netbsd"
    )) {
        (1, false)
    } else {
        (0, true)
    }
}

const AF_INET: u16 = 2;
const AF_INET6: u16 = if cfg!(windows) {
    23
} else if cfg!(target_os = "macos") {
    30
} else if cfg!(target_os = "freebsd") {
    28
} else {
    10
};

/// IPv4 or IPv6 address in a `sockaddr` (others, e.g. link-layer, are `None`).
///
/// # Safety
/// `sa` is null or points to a sockaddr libpcap returned (`sockaddr_in6`-sized for IPv6).
unsafe fn sockaddr_ip(sa: *const u8) -> Option<IpAddr> {
    if sa.is_null() {
        return None;
    }
    let (at, wide) = family_offset();
    let family = if wide {
        u16::from_ne_bytes([*sa, *sa.add(1)])
    } else {
        u16::from(*sa.add(at))
    };
    match family {
        AF_INET => {
            let b = std::slice::from_raw_parts(sa.add(4), 4);
            Some(IpAddr::V4(Ipv4Addr::new(b[0], b[1], b[2], b[3])))
        }
        AF_INET6 => {
            let b: [u8; 16] = std::slice::from_raw_parts(sa.add(8), 16).try_into().ok()?;
            Some(IpAddr::V6(Ipv6Addr::from(b)))
        }
        _ => None,
    }
}
