//! The Linux eBPF sensor: loads and attaches `src/bpf/scribe.bpf.c`, then reads the ring
//! buffer (who) and the `AF_PACKET` socket (what) on one thread and joins them.

use std::cell::RefCell;
use std::mem::MaybeUninit;
use std::os::fd::{AsFd, AsRawFd, FromRawFd, OwnedFd};
use std::rc::Rc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::mpsc::{self, Sender};
use std::sync::{Arc, Mutex};
use std::thread::JoinHandle;
use std::time::Duration;

use libbpf_rs::skel::{OpenSkel, SkelBuilder};
use libbpf_rs::{Link, MapCore, MapFlags, RingBufferBuilder};
use scribe_core::{AttributionStats, Clock, Observation, Sensor, SensorError, SystemClock};
use scribe_sensor_pcap::decode::{self, LINKTYPE_RAW};
use scribe_sensor_pcap::flows::{FlowTracker, TrackerOptions};

use crate::join::Joiner;
use crate::owners::Owners;
use crate::record::Record;

#[allow(clippy::all, clippy::pedantic, unsafe_op_in_unsafe_fn)]
mod skel {
    include!(concat!(env!("OUT_DIR"), "/scribe.skel.rs"));
}
use skel::{ScribeSkel, ScribeSkelBuilder};

/// Opens and loads the programs into `object`, with or without the IPv6 UDP probe.
fn load(
    object: &mut MaybeUninit<libbpf_rs::OpenObject>,
    v6_udp: bool,
) -> libbpf_rs::Result<ScribeSkel<'_>> {
    let mut open = ScribeSkelBuilder::default().open(object)?;
    if let Some(rodata) = open.maps.rodata_data.as_deref_mut() {
        rodata.udp_repeat_ns = UDP_REPEAT.as_nanos() as u64;
        rodata.loopback_ifindex = loopback_index();
        if let Some((dev, ino)) = pid_namespace() {
            rodata.pidns_dev = dev;
            rodata.pidns_ino = ino;
        }
    }
    if !v6_udp {
        open.progs.udpv6_sendmsg_exit.set_autoload(false);
    }
    open.load()
}

/// A UDP socket reports a destination again after this long (`udp_repeat_ns`).
const UDP_REPEAT: Duration = Duration::from_secs(30);
/// Longest wait in `poll`: also how quickly `stop` is noticed.
const POLL_MS: i32 = 100;
/// Packets read per loop turn before the ring buffer is read again.
const PACKETS_PER_TURN: usize = 256;
/// Receive buffer of the packet socket.
const SOCKET_BUFFER: libc::c_int = 4 << 20;
const TICK: Duration = Duration::from_millis(250);

struct Running {
    stop: Arc<AtomicBool>,
    thread: JoinHandle<()>,
}

/// The eBPF sensor (plan option 7B). Needs root, or `CAP_BPF`, `CAP_PERFMON` and `CAP_NET_RAW`;
/// kernel 5.8+ on x86_64 and 6.0+ on arm64 (BTF, `fentry` / `fexit`, ring buffer).
pub struct EbpfSensor {
    payload: bool,
    clock: Arc<dyn Clock>,
    stats: Arc<Mutex<AttributionStats>>,
    running: Option<Running>,
}

impl Default for EbpfSensor {
    fn default() -> Self {
        Self::new(Arc::new(SystemClock))
    }
}

impl EbpfSensor {
    pub fn new(clock: Arc<dyn Clock>) -> Self {
        Self {
            payload: true,
            clock,
            stats: Arc::new(Mutex::new(AttributionStats::default())),
            running: None,
        }
    }
}

fn io(context: &str, e: impl std::fmt::Display) -> SensorError {
    SensorError::Io(std::io::Error::other(format!("{context}: {e}")))
}

fn os_error(context: &str) -> SensorError {
    let e = std::io::Error::last_os_error();
    match e.raw_os_error() {
        Some(libc::EPERM) | Some(libc::EACCES) => {
            SensorError::Permission(format!("{context}: {e}"))
        }
        _ => io(context, e),
    }
}

fn exe_path(pid: u32) -> Option<String> {
    std::fs::read_link(format!("/proc/{pid}/exe"))
        .ok()
        .map(|p| p.to_string_lossy().into_owned())
}

/// An `AF_PACKET` socket on every interface, with `filter` attached before it receives anything.
fn packet_socket(filter: std::os::fd::BorrowedFd<'_>) -> Result<OwnedFd, SensorError> {
    // SAFETY: plain socket calls on a descriptor this function owns; every pointer passed
    // points to a live local of the size given.
    unsafe {
        // Protocol 0: no packets until bound below, so none arrive unfiltered.
        let fd = libc::socket(
            libc::AF_PACKET,
            libc::SOCK_DGRAM | libc::SOCK_NONBLOCK | libc::SOCK_CLOEXEC,
            0,
        );
        if fd < 0 {
            return Err(os_error("packet socket"));
        }
        let fd = OwnedFd::from_raw_fd(fd);
        let prog = filter.as_raw_fd();
        if libc::setsockopt(
            fd.as_raw_fd(),
            libc::SOL_SOCKET,
            libc::SO_ATTACH_BPF,
            (&prog as *const libc::c_int).cast(),
            std::mem::size_of::<libc::c_int>() as libc::socklen_t,
        ) != 0
        {
            return Err(os_error("attaching the packet filter"));
        }
        let size = SOCKET_BUFFER;
        // A smaller buffer is fine; ignore a refusal.
        libc::setsockopt(
            fd.as_raw_fd(),
            libc::SOL_SOCKET,
            libc::SO_RCVBUF,
            (&size as *const libc::c_int).cast(),
            std::mem::size_of::<libc::c_int>() as libc::socklen_t,
        );
        let mut addr: libc::sockaddr_ll = std::mem::zeroed();
        addr.sll_family = libc::AF_PACKET as u16;
        addr.sll_protocol = (libc::ETH_P_ALL as u16).to_be();
        addr.sll_ifindex = 0; // every interface
        if libc::bind(
            fd.as_raw_fd(),
            (&addr as *const libc::sockaddr_ll).cast(),
            std::mem::size_of::<libc::sockaddr_ll>() as libc::socklen_t,
        ) != 0
        {
            return Err(os_error("binding the packet socket"));
        }
        Ok(fd)
    }
}

/// Device and inode of this process's pid namespace, so the programs report pids as scribed
/// sees them (it may run in a container). Processes outside that namespace get no process.
fn pid_namespace() -> Option<(u64, u64)> {
    use std::os::unix::fs::MetadataExt;
    let meta = std::fs::metadata("/proc/self/ns/pid").ok()?;
    Some((meta.dev(), meta.ino()))
}

fn loopback_index() -> u32 {
    // SAFETY: a NUL-terminated literal.
    match unsafe { libc::if_nametoindex(c"lo".as_ptr()) } {
        0 => 1,
        i => i,
    }
}

/// Sum of the `lost` per-CPU counter.
fn lost(map: &dyn MapCore) -> u64 {
    map.lookup_percpu(&0u32.to_ne_bytes(), MapFlags::ANY)
        .ok()
        .flatten()
        .map(|cpus| {
            cpus.iter()
                .filter_map(|v| {
                    v.get(..8)
                        .map(|b| u64::from_ne_bytes(b.try_into().unwrap()))
                })
                .sum()
        })
        .unwrap_or(0)
}

struct Loop {
    out: Sender<Observation>,
    stop: Arc<AtomicBool>,
    clock: Arc<dyn Clock>,
    payload: bool,
    stats: Arc<Mutex<AttributionStats>>,
}

impl Loop {
    /// Loads, attaches and runs until stopped; `ready` gets the outcome of loading.
    fn run(self, ready: mpsc::Sender<Result<(), SensorError>>) {
        // A second object store for the retry without the IPv6 UDP probe.
        let mut first = MaybeUninit::uninit();
        let mut second = MaybeUninit::uninit();
        let (skel, with_v6_udp) = match load(&mut first, true) {
            Ok(skel) => (skel, true),
            Err(e) => {
                // IPv6 built as a module without BTF: carry on without IPv6 UDP records.
                tracing::warn!(
                    "loading the eBPF programs failed ({e}); trying without the IPv6 UDP probe"
                );
                match load(&mut second, false) {
                    Ok(skel) => (skel, false),
                    Err(e) => {
                        let error = if e.kind() == libbpf_rs::ErrorKind::PermissionDenied {
                            SensorError::Permission(format!("loading the eBPF programs: {e}"))
                        } else {
                            io(
                                "loading the eBPF programs (kernel 5.8+ with BTF needed; 6.0+ on arm64)",
                                e,
                            )
                        };
                        let _ = ready.send(Err(error));
                        return;
                    }
                }
            }
        };

        let mut links: Vec<Link> = Vec::new();
        let mut attach = |prog: &libbpf_rs::ProgramMut<'_>, name: &str| match prog.attach() {
            Ok(link) => {
                links.push(link);
                Ok(())
            }
            Err(e) => Err(io(&format!("attaching {name}"), e)),
        };
        let attached = attach(&skel.progs.tcp_connect, "tcp_connect")
            .and_then(|()| attach(&skel.progs.udp_sendmsg_exit, "udp_sendmsg"));
        if let Err(e) = attached {
            let _ = ready.send(Err(e));
            return;
        }
        if with_v6_udp {
            if let Err(e) = attach(&skel.progs.udpv6_sendmsg_exit, "udpv6_sendmsg") {
                tracing::warn!("{e}; IPv6 UDP flows will have no process");
            }
        }

        let records: Rc<RefCell<Vec<Record>>> = Rc::default();
        let sink = records.clone();
        let mut bad = 0u64;
        let mut builder = RingBufferBuilder::new();
        let added = builder.add(&skel.maps.events, move |bytes: &[u8]| {
            match Record::parse(bytes) {
                Ok(r) => sink.borrow_mut().push(r),
                Err(e) => {
                    bad += 1;
                    if bad == 1 {
                        tracing::warn!("unreadable eBPF record: {e}");
                    }
                }
            }
            0
        });
        let ring = match added.map(|_| ()).and_then(|()| builder.build()) {
            Ok(r) => r,
            Err(e) => {
                let _ = ready.send(Err(io("ring buffer", e)));
                return;
            }
        };
        let socket = match packet_socket(skel.progs.packets.as_fd()) {
            Ok(s) => s,
            Err(e) => {
                let _ = ready.send(Err(e));
                return;
            }
        };
        let _ = ready.send(Ok(()));
        tracing::info!(
            ipv6_udp = with_v6_udp,
            "eBPF sensor attached (tcp_connect, udp_sendmsg, packet filter)"
        );

        let mut tracker = FlowTracker::new(TrackerOptions {
            payload: self.payload,
            ..TrackerOptions::default()
        });
        let owners = Owners::new(self.clock.clone(), Box::new(exe_path));
        let mut joiner = Joiner::new(owners, self.clock.clone());
        let mut buf = vec![0u8; 65_536];
        let mut last_tick = self.clock.now();
        let mut lost_seen = 0u64;
        let send = |obs: Vec<Observation>, out: &Sender<Observation>| {
            obs.into_iter().all(|o| out.send(o).is_ok())
        };
        let mut fds = [
            libc::pollfd {
                fd: ring.epoll_fd(),
                events: libc::POLLIN,
                revents: 0,
            },
            libc::pollfd {
                fd: socket.as_raw_fd(),
                events: libc::POLLIN,
                revents: 0,
            },
        ];
        'run: while !self.stop.load(Ordering::Relaxed) {
            // SAFETY: `fds` is a live array of two pollfd.
            unsafe { libc::poll(fds.as_mut_ptr(), fds.len() as libc::nfds_t, POLL_MS) };
            // Records first: they name the owners of the packets read next.
            let _ = ring.consume();
            for r in records.borrow_mut().drain(..) {
                joiner.record(&r);
            }
            for _ in 0..PACKETS_PER_TURN {
                // SAFETY: `buf` is writable for its length; the address arguments may be null.
                let n = unsafe {
                    libc::recv(
                        socket.as_raw_fd(),
                        buf.as_mut_ptr().cast(),
                        buf.len(),
                        libc::MSG_DONTWAIT,
                    )
                };
                if n <= 0 {
                    break;
                }
                let now = self.clock.now();
                if let Some(p) = decode::decode(LINKTYPE_RAW, &buf[..n as usize], now) {
                    let ready = joiner.push(tracker.push(&p));
                    if !send(ready, &self.out) {
                        break 'run;
                    }
                }
            }
            let now = self.clock.now();
            if now.duration_since(last_tick).unwrap_or_default() >= TICK {
                last_tick = now;
                let mut ready = joiner.push(tracker.tick(now));
                ready.extend(joiner.ready());
                if !send(ready, &self.out) {
                    break;
                }
                let l = lost(&skel.maps.lost);
                if l > lost_seen {
                    tracing::warn!(
                        lost = l - lost_seen,
                        "eBPF ring buffer full: connection records lost"
                    );
                    lost_seen = l;
                }
                *self.stats.lock().unwrap_or_else(|p| p.into_inner()) = joiner.stats();
            } else if !send(joiner.ready(), &self.out) {
                break;
            }
        }
        let mut rest = joiner.push(tracker.flush());
        rest.extend(joiner.flush());
        send(rest, &self.out);
        *self.stats.lock().unwrap_or_else(|p| p.into_inner()) = joiner.stats();
        drop(links);
    }
}

impl Sensor for EbpfSensor {
    fn name(&self) -> &'static str {
        "linux-ebpf"
    }

    fn has_process_info(&self) -> bool {
        true
    }

    fn set_payload(&mut self, needed: bool) {
        self.payload = needed;
    }

    fn attribution(&self) -> Option<AttributionStats> {
        Some(*self.stats.lock().unwrap_or_else(|p| p.into_inner()))
    }

    fn start(&mut self, out: Sender<Observation>) -> Result<(), SensorError> {
        if self.running.is_some() {
            return Ok(());
        }
        let stop = Arc::new(AtomicBool::new(false));
        let (ready, outcome) = mpsc::channel();
        let job = Loop {
            out,
            stop: stop.clone(),
            clock: self.clock.clone(),
            payload: self.payload,
            stats: self.stats.clone(),
        };
        let thread = std::thread::Builder::new()
            .name("scribe-ebpf".into())
            .spawn(move || job.run(ready))
            .map_err(SensorError::Io)?;
        match outcome.recv() {
            Ok(Ok(())) => {
                self.running = Some(Running { stop, thread });
                Ok(())
            }
            Ok(Err(e)) => {
                let _ = thread.join();
                Err(e)
            }
            Err(_) => {
                let _ = thread.join();
                Err(io("eBPF sensor", "the loader thread ended"))
            }
        }
    }

    /// Stops reading (within about 100 ms) and detaches the programs.
    fn stop(&mut self) {
        if let Some(r) = self.running.take() {
            r.stop.store(true, Ordering::Relaxed);
            let _ = r.thread.join();
        }
    }
}

impl Drop for EbpfSensor {
    fn drop(&mut self) {
        self.stop();
    }
}
