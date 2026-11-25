//! The ETW sensor (Windows): a real-time session on Kernel-Network, DNS-Client and
//! Kernel-Process, joined with packets from Npcap when it is installed.
//!
//! Threads:
//! - `scribe-etw`: `ProcessTrace` on the session; its callback copies each event's id and user
//!   data into a channel and returns (ETW drops events while a callback is slow);
//! - `scribe-etw-join`: parses the events, keeps each process's path (from its start event, or the
//!   rundown the session asks for at start), reports connections to the join and makes flows from
//!   them when there are no packets, or joins them with the pcap sensor's observations;
//! - the pcap sensor's own threads, when Npcap loads.
//!
//! The session needs Administrator rights or the Performance Log Users group (the installer adds
//! `NT SERVICE\scribed` to it). Paths come from Kernel-Process, so reading other processes needs
//! no rights; `QueryFullProcessImageNameW` is only the fallback. Events arrive
//! about once a second (`FlushTimer`), so packet observations wait up to [`HOLD`] for theirs.

use std::mem::{offset_of, size_of};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::mpsc::{self, Receiver, RecvTimeoutError, Sender};
use std::sync::{Arc, Mutex};
use std::thread::JoinHandle;
use std::time::Duration;

use scribe_core::{AttributionStats, Clock, Observation, Sensor, SensorError, SystemClock};
use scribe_process::join::{Joiner, Owners};
use scribe_sensor_pcap::PcapSensor;
use windows_sys::core::GUID;
use windows_sys::Win32::Foundation::{ERROR_ACCESS_DENIED, ERROR_ALREADY_EXISTS, ERROR_SUCCESS};
use windows_sys::Win32::System::Diagnostics::Etw::{
    CloseTrace, ControlTraceW, EnableTraceEx2, OpenTraceW, ProcessTrace, StartTraceW,
    CONTROLTRACE_HANDLE, ENABLE_TRACE_PARAMETERS, ENABLE_TRACE_PARAMETERS_VERSION_2,
    EVENT_CONTROL_CODE_CAPTURE_STATE, EVENT_CONTROL_CODE_ENABLE_PROVIDER, EVENT_FILTER_DESCRIPTOR,
    EVENT_FILTER_TYPE_EVENT_ID, EVENT_RECORD, EVENT_TRACE_CONTROL_STOP, EVENT_TRACE_LOGFILEW,
    EVENT_TRACE_PROPERTIES, EVENT_TRACE_REAL_TIME_MODE, PROCESSTRACE_HANDLE,
    PROCESS_TRACE_MODE_EVENT_RECORD, PROCESS_TRACE_MODE_REAL_TIME, TRACE_LEVEL_VERBOSE,
    WNODE_FLAG_TRACED_GUID,
};

use crate::events::{
    DNS_QUERY_COMPLETED, TCP_CONNECT_V4, TCP_CONNECT_V6, UDP_SEND_V4, UDP_SEND_V6,
};
use crate::processes::{
    DevicePaths, ProcEvent, Processes, KEYWORD_PROCESS, PROCESS_RUNDOWN, PROCESS_START,
    PROCESS_STOP,
};
use crate::{dns, DnsQuery, EtwFlows, NetEvent};

/// Longest wait of a packet observation for its ETW event.
pub const HOLD: Duration = Duration::from_millis(1500);
/// The ETW session's name (one per machine).
pub const SESSION: &str = "scribe-etw";

const KERNEL_NETWORK: GUID = GUID::from_u128(0x7dd42a49_5329_4832_8dfd_43d979153a88);
const DNS_CLIENT: GUID = GUID::from_u128(0x1c95126e_7eea_49a9_a3fe_a378b03ddb4d);
const KERNEL_PROCESS: GUID = GUID::from_u128(0x22fb2cd6_0e7b_422b_a0c7_2fad1fd0e716);
const INVALID_PROCESSTRACE: u64 = u64::MAX;

fn same(a: &GUID, b: &GUID) -> bool {
    (a.data1, a.data2, a.data3, a.data4) == (b.data1, b.data2, b.data3, b.data4)
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum Provider {
    Network,
    Dns,
    Process,
}

/// One event as the callback copied it.
struct Raw {
    provider: Provider,
    id: u16,
    data: Vec<u8>,
}

enum Input {
    Event(Raw),
    Packet(Observation),
}

/// `EVENT_TRACE_PROPERTIES` followed by room for the session name, as Start/ControlTrace want.
#[repr(C)]
struct Properties {
    p: EVENT_TRACE_PROPERTIES,
    name: [u16; 64],
}

fn wide(s: &str) -> Vec<u16> {
    s.encode_utf16().chain(std::iter::once(0)).collect()
}

fn properties() -> Box<Properties> {
    // SAFETY: plain data; all-zero is a valid starting value.
    let mut props: Box<Properties> = Box::new(unsafe { std::mem::zeroed() });
    props.p.Wnode.BufferSize = size_of::<Properties>() as u32;
    props.p.Wnode.Flags = WNODE_FLAG_TRACED_GUID;
    props.p.Wnode.ClientContext = 1; // QueryPerformanceCounter time stamps
    props.p.LogFileMode = EVENT_TRACE_REAL_TIME_MODE;
    props.p.FlushTimer = 1;
    props.p.BufferSize = 64; // KiB
    props.p.MinimumBuffers = 4;
    props.p.MaximumBuffers = 64;
    props.p.LoggerNameOffset = offset_of!(Properties, name) as u32;
    props
}

fn win32(context: &str, code: u32) -> SensorError {
    let e = std::io::Error::from_raw_os_error(code as i32);
    if code == ERROR_ACCESS_DENIED {
        SensorError::Permission(format!(
            "{context}: {e} (the ETW session needs Administrator rights)"
        ))
    } else {
        SensorError::Io(std::io::Error::other(format!("{context}: {e}")))
    }
}

/// Stops a session by name; returns its lost-event counts when it was running.
fn stop_session(name: &[u16]) -> Option<(u32, u32)> {
    let mut props = properties();
    // SAFETY: a valid name and a properties buffer of the declared size.
    let rc = unsafe {
        ControlTraceW(
            CONTROLTRACE_HANDLE { Value: 0 },
            name.as_ptr(),
            &mut props.p,
            EVENT_TRACE_CONTROL_STOP,
        )
    };
    (rc == ERROR_SUCCESS).then_some((props.p.EventsLost, props.p.RealTimeBuffersLost))
}

fn start_session(name: &[u16]) -> Result<CONTROLTRACE_HANDLE, SensorError> {
    for attempt in 0..2 {
        let mut props = properties();
        let mut handle = CONTROLTRACE_HANDLE { Value: 0 };
        // SAFETY: as in `stop_session`.
        let rc = unsafe { StartTraceW(&mut handle, name.as_ptr(), &mut props.p) };
        match rc {
            ERROR_SUCCESS => return Ok(handle),
            // Left over from a scribed that didn't stop cleanly: take it over.
            ERROR_ALREADY_EXISTS if attempt == 0 => {
                tracing::info!("ETW session {SESSION} was still running; restarting it");
                stop_session(name);
            }
            other => return Err(win32("StartTraceW", other)),
        }
    }
    Err(win32("StartTraceW", ERROR_ALREADY_EXISTS))
}

/// Enables `provider` (`keywords`) for the events `ids` only (dropping, e.g., Kernel-Network's
/// per-packet send / receive events in the kernel); without the filter on systems that don't
/// take it.
fn enable(
    session: CONTROLTRACE_HANDLE,
    provider: &GUID,
    keywords: u64,
    ids: &[u16],
) -> Result<(), SensorError> {
    // EVENT_FILTER_EVENT_ID: FilterIn (BOOLEAN), Reserved, Count, then the ids.
    let mut filter = vec![1u8, 0];
    filter.extend_from_slice(&(ids.len() as u16).to_le_bytes());
    for id in ids {
        filter.extend_from_slice(&id.to_le_bytes());
    }
    let mut desc = EVENT_FILTER_DESCRIPTOR {
        Ptr: filter.as_ptr() as u64,
        Size: filter.len() as u32,
        Type: EVENT_FILTER_TYPE_EVENT_ID,
    };
    let params = ENABLE_TRACE_PARAMETERS {
        Version: ENABLE_TRACE_PARAMETERS_VERSION_2,
        EnableFilterDesc: &mut desc,
        FilterDescCount: 1,
        ..Default::default()
    };
    let call = |params: *const ENABLE_TRACE_PARAMETERS| {
        // SAFETY: a running session, a valid GUID; `params` and its filter outlive the call.
        unsafe {
            EnableTraceEx2(
                session,
                provider,
                EVENT_CONTROL_CODE_ENABLE_PROVIDER,
                TRACE_LEVEL_VERBOSE as u8,
                keywords,
                0,
                0,
                params,
            )
        }
    };
    match call(&params) {
        ERROR_SUCCESS => Ok(()),
        _ => match call(std::ptr::null()) {
            ERROR_SUCCESS => Ok(()),
            rc => Err(win32("EnableTraceEx2", rc)),
        },
    }
}

/// Asks `provider` to report its state now (Kernel-Process: one rundown event per process).
fn capture_state(session: CONTROLTRACE_HANDLE, provider: &GUID, keywords: u64) -> u32 {
    // SAFETY: a running session and a valid GUID, no parameters.
    unsafe {
        EnableTraceEx2(
            session,
            provider,
            EVENT_CONTROL_CODE_CAPTURE_STATE,
            TRACE_LEVEL_VERBOSE as u8,
            keywords,
            0,
            0,
            std::ptr::null(),
        )
    }
}

/// Copies one event to the channel the context points at.
unsafe extern "system" fn on_event(record: *mut EVENT_RECORD) {
    // SAFETY: ETW passes a valid record for the duration of the call; UserContext is the
    // `Sender` boxed in `Running`, alive until ProcessTrace has returned.
    let r = unsafe { &*record };
    let provider = if same(&r.EventHeader.ProviderId, &KERNEL_NETWORK) {
        Provider::Network
    } else if same(&r.EventHeader.ProviderId, &DNS_CLIENT) {
        Provider::Dns
    } else if same(&r.EventHeader.ProviderId, &KERNEL_PROCESS) {
        Provider::Process
    } else {
        return;
    };
    let data = if r.UserData.is_null() || r.UserDataLength == 0 {
        Vec::new()
    } else {
        // SAFETY: UserData points at UserDataLength bytes.
        unsafe { std::slice::from_raw_parts(r.UserData as *const u8, r.UserDataLength as usize) }
            .to_vec()
    };
    let tx = unsafe { &*(r.UserContext as *const Sender<Input>) };
    let _ = tx.send(Input::Event(Raw {
        provider,
        id: r.EventHeader.EventDescriptor.Id,
        data,
    }));
}

struct Running {
    name: Vec<u16>,
    trace: u64,
    reader: Option<JoinHandle<()>>,
    worker: Option<JoinHandle<()>>,
    stop: Arc<AtomicBool>,
    pcap: Option<PcapSensor>,
    /// The callback's channel; freed after `reader` has ended.
    context: *mut Sender<Input>,
}

// SAFETY: `context` is only dereferenced by the ETW callback and freed in `stop`.
unsafe impl Send for Running {}

pub struct EtwSensor {
    /// The Npcap device for packet contents; `None` = automatic.
    interface: Option<String>,
    payload: bool,
    clock: Arc<dyn Clock>,
    stats: Arc<Mutex<AttributionStats>>,
    running: Option<Running>,
}

impl Default for EtwSensor {
    fn default() -> Self {
        Self::new(None)
    }
}

impl EtwSensor {
    pub fn new(interface: Option<String>) -> Self {
        Self {
            interface,
            payload: true,
            clock: Arc::new(SystemClock),
            stats: Arc::default(),
            running: None,
        }
    }

    /// Without packets: no Npcap, so flows come from the ETW events alone (for tests).
    pub fn without_packets(mut self) -> Self {
        self.interface = Some(String::new());
        self
    }
}

fn exe_path() -> scribe_process::join::ExePath {
    match scribe_process::os_table() {
        Some(table) => Box::new(move |pid| table.process_path(pid)),
        None => Box::new(|_| None),
    }
}

fn work(
    rx: Receiver<Input>,
    out: Sender<Observation>,
    clock: Arc<dyn Clock>,
    packets: bool,
    stop: Arc<AtomicBool>,
    stats: Arc<Mutex<AttributionStats>>,
) {
    let owners = Owners::new(clock.clone(), exe_path());
    let mut processes = Processes::new(DevicePaths::system());
    let mut joiner = Joiner::new(owners, clock.clone(), HOLD);
    let mut flows = EtwFlows::new();
    let mut bad = 0u64;
    let send = |obs: Vec<Observation>| obs.into_iter().all(|o| out.send(o).is_ok());
    loop {
        let input = rx.recv_timeout(Duration::from_millis(100));
        let mut ready = Vec::new();
        match input {
            Ok(Input::Event(raw)) => {
                let now = clock.now();
                match raw.provider {
                    Provider::Network => match NetEvent::parse(raw.id, &raw.data) {
                        Ok(Some(e)) => {
                            let mut c = e.connection();
                            c.path = processes.path(e.pid).map(str::to_owned);
                            joiner.record(&c);
                            if !packets {
                                ready.extend(
                                    joiner.push(flows.observe(&e, now).into_iter().collect()),
                                );
                            }
                        }
                        Ok(None) => {}
                        Err(err) => {
                            bad += 1;
                            if bad == 1 {
                                tracing::warn!("ETW: {err}");
                            }
                        }
                    },
                    Provider::Dns if raw.id == DNS_QUERY_COMPLETED => {
                        match DnsQuery::parse(&raw.data) {
                            Ok(q) => ready.extend(
                                joiner.push(dns::observation(&q, now).into_iter().collect()),
                            ),
                            Err(err) => {
                                bad += 1;
                                if bad == 1 {
                                    tracing::warn!("ETW: {err}");
                                }
                            }
                        }
                    }
                    Provider::Dns => {}
                    Provider::Process => match ProcEvent::parse(raw.id, &raw.data) {
                        Ok(Some(e)) => processes.apply(&e, now),
                        Ok(None) => {}
                        Err(err) => {
                            bad += 1;
                            if bad == 1 {
                                tracing::warn!("ETW: {err}");
                            }
                        }
                    },
                }
            }
            Ok(Input::Packet(obs)) => ready.extend(joiner.push(vec![obs])),
            Err(RecvTimeoutError::Timeout) => {}
            Err(RecvTimeoutError::Disconnected) => break,
        }
        ready.extend(joiner.ready());
        *stats.lock().unwrap_or_else(|p| p.into_inner()) = joiner.stats();
        if !send(ready) || stop.load(Ordering::Relaxed) {
            break;
        }
    }
    if !stop.load(Ordering::Relaxed) {
        send(joiner.flush());
    }
    *stats.lock().unwrap_or_else(|p| p.into_inner()) = joiner.stats();
    if bad > 0 {
        tracing::warn!(events = bad, "ETW events that could not be read");
    }
}

impl Sensor for EtwSensor {
    fn name(&self) -> &'static str {
        "windows-etw"
    }

    fn has_process_info(&self) -> bool {
        true
    }

    fn attribution(&self) -> Option<AttributionStats> {
        Some(*self.stats.lock().unwrap_or_else(|p| p.into_inner()))
    }

    fn set_payload(&mut self, needed: bool) {
        self.payload = needed;
    }

    fn start(&mut self, out: Sender<Observation>) -> Result<(), SensorError> {
        if self.running.is_some() {
            return Ok(());
        }
        let name = wide(SESSION);
        let session = start_session(&name)?;
        let enabled = enable(
            session,
            &KERNEL_NETWORK,
            u64::MAX,
            &[TCP_CONNECT_V4, TCP_CONNECT_V6, UDP_SEND_V4, UDP_SEND_V6],
        )
        .and_then(|()| enable(session, &DNS_CLIENT, u64::MAX, &[DNS_QUERY_COMPLETED]))
        .and_then(|()| {
            enable(
                session,
                &KERNEL_PROCESS,
                KEYWORD_PROCESS,
                &[PROCESS_START, PROCESS_STOP, PROCESS_RUNDOWN],
            )
        });
        if let Err(e) = enabled {
            stop_session(&name);
            return Err(e);
        }

        let (tx, rx) = mpsc::channel::<Input>();
        // Packets from Npcap when it loads; ETW alone otherwise.
        let mut pcap = None;
        if self.interface.as_deref() != Some("") {
            let mut p = PcapSensor::new(self.interface.clone());
            p.set_payload(self.payload);
            let (ptx, prx) = mpsc::channel::<Observation>();
            match p.start(ptx) {
                Ok(()) => {
                    let fwd = tx.clone();
                    std::thread::Builder::new()
                        .name("scribe-etw-packets".into())
                        .spawn(move || {
                            for obs in prx {
                                if fwd.send(Input::Packet(obs)).is_err() {
                                    break;
                                }
                            }
                        })
                        .map_err(SensorError::Io)?;
                    pcap = Some(p);
                }
                Err(e) => tracing::info!(
                    "Npcap not available ({e}): flows from ETW alone, without first bytes (no SNI or URLs)"
                ),
            }
        }
        let packets = pcap.is_some();

        let context = Box::into_raw(Box::new(tx));
        let mut logfile: EVENT_TRACE_LOGFILEW = Default::default();
        let mut logger = name.clone();
        logfile.LoggerName = logger.as_mut_ptr();
        logfile.Anonymous1.ProcessTraceMode =
            PROCESS_TRACE_MODE_REAL_TIME | PROCESS_TRACE_MODE_EVENT_RECORD;
        logfile.Anonymous2.EventRecordCallback = Some(on_event);
        logfile.Context = context.cast();
        // SAFETY: a filled-in logfile; the name and context outlive the trace.
        let trace: PROCESSTRACE_HANDLE = unsafe { OpenTraceW(&mut logfile) };
        if trace.Value == INVALID_PROCESSTRACE {
            let e = std::io::Error::last_os_error();
            stop_session(&name);
            // SAFETY: never handed to ETW.
            drop(unsafe { Box::from_raw(context) });
            return Err(SensorError::Io(std::io::Error::other(format!(
                "OpenTraceW: {e}"
            ))));
        }
        let handle = trace.Value;
        let reader = std::thread::Builder::new()
            .name("scribe-etw".into())
            .spawn(move || {
                let h = PROCESSTRACE_HANDLE { Value: handle };
                // SAFETY: an open real-time trace; returns once the session stops.
                let rc = unsafe { ProcessTrace(&h, 1, std::ptr::null(), std::ptr::null()) };
                if rc != ERROR_SUCCESS {
                    tracing::warn!(
                        "ProcessTrace ended: {}",
                        std::io::Error::from_raw_os_error(rc as i32)
                    );
                }
            })
            .map_err(SensorError::Io)?;
        let stop = Arc::new(AtomicBool::new(false));
        let (clock, stats, stop2) = (self.clock.clone(), self.stats.clone(), stop.clone());
        let worker = std::thread::Builder::new()
            .name("scribe-etw-join".into())
            .spawn(move || work(rx, out, clock, packets, stop2, stats))
            .map_err(SensorError::Io)?;
        // The paths of processes already running; until they arrive, QueryFullProcessImageNameW.
        let rc = capture_state(session, &KERNEL_PROCESS, KEYWORD_PROCESS);
        if rc != ERROR_SUCCESS {
            tracing::info!(
                "ETW process rundown not available: {}",
                std::io::Error::from_raw_os_error(rc as i32)
            );
        }
        tracing::info!(
            packets,
            "ETW sensor started (Kernel-Network, DNS-Client, Kernel-Process)"
        );
        self.running = Some(Running {
            name,
            trace: handle,
            reader: Some(reader),
            worker: Some(worker),
            stop,
            pcap,
            context,
        });
        Ok(())
    }

    fn stop(&mut self) {
        let Some(mut r) = self.running.take() else {
            return;
        };
        r.stop.store(true, Ordering::Relaxed);
        if let Some((events, buffers)) = stop_session(&r.name) {
            if events > 0 || buffers > 0 {
                tracing::warn!(events, buffers, "ETW lost events while capturing");
            }
        }
        // SAFETY: the handle from OpenTraceW, closed once.
        unsafe { CloseTrace(PROCESSTRACE_HANDLE { Value: r.trace }) };
        if let Some(t) = r.reader.take() {
            let _ = t.join();
        }
        if let Some(mut p) = r.pcap.take() {
            p.stop();
        }
        // SAFETY: ProcessTrace has returned, so the callback no longer runs; frees the sender,
        // which ends the worker once the packet forwarder is gone too.
        drop(unsafe { Box::from_raw(r.context) });
        if let Some(t) = r.worker.take() {
            let _ = t.join();
        }
    }
}

impl Drop for EtwSensor {
    fn drop(&mut self) {
        self.stop();
    }
}
