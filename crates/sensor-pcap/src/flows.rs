//! From packets to [`Observation`]s: one `NewFlow` per outgoing TCP connection or UDP flow,
//! carrying up to [`HEAD_MAX`] of the first client bytes; `Payload` for later plaintext HTTP
//! requests (when a module needs payload) and for the next QUIC Initials of a flow; `DnsResponse`
//! for DNS answers; `Close` with the client bytes not reported yet.
//!
//! TCP: a flow starts with the client's SYN (no ACK). Its first bytes are reassembled by sequence
//! number, in or out of order, until they are complete: a whole TLS ClientHello, an HTTP request
//! head up to the empty line, the first segment of anything else, or [`HEAD_MAX`] bytes. A flow
//! whose first bytes aren't complete [`TrackerOptions::first_data_wait`] after its SYN is reported
//! with what arrived, or none (protocols where the server speaks first). Connections already open when capture started (no SYN seen) are not
//! tracked. FIN or RST from either side, or [`TrackerOptions::tcp_idle`], closes a flow.
//!
//! UDP: the first datagram between two addresses starts a flow from its sender (with known local
//! addresses: only senders on this machine). A datagram from port 53 is a DNS response.
//!
//! Time comes from the packets, so replays and live capture behave the same.

use std::collections::{BTreeMap, HashMap};
use std::net::{IpAddr, SocketAddr};
use std::time::{Duration, SystemTime};

use scribe_core::{FlowEvent, FlowKind, Notes, Observation, Protocol, Security, HEAD_MAX};

use crate::decode::{Packet, Transport, TCP_ACK, TCP_FIN, TCP_RST, TCP_SYN};

#[derive(Debug, Clone)]
pub struct TrackerOptions {
    /// Report later plaintext HTTP requests on a connection (an enabled module needs payload).
    pub payload: bool,
    /// Report a TCP flow without client data after this long.
    pub first_data_wait: Duration,
    pub tcp_idle: Duration,
    pub udp_idle: Duration,
    /// Flows tracked at once; the least recently active one is closed to make room.
    pub max_flows: usize,
    /// This machine's addresses. When known, only flows they start are outgoing; when empty,
    /// whoever sends first is the client.
    pub local: Vec<IpAddr>,
}

impl Default for TrackerOptions {
    fn default() -> Self {
        Self {
            payload: true,
            first_data_wait: Duration::from_secs(1),
            tcp_idle: Duration::from_secs(300),
            udp_idle: Duration::from_secs(60),
            max_flows: 65_536,
            local: Vec::new(),
        }
    }
}

/// How many datagrams after the first may still be QUIC Initials worth passing on.
const QUIC_FOLLOW_UP: u32 = 4;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
enum Kind {
    Tcp,
    Udp,
}

type Key = (SocketAddr, SocketAddr, Kind);

#[derive(Debug)]
struct Tcp {
    /// Sequence number of the first client data byte.
    base: u32,
    head: Vec<u8>,
    pending: BTreeMap<u32, Vec<u8>>,
    reported: bool,
    http: bool,
    request: Vec<u8>,
}

#[derive(Debug)]
struct Flow {
    client: SocketAddr,
    server: SocketAddr,
    first: SystemTime,
    last: SystemTime,
    /// Client bytes not yet carried by an observation.
    unreported: u64,
    tcp: Option<Tcp>,
    datagrams: u32,
}

pub struct FlowTracker {
    opts: TrackerOptions,
    flows: HashMap<Key, Flow>,
}

fn event(
    ts: SystemTime,
    kind: Kind,
    client: SocketAddr,
    server: SocketAddr,
    flow_kind: FlowKind,
) -> FlowEvent {
    FlowEvent {
        ts,
        pid: None,
        process_path: None,
        proto: match kind {
            Kind::Tcp => Protocol::Tcp,
            Kind::Udp => Protocol::Udp,
        },
        src: client,
        dst_ip: server.ip(),
        dst_port: server.port(),
        hostname: None,
        ech: false,
        notes: Notes::new(),
        security: Security::Unknown,
        bytes_out: 0,
        kind: flow_kind,
    }
}

/// An HTTP request line starts with an upper-case method and a space.
fn looks_like_request(bytes: &[u8]) -> bool {
    let method_len = bytes.iter().take_while(|b| b.is_ascii_uppercase()).count();
    (3..=16).contains(&method_len) && bytes.get(method_len) == Some(&b' ')
}

fn has_head_end(bytes: &[u8]) -> bool {
    bytes.windows(4).any(|w| w == b"\r\n\r\n")
}

/// Whether the first bytes hold a whole ClientHello: TLS handshake records whose payloads add
/// up to the first handshake message.
fn tls_hello_complete(bytes: &[u8]) -> bool {
    let mut payload = Vec::new();
    let mut at = 0;
    while at + 5 <= bytes.len() && bytes[at] == 0x16 {
        let len = usize::from(u16::from_be_bytes([bytes[at + 3], bytes[at + 4]]));
        let end = (at + 5 + len).min(bytes.len());
        payload.extend_from_slice(&bytes[at + 5..end]);
        if payload.len() >= 4 {
            let need = 4
                + ((usize::from(payload[1]) << 16)
                    | (usize::from(payload[2]) << 8)
                    | usize::from(payload[3]));
            if payload.len() >= need {
                return true;
            }
        }
        if end < at + 5 + len {
            return false;
        }
        at = end;
    }
    false
}

impl Tcp {
    /// Bytes in order from the first data byte.
    fn place(&mut self, seq: u32, data: &[u8]) {
        let rel = seq.wrapping_sub(self.base);
        if rel as usize >= HEAD_MAX {
            return;
        }
        self.pending.entry(rel).or_insert_with(|| data.to_vec());
        while let Some((&off, _)) = self.pending.first_key_value() {
            let off = off as usize;
            if off > self.head.len() {
                break;
            }
            let (_, chunk) = self.pending.pop_first().expect("checked");
            if off + chunk.len() > self.head.len() {
                self.head.extend_from_slice(&chunk[self.head.len() - off..]);
            }
        }
        self.head.truncate(HEAD_MAX);
    }

    fn complete(&self) -> bool {
        let h = &self.head;
        if h.is_empty() {
            return false;
        }
        if h.len() >= HEAD_MAX {
            return true;
        }
        if h[0] == 0x16 {
            return tls_hello_complete(h);
        }
        if looks_like_request(h) {
            return has_head_end(h);
        }
        true
    }
}

impl FlowTracker {
    pub fn new(opts: TrackerOptions) -> Self {
        Self {
            opts,
            flows: HashMap::new(),
        }
    }

    pub fn len(&self) -> usize {
        self.flows.len()
    }

    pub fn is_empty(&self) -> bool {
        self.flows.is_empty()
    }

    fn is_local(&self, ip: IpAddr) -> bool {
        self.opts.local.is_empty() || self.opts.local.contains(&ip)
    }

    /// Feed one decoded packet; returns the observations it completes.
    pub fn push(&mut self, p: &Packet<'_>) -> Vec<Observation> {
        let mut out = self.tick(p.ts);
        match p.transport {
            Transport::Tcp { flags, seq } => self.tcp(p, flags, seq, &mut out),
            Transport::Udp => self.udp(p, &mut out),
        }
        out
    }

    fn make_room(&mut self, out: &mut Vec<Observation>) {
        if self.flows.len() < self.opts.max_flows {
            return;
        }
        if let Some(oldest) = self
            .flows
            .iter()
            .min_by_key(|(_, f)| f.last)
            .map(|(k, _)| *k)
        {
            out.extend(self.finish(oldest));
        }
    }

    fn tcp(&mut self, p: &Packet<'_>, flags: u8, seq: u32, out: &mut Vec<Observation>) {
        let forward = (p.src, p.dst, Kind::Tcp);
        let reverse = (p.dst, p.src, Kind::Tcp);
        if flags & TCP_SYN != 0 && flags & TCP_ACK == 0 {
            if !self.flows.contains_key(&forward) && self.is_local(p.src.ip()) {
                self.make_room(out);
                self.flows.insert(
                    forward,
                    Flow {
                        client: p.src,
                        server: p.dst,
                        first: p.ts,
                        last: p.ts,
                        unreported: 0,
                        datagrams: 0,
                        tcp: Some(Tcp {
                            base: seq.wrapping_add(1),
                            head: Vec::new(),
                            pending: BTreeMap::new(),
                            reported: false,
                            http: false,
                            request: Vec::new(),
                        }),
                    },
                );
            }
            return;
        }
        let key = if self.flows.contains_key(&forward) {
            forward
        } else if self.flows.contains_key(&reverse) {
            reverse
        } else {
            return;
        };
        let from_client = key == forward;
        let payload = self.opts.payload;
        if let Some(flow) = self.flows.get_mut(&key) {
            flow.last = p.ts;
            if from_client && !p.payload.is_empty() {
                flow.unreported += p.payload.len() as u64;
                let tcp = flow.tcp.as_mut().expect("TCP flow");
                if !tcp.reported {
                    tcp.place(seq, p.payload);
                    if tcp.complete() {
                        out.push(Self::first_observation(flow, Kind::Tcp));
                    }
                } else if payload && tcp.http {
                    if tcp.request.is_empty() && !looks_like_request(p.payload) {
                        // Request body or something else: only counted.
                    } else {
                        tcp.request.extend_from_slice(p.payload);
                        if has_head_end(&tcp.request) || tcp.request.len() >= HEAD_MAX {
                            let mut e =
                                event(p.ts, Kind::Tcp, flow.client, flow.server, FlowKind::Payload);
                            e.bytes_out = std::mem::take(&mut flow.unreported);
                            let head = std::mem::take(&mut tcp.request);
                            out.push(Observation::new(e).with_head(&head));
                        }
                    }
                }
            }
        }
        if flags & (TCP_FIN | TCP_RST) != 0 {
            out.extend(self.finish(key));
        }
    }

    /// The `NewFlow` observation of a flow, with its first bytes.
    fn first_observation(flow: &mut Flow, kind: Kind) -> Observation {
        let mut e = event(
            flow.first,
            kind,
            flow.client,
            flow.server,
            FlowKind::NewFlow,
        );
        e.bytes_out = std::mem::take(&mut flow.unreported);
        let mut obs = Observation::new(e);
        if let Some(tcp) = flow.tcp.as_mut() {
            tcp.reported = true;
            tcp.http = looks_like_request(&tcp.head);
            if !tcp.head.is_empty() {
                obs = obs.with_head(&tcp.head);
            }
            tcp.head = Vec::new();
            tcp.pending.clear();
        }
        obs
    }

    fn udp(&mut self, p: &Packet<'_>, out: &mut Vec<Observation>) {
        let forward = (p.src, p.dst, Kind::Udp);
        let reverse = (p.dst, p.src, Kind::Udp);
        if p.src.port() == 53 {
            let e = event(p.ts, Kind::Udp, p.src, p.dst, FlowKind::DnsResponse);
            out.push(Observation::new(e).with_head(p.payload));
            return;
        }
        if let Some(flow) = self.flows.get_mut(&forward) {
            flow.last = p.ts;
            flow.datagrams += 1;
            flow.unreported += p.payload.len() as u64;
            // A QUIC ClientHello may span several Initials: pass the next long-header datagrams on.
            let long_header = p.payload.first().is_some_and(|b| b & 0xc0 == 0xc0);
            if flow.datagrams <= QUIC_FOLLOW_UP && long_header {
                let mut e = event(p.ts, Kind::Udp, flow.client, flow.server, FlowKind::Payload);
                e.bytes_out = std::mem::take(&mut flow.unreported);
                out.push(Observation::new(e).with_head(p.payload));
            }
            return;
        }
        if let Some(flow) = self.flows.get_mut(&reverse) {
            flow.last = p.ts; // a reply keeps the flow alive
            return;
        }
        if !self.is_local(p.src.ip()) {
            return;
        }
        self.make_room(out);
        let mut flow = Flow {
            client: p.src,
            server: p.dst,
            first: p.ts,
            last: p.ts,
            unreported: p.payload.len() as u64,
            datagrams: 1,
            tcp: None,
        };
        let mut obs = Self::first_observation(&mut flow, Kind::Udp);
        if !p.payload.is_empty() {
            obs = obs.with_head(p.payload);
        }
        out.push(obs);
        self.flows.insert(forward, flow);
    }

    /// Close a flow: its `NewFlow` if it never had one, then `Close` with the bytes left.
    fn finish(&mut self, key: Key) -> Vec<Observation> {
        let mut out = Vec::new();
        let Some(mut flow) = self.flows.remove(&key) else {
            return out;
        };
        if flow.tcp.as_ref().is_some_and(|t| !t.reported) {
            out.push(Self::first_observation(&mut flow, key.2));
        }
        let mut e = event(flow.last, key.2, flow.client, flow.server, FlowKind::Close);
        e.bytes_out = flow.unreported;
        out.push(Observation::new(e));
        out
    }

    /// Report TCP flows still without data after the wait, and close idle flows, as of `now`.
    pub fn tick(&mut self, now: SystemTime) -> Vec<Observation> {
        let mut out = Vec::new();
        let age = |t: SystemTime| now.duration_since(t).unwrap_or(Duration::ZERO);
        let idle: Vec<Key> = self
            .flows
            .iter()
            .filter(|(k, f)| {
                let limit = if k.2 == Kind::Tcp {
                    self.opts.tcp_idle
                } else {
                    self.opts.udp_idle
                };
                age(f.last) >= limit
            })
            .map(|(k, _)| *k)
            .collect();
        for key in idle {
            out.extend(self.finish(key));
        }
        // Flows whose first bytes didn't complete in time are reported with what arrived (or none).
        let wait = self.opts.first_data_wait;
        for flow in self.flows.values_mut() {
            let waiting = flow.tcp.as_ref().is_some_and(|t| !t.reported);
            if waiting && age(flow.first) >= wait {
                out.push(Self::first_observation(flow, Kind::Tcp));
            }
        }
        out
    }

    /// Close every flow (capture stopped, end of a replay).
    pub fn flush(&mut self) -> Vec<Observation> {
        let mut keys: Vec<Key> = self.flows.keys().copied().collect();
        keys.sort_by_key(|k| self.flows[k].first);
        keys.into_iter().flat_map(|k| self.finish(k)).collect()
    }
}

/// Every observation a pcap file gives, in order, as live capture would report them.
pub fn replay(
    bytes: &[u8],
    opts: TrackerOptions,
) -> Result<Vec<Observation>, crate::file::FileError> {
    let capture = crate::file::parse(bytes)?;
    let mut tracker = FlowTracker::new(opts);
    let mut out = Vec::new();
    for frame in &capture.frames {
        if let Some(p) = crate::decode::decode(capture.linktype, frame.data, frame.ts) {
            out.extend(tracker.push(&p));
        }
    }
    out.extend(tracker.flush());
    Ok(out)
}
