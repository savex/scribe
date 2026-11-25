use std::io;
use std::net::SocketAddr;
use std::sync::mpsc;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use scribe_core::{FlowKind, Sensor};
use scribe_process::{
    Attributed, AttributionStats, Owner, Resolver, SocketEntry, SocketTable, Transport,
    MAX_REFRESH, MIN_REFRESH, SCAN_BUDGET,
};
use scribe_test_support::{flow, FakeClock, FakeSensor};

fn addr(s: &str) -> SocketAddr {
    s.parse().unwrap()
}

/// A socket table the test fills; counts how often it is read.
#[derive(Clone, Default)]
struct Table {
    entries: Arc<Mutex<Vec<SocketEntry>>>,
    reads: Arc<Mutex<usize>>,
    fail: Arc<Mutex<bool>>,
}

impl Table {
    fn add(&self, transport: Transport, local: &str, remote: Option<&str>, pid: u32) {
        self.entries.lock().unwrap().push(SocketEntry {
            transport,
            local: addr(local),
            remote: remote.map(addr),
            pid,
        });
    }
    fn reads(&self) -> usize {
        *self.reads.lock().unwrap()
    }
}

impl SocketTable for Table {
    fn snapshot(&mut self) -> io::Result<Vec<SocketEntry>> {
        *self.reads.lock().unwrap() += 1;
        if *self.fail.lock().unwrap() {
            return Err(io::Error::other("no permission"));
        }
        Ok(self.entries.lock().unwrap().clone())
    }
    fn process_path(&self, pid: u32) -> Option<String> {
        (pid != 0).then(|| format!("/opt/app{pid}/bin/app"))
    }
}

fn resolver(table: &Table) -> (Resolver, Arc<FakeClock>) {
    let clock = Arc::new(FakeClock::at_unix(1_800_000_000));
    (Resolver::new(Box::new(table.clone()), clock.clone()), clock)
}

#[test]
fn tcp_flows_match_their_exact_socket() {
    let table = Table::default();
    table.add(
        Transport::Tcp,
        "192.0.2.10:50000",
        Some("203.0.113.9:443"),
        41,
    );
    table.add(
        Transport::Tcp,
        "192.0.2.10:50001",
        Some("203.0.113.9:443"),
        42,
    );
    let (mut r, _) = resolver(&table);
    assert_eq!(
        r.lookup(
            Transport::Tcp,
            addr("192.0.2.10:50001"),
            addr("203.0.113.9:443")
        ),
        Some(Owner {
            pid: 42,
            path: Some("/opt/app42/bin/app".into())
        })
    );
    assert_eq!(
        r.lookup(
            Transport::Udp,
            addr("192.0.2.10:50001"),
            addr("203.0.113.9:443")
        ),
        None,
        "the transport must match"
    );
}

#[test]
fn v4_mapped_sockets_and_wildcard_udp_match() {
    let table = Table::default();
    table.add(
        Transport::Tcp,
        "[::ffff:192.0.2.10]:50002",
        Some("[::ffff:203.0.113.9]:443"),
        7,
    );
    table.add(Transport::Udp, "0.0.0.0:53000", None, 8);
    table.add(Transport::Udp, "[::]:53001", None, 9);
    let (mut r, _) = resolver(&table);
    let pid =
        |r: &mut Resolver, t, l: &str, rem: &str| r.lookup(t, addr(l), addr(rem)).map(|o| o.pid);
    assert_eq!(
        pid(
            &mut r,
            Transport::Tcp,
            "192.0.2.10:50002",
            "203.0.113.9:443"
        ),
        Some(7)
    );
    assert_eq!(
        pid(
            &mut r,
            Transport::Udp,
            "192.0.2.10:53000",
            "198.51.100.1:53"
        ),
        Some(8)
    );
    assert_eq!(
        pid(
            &mut r,
            Transport::Udp,
            "192.0.2.10:53001",
            "198.51.100.1:443"
        ),
        Some(9)
    );
}

#[test]
fn misses_read_the_table_again_at_most_every_100_ms() {
    let table = Table::default();
    let (mut r, clock) = resolver(&table);
    let probe = |r: &mut Resolver| {
        r.lookup(
            Transport::Tcp,
            addr("192.0.2.10:50003"),
            addr("203.0.113.9:443"),
        )
    };
    assert_eq!(probe(&mut r), None);
    assert_eq!(table.reads(), 1);
    // The socket appears, but the table was read just now.
    table.add(
        Transport::Tcp,
        "192.0.2.10:50003",
        Some("203.0.113.9:443"),
        5,
    );
    assert_eq!(probe(&mut r), None);
    assert_eq!(table.reads(), 1);
    clock.advance(Duration::from_millis(100));
    assert_eq!(probe(&mut r).map(|o| o.pid), Some(5));
    assert_eq!(table.reads(), 2);
    // Hits come from the copy.
    assert_eq!(probe(&mut r).map(|o| o.pid), Some(5));
    assert_eq!(table.reads(), 2);
}

#[test]
fn an_unreadable_table_means_no_owner() {
    let table = Table::default();
    *table.fail.lock().unwrap() = true;
    let (mut r, clock) = resolver(&table);
    assert_eq!(
        r.lookup(
            Transport::Tcp,
            addr("192.0.2.10:1"),
            addr("203.0.113.9:443")
        ),
        None
    );
    clock.advance(Duration::from_secs(1));
    assert_eq!(
        r.lookup(
            Transport::Tcp,
            addr("192.0.2.10:1"),
            addr("203.0.113.9:443")
        ),
        None
    );
    assert_eq!(table.reads(), 2);
}

#[test]
fn the_wrapper_fills_in_new_flows_and_keeps_what_the_sensor_knew() {
    let table = Table::default();
    table.add(
        Transport::Tcp,
        "10.0.0.2:50000",
        Some("203.0.113.9:443"),
        77,
    );
    table.add(Transport::Udp, "10.0.0.2:50000", None, 78);
    let (r, _) = resolver(&table);
    let mut known = flow("203.0.113.9:443")
        .process(5, "/usr/bin/known")
        .observe();
    known.event.kind = FlowKind::NewFlow;
    let mut tcp = flow("203.0.113.9:443").observe();
    tcp.event.kind = FlowKind::NewFlow;
    let mut quic = flow("203.0.113.9:443").quic().observe();
    quic.event.kind = FlowKind::NewFlow;
    let mut close = flow("203.0.113.9:443").close().observe();
    close.event.kind = FlowKind::Close;
    let mut unknown = flow("198.51.100.4:443").observe();
    unknown.event.src = addr("10.0.0.2:60000");
    unknown.event.kind = FlowKind::NewFlow;
    let inner = FakeSensor::from_observations(vec![known, tcp, quic, close, unknown])
        .without_process_info();

    let mut sensor = Attributed::new(Box::new(inner), r);
    assert!(sensor.has_process_info());
    assert_eq!(sensor.name(), "fake");
    let (tx, rx) = mpsc::channel();
    sensor.start(tx).unwrap();
    let got: Vec<_> = rx.iter().take(5).collect();
    let pids: Vec<Option<u32>> = got.iter().map(|o| o.event.pid).collect();
    assert_eq!(pids, [Some(5), Some(77), Some(78), None, None]);
    assert_eq!(got[0].event.process_path.as_deref(), Some("/usr/bin/known"));
    assert_eq!(
        got[1].event.process_path.as_deref(),
        Some("/opt/app77/bin/app")
    );
    sensor.stop();
    let stats = sensor.stats();
    assert_eq!(
        (stats.attributed, stats.missed),
        (2, 1),
        "the new TCP and QUIC flows found, the unknown one missed; the close isn't counted"
    );
    assert_eq!(stats.hit_rate(), Some(2.0 / 3.0));
    assert!(stats.scans >= 1);
    assert_eq!(sensor.attribution(), Some(stats));
    assert_eq!(AttributionStats::default().hit_rate(), None);
}

/// A table whose every read takes `took` on the fake clock, with `sockets` entries.
struct SlowTable {
    clock: Arc<FakeClock>,
    took: Arc<Mutex<Duration>>,
    sockets: u32,
    reads: Arc<Mutex<usize>>,
}

impl SocketTable for SlowTable {
    fn snapshot(&mut self) -> io::Result<Vec<SocketEntry>> {
        *self.reads.lock().unwrap() += 1;
        self.clock.advance(*self.took.lock().unwrap());
        Ok((0..self.sockets)
            .map(|i| SocketEntry {
                transport: Transport::Tcp,
                local: SocketAddr::new(
                    std::net::Ipv4Addr::from(0xC000_0200 + (i >> 16)).into(),
                    (i & 0xFFFF) as u16,
                ),
                remote: Some(addr("203.0.113.9:443")),
                pid: 1000 + i % 500,
            })
            .collect())
    }
    fn process_path(&self, pid: u32) -> Option<String> {
        Some(format!("/opt/app{pid}/bin/app"))
    }
}

fn slow_resolver(took: Duration, sockets: u32) -> (Resolver, Arc<FakeClock>, SlowTable) {
    let clock = Arc::new(FakeClock::at_unix(1_800_000_000));
    let table = SlowTable {
        clock: clock.clone(),
        took: Arc::new(Mutex::new(took)),
        sockets,
        reads: Arc::new(Mutex::new(0)),
    };
    let handle = SlowTable {
        clock: clock.clone(),
        took: table.took.clone(),
        sockets,
        reads: table.reads.clone(),
    };
    (Resolver::new(Box::new(table), clock.clone()), clock, handle)
}

#[test]
fn a_slow_scan_spaces_out_the_next_reads_and_a_fast_one_resets_that() {
    let (mut r, clock, table) = slow_resolver(Duration::from_millis(200), 10);
    let miss = |r: &mut Resolver| {
        r.lookup(
            Transport::Tcp,
            addr("198.51.100.1:9999"),
            addr("203.0.113.9:443"),
        )
    };
    assert_eq!(miss(&mut r), None);
    let s = r.scan_stats();
    assert_eq!(
        (s.scans, s.slow, s.last, s.max),
        (1, 1, Duration::from_millis(200), Duration::from_millis(200))
    );
    // 200 ms × 10 = 2 s before the next read (time since the read started).
    assert_eq!(r.refresh_gap(), Duration::from_secs(2));
    clock.advance(Duration::from_millis(1_700));
    assert_eq!(miss(&mut r), None);
    assert_eq!(
        *table.reads.lock().unwrap(),
        1,
        "too early for another read"
    );
    clock.advance(Duration::from_millis(100));
    *table.took.lock().unwrap() = Duration::from_millis(5);
    assert_eq!(miss(&mut r), None);
    assert_eq!(*table.reads.lock().unwrap(), 2);
    assert_eq!(r.refresh_gap(), MIN_REFRESH, "a fast read resets the gap");
    let s = r.scan_stats();
    assert_eq!(
        (s.scans, s.slow, s.last, s.max),
        (2, 1, Duration::from_millis(5), Duration::from_millis(200))
    );
}

#[test]
fn the_gap_after_a_very_slow_scan_is_capped() {
    let (mut r, _, _) = slow_resolver(Duration::from_secs(3), 1);
    r.lookup(
        Transport::Tcp,
        addr("198.51.100.1:9999"),
        addr("203.0.113.9:443"),
    );
    assert_eq!(r.refresh_gap(), MAX_REFRESH);
    assert!(SCAN_BUDGET < MIN_REFRESH);
}

#[test]
fn a_table_of_a_hundred_thousand_sockets_answers_every_lookup() {
    // Load check of the lookup side: many processes and sockets in one table. The real
    // scan cost is measured by `live::many_own_sockets_scan_within_the_budget`.
    let (mut r, _, table) = slow_resolver(Duration::ZERO, 100_000);
    let started = std::time::Instant::now();
    for i in (0..100_000u32).step_by(7) {
        let local = SocketAddr::new(
            std::net::Ipv4Addr::from(0xC000_0200 + (i >> 16)).into(),
            (i & 0xFFFF) as u16,
        );
        let owner = r
            .lookup(Transport::Tcp, local, addr("203.0.113.9:443"))
            .expect("every socket is in the table");
        assert_eq!(owner.pid, 1000 + i % 500);
    }
    assert_eq!(*table.reads.lock().unwrap(), 1, "hits come from the copy");
    assert!(
        started.elapsed() < Duration::from_secs(2),
        "{:?}",
        started.elapsed()
    );
}
