use std::io;
use std::net::SocketAddr;
use std::sync::mpsc;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use scribe_core::{FlowKind, Sensor};
use scribe_process::{
    Attributed, AttributionStats, Owner, Resolver, SocketEntry, SocketTable, Transport,
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
    assert_eq!(
        sensor.stats(),
        AttributionStats {
            attributed: 2,
            missed: 1
        }
    );
}
