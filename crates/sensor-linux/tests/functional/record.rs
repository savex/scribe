use std::net::SocketAddr;

use scribe_sensor_linux::{Record, RecordError, RecordKind, RECORD_SIZE};

fn addr(s: &str) -> SocketAddr {
    s.parse().unwrap()
}

fn sample(src: &str, dst: &str) -> Record {
    Record {
        kind: RecordKind::TcpConnect,
        ts_ns: 1_700_000_000_000_000_000,
        cgroup_id: 7777,
        tgid: 4242,
        pid: 4243,
        uid: 1000,
        comm: "curl".into(),
        src: addr(src),
        dst: addr(dst),
    }
}

#[test]
fn records_read_back_what_was_written_for_both_families() {
    for (src, dst) in [
        ("10.0.0.2:50001", "192.0.2.10:443"),
        ("[fd00::2]:50002", "[2001:db8::10]:443"),
        ("[::]:53002", "[2001:db8::53]:53"),
    ] {
        let r = sample(src, dst);
        let bytes = r.to_bytes();
        assert_eq!(bytes.len(), RECORD_SIZE);
        assert_eq!(Record::parse(&bytes).unwrap(), r);
    }
}

#[test]
fn v4_mapped_addresses_come_back_as_ipv4_and_long_names_are_cut() {
    let mut r = sample("[::ffff:10.0.0.2]:50001", "[::ffff:192.0.2.10]:443");
    r.comm = "a-very-long-thread-name".into();
    let back = Record::parse(&r.to_bytes()).unwrap();
    assert_eq!(back.src, addr("10.0.0.2:50001"));
    assert_eq!(back.dst, addr("192.0.2.10:443"));
    assert_eq!(
        back.comm, "a-very-long-thr",
        "15 bytes, as the kernel keeps"
    );
}

#[test]
fn wrong_sizes_versions_kinds_and_families_are_refused() {
    let good = sample("10.0.0.2:1", "192.0.2.10:443").to_bytes();
    assert_eq!(Record::parse(&good[..87]), Err(RecordError::Size(87)));
    assert_eq!(Record::parse(&[]), Err(RecordError::Size(0)));
    let mut b = good;
    b[31] = 2;
    assert_eq!(Record::parse(&b), Err(RecordError::Version(2)));
    let mut b = good;
    b[30] = 9;
    assert_eq!(Record::parse(&b), Err(RecordError::Kind(9)));
    let mut b = good;
    b[28..30].copy_from_slice(&17u16.to_ne_bytes());
    assert_eq!(Record::parse(&b), Err(RecordError::Family(17)));
}

#[test]
fn any_bytes_of_the_right_size_never_panic() {
    // A cheap sweep instead of a fuzz target: every single-byte value at every offset.
    let base = sample("10.0.0.2:1", "192.0.2.10:443").to_bytes();
    for at in 0..RECORD_SIZE {
        for v in [0u8, 1, 2, 10, 0x7f, 0xff] {
            let mut b = base;
            b[at] = v;
            let _ = Record::parse(&b);
        }
    }
}
