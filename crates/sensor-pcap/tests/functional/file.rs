//! pcap files: the fixtures, both byte orders, nanosecond precision, broken files.

use std::time::{Duration, UNIX_EPOCH};

use proptest::prelude::*;
use scribe_sensor_pcap::decode::{decode, LINKTYPE_ETHERNET};
use scribe_sensor_pcap::file::{parse, FileError};
use scribe_test_support::packets::pcap::{write_pcap, BASE_TS_SECS};

#[test]
fn every_fixture_parses_and_decodes() {
    for fixture in scribe_test_support::fixtures::all() {
        let bytes = fixture.pcap();
        let capture = parse(&bytes).unwrap_or_else(|e| panic!("{}: {e}", fixture.name));
        assert_eq!(capture.linktype, LINKTYPE_ETHERNET);
        assert_eq!(
            capture.frames.len(),
            fixture.frames.len(),
            "{}",
            fixture.name
        );
        let decoded = capture
            .frames
            .iter()
            .filter(|f| decode(capture.linktype, f.data, f.ts).is_some())
            .count();
        if fixture.name == "malformed" {
            assert_eq!(decoded, 0);
        } else {
            assert_eq!(
                decoded,
                fixture.frames.len(),
                "{}: every frame decodes",
                fixture.name
            );
        }
    }
}

#[test]
fn timestamps_come_from_the_records() {
    let bytes = write_pcap(&[vec![0u8; 20], vec![1u8; 20]]);
    let capture = parse(&bytes).unwrap();
    let base = UNIX_EPOCH + Duration::from_secs(u64::from(BASE_TS_SECS));
    assert_eq!(capture.frames[0].ts, base);
    assert_eq!(capture.frames[1].ts, base + Duration::from_millis(1));
    assert_eq!(capture.frames[1].data, &[1u8; 20][..]);
}

/// The same file as big-endian with nanosecond timestamps.
fn big_endian_nanos(le: &[u8]) -> Vec<u8> {
    let mut out = vec![0xa1, 0xb2, 0x3c, 0x4d];
    let flip = |b: &[u8]| b.iter().rev().copied().collect::<Vec<u8>>();
    out.extend(flip(&le[4..6]));
    out.extend(flip(&le[6..8]));
    for i in 0..4 {
        out.extend(flip(&le[8 + i * 4..12 + i * 4]));
    }
    let mut at = 24;
    while at < le.len() {
        let caplen = u32::from_le_bytes(le[at + 8..at + 12].try_into().unwrap()) as usize;
        let micros = u32::from_le_bytes(le[at + 4..at + 8].try_into().unwrap());
        out.extend(flip(&le[at..at + 4]));
        out.extend((micros * 1000).to_be_bytes());
        out.extend(flip(&le[at + 8..at + 12]));
        out.extend(flip(&le[at + 12..at + 16]));
        out.extend(&le[at + 16..at + 16 + caplen]);
        at += 16 + caplen;
    }
    out
}

#[test]
fn big_endian_and_nanosecond_files_read_the_same() {
    let le = write_pcap(&[vec![7u8; 30], vec![8u8; 31]]);
    let be = big_endian_nanos(&le);
    let (a, b) = (parse(&le).unwrap(), parse(&be).unwrap());
    assert_eq!(a.linktype, b.linktype);
    assert_eq!(a.frames, b.frames);
}

#[test]
fn broken_files_are_errors() {
    assert_eq!(parse(b"").unwrap_err(), FileError::NotPcap);
    assert_eq!(
        parse(&[0x0a, 0x0d, 0x0d, 0x0a, 0, 0]).unwrap_err(),
        FileError::NotPcap,
        "pcapng"
    );
    let ok = write_pcap(&[vec![1u8; 40]]);
    assert_eq!(
        parse(&ok[..ok.len() - 5]).unwrap_err(),
        FileError::Truncated
    );
    assert_eq!(parse(&ok[..10]).unwrap_err(), FileError::Truncated);
}

proptest! {
    #[test]
    fn random_files_never_panic(bytes in prop::collection::vec(any::<u8>(), 0..300)) {
        let _ = parse(&bytes);
        let mut le = vec![0xd4, 0xc3, 0xb2, 0xa1];
        le.extend(&bytes);
        let _ = parse(&le);
    }
}
