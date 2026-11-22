#![no_main]

use libfuzzer_sys::fuzz_target;
use scribe_enrich::quic::{crypto_frames, decrypt_initial, InitialReassembler, Progress};

// Input: one or more datagrams, each prefixed by a 2-byte big-endian length, fed to one
// reassembler. Raw bytes also go straight to the frame parser (decryption rarely succeeds on
// mutated input, so the frame parser is fuzzed directly too).
fuzz_target!(|data: &[u8]| {
    let _ = crypto_frames(data);
    let mut r = InitialReassembler::default();
    let mut rest = data;
    while rest.len() >= 2 {
        let n = usize::from(u16::from_be_bytes([rest[0], rest[1]])).min(rest.len() - 2);
        let datagram = &rest[2..2 + n];
        rest = &rest[2 + n..];
        if let Ok(initial) = decrypt_initial(datagram) {
            assert!(initial.dcid.len() <= 20);
        }
        if let Progress::Hello(hello) = r.push(datagram) {
            if let Some(sni) = hello.sni {
                assert!(sni.len() <= 253 && !sni.is_empty());
            }
        }
    }
});
