#![no_main]

use libfuzzer_sys::fuzz_target;
use scribe_enrich::tls::{detect_security, parse_sni};

fuzz_target!(|data: &[u8]| {
    let _ = detect_security(data);
    if let Some(name) = parse_sni(data) {
        assert!(name.len() <= 255, "SNI longer than a DNS name");
    }
});
