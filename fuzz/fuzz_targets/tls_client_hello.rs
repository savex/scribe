#![no_main]

use libfuzzer_sys::fuzz_target;
use scribe_enrich::tls::{detect_security, parse_client_hello, parse_sni};

fuzz_target!(|data: &[u8]| {
    let _ = detect_security(data);
    if let Some(name) = parse_sni(data) {
        assert!(name.len() <= 255, "SNI longer than a DNS name");
    }
    if let Ok(hello) = parse_client_hello(data) {
        if let Some(sni) = hello.sni {
            assert_eq!(sni, sni.to_ascii_lowercase());
        }
    }
});
