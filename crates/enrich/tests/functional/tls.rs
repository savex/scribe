//! Functional tests for `scribe_enrich::tls` (moved from `src/tls.rs`).

use scribe_core::Security;
use scribe_enrich::tls::*;

#[test]
fn detects_tls_handshake() {
    assert_eq!(
        detect_security(&[0x16, 0x03, 0x01, 0x02, 0x00]),
        Security::Tls
    );
}

#[test]
fn detects_plaintext_http() {
    assert_eq!(detect_security(b"GET / HTTP/1.1\r\n"), Security::Plaintext);
}

#[test]
fn empty_is_unknown() {
    assert_eq!(detect_security(&[]), Security::Unknown);
}
