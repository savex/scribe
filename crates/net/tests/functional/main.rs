//! Functional tests of `scribe_net` (FUN-A02 `webhook_signing_and_https`, client part): URL rules,
//! signing test vectors, and requests against local test servers on port 0 (plain HTTP on
//! loopback, and TLS with a self-signed certificate for the pin).

mod client;
mod server;
mod tls;
mod url;

#[test]
fn signature_matches_independent_test_vectors() {
    // Computed with Python's hmac module.
    assert_eq!(
        scribe_net::signature(b"whsec_test", 1_800_000_000, br#"{"a":1}"#),
        "t=1800000000,v1=7de5e6bbc99c65ef0ddccacd4308ba03a5a12eb8859a0db070c5ca731c4fdc19"
    );
    let key: Vec<u8> = (0..32).collect();
    assert_eq!(
        scribe_net::signature(&key, 0, b""),
        "t=0,v1=0e80838223869e9517439e639ad55157d90d439a465b4e569e67014750fa80da"
    );
}

#[test]
fn pins_parse_with_or_without_colons() {
    let hex = "ab".repeat(32);
    assert_eq!(scribe_net::parse_pin(&hex).unwrap(), [0xab; 32]);
    let colons = vec!["AB"; 32].join(":");
    assert_eq!(scribe_net::parse_pin(&colons).unwrap(), [0xab; 32]);
    assert!(scribe_net::parse_pin("abcd").is_err());
    assert!(scribe_net::parse_pin(&"zz".repeat(32)).is_err());
}
