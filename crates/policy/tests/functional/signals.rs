//! Built-in signals: IPs, TLDs, entropy, usual ports.

use proptest::prelude::*;
use scribe_core::Protocol;
use scribe_policy::signals::*;

#[test]
fn ips_are_recognised_in_both_forms() {
    assert!(is_ip("198.51.100.7"));
    assert!(is_ip("2001:db8::50"));
    assert!(is_ip("[2001:db8::50]"));
    assert!(!is_ip("api.example.com"));
}

#[test]
fn tld_is_the_last_label() {
    assert_eq!(tld("shop.example.net"), Some("net"));
    assert_eq!(tld("api.example.com."), Some("com"));
    assert_eq!(tld("localhost"), None);
    assert_eq!(tld("198.51.100.7"), None);
}

#[test]
fn entropy_matches_hand_computed_values() {
    assert_eq!(shannon_bits(""), 0.0);
    assert_eq!(shannon_bits("aaaa"), 0.0);
    assert!((shannon_bits("ab") - 1.0).abs() < 1e-9);
    assert!((shannon_bits("x7qk2v9zr4tplm8w") - 4.0).abs() < 1e-9); // 16 distinct characters
}

#[test]
fn random_looking_names_are_flagged_and_ordinary_ones_are_not() {
    assert!(high_entropy("x7qk2v9zr4tplm8w.example.net", 10, 3.5));
    for ordinary in [
        "api.example.com",
        "docs.example.com",
        "authentication.example.com", // long but readable: 3.3 bits
        "198.51.100.7",
        "a1b2c3d4e.example.com", // 9 characters: too short
    ] {
        assert!(!high_entropy(ordinary, 10, 3.5), "{ordinary}");
    }
    assert_eq!(longest_label("a.bbb.cc"), "bbb");
}

#[test]
fn usual_ports_follow_the_transport() {
    let usual = UsualPorts::default();
    assert!(usual.is_usual(Protocol::Tcp, 443));
    assert!(!usual.is_usual(Protocol::Tcp, 8443));
    assert!(usual.is_usual(Protocol::Quic, 443));
    assert!(usual.is_usual(Protocol::Udp, 123));
    assert!(!usual.is_usual(Protocol::Tcp, 123));
}

proptest! {
    #[test]
    fn entropy_is_bounded_by_the_alphabet(s in "[a-z0-9]{1,64}") {
        let bits = shannon_bits(&s);
        let distinct = s.chars().collect::<std::collections::HashSet<_>>().len() as f64;
        prop_assert!(bits >= 0.0 && bits <= distinct.log2() + 1e-9);
    }
}
