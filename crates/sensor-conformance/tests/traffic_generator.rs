//! Checks the generator itself; needs no privileges.

use scribe_sensor_conformance::{default_cases, traffic};

mod functional {
    use super::*;

    #[test]
    fn every_case_reaches_its_local_server() {
        for case in default_cases() {
            let (expected, receipt) = traffic::send(&case).expect("send traffic");
            let received = receipt.wait().expect("server received data");
            assert!(!received.is_empty(), "{case:?}: server got no bytes");
            assert!(expected.dst.ip().is_loopback());
        }
    }

    #[test]
    fn cases_use_distinct_ports() {
        let ports: Vec<u16> = default_cases()
            .iter()
            .map(|case| {
                let (expected, receipt) = traffic::send(case).unwrap();
                receipt.wait().unwrap();
                expected.dst.port()
            })
            .collect();
        let mut unique = ports.clone();
        unique.sort_unstable();
        unique.dedup();
        assert_eq!(unique.len(), ports.len());
    }
}
