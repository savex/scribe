//! Functional tests for `scribe_core::sensor` (moved from `src/sensor.rs`).

use scribe_core::sensor::*;

#[test]
fn io_errors_convert() {
    let err: SensorError = std::io::Error::other("no device").into();
    assert!(matches!(err, SensorError::Io(_)));
    assert_eq!(err.to_string(), "io error: no device");
}

#[test]
fn messages_are_stable() {
    assert_eq!(
        SensorError::Unsupported("pcap").to_string(),
        "unsupported: pcap"
    );
    assert_eq!(
        SensorError::Permission("need root".into()).to_string(),
        "permission denied: need root"
    );
}
