use std::sync::mpsc::Sender;

use crate::Observation;

/// A platform capture backend. Implementations push observations (normalized events plus the
/// first client bytes) into `out`. `start` may be called again after `stop`.
pub trait Sensor: Send {
    fn name(&self) -> &'static str;
    /// Whether events carry pid / process path.
    fn has_process_info(&self) -> bool;
    fn start(&mut self, out: Sender<Observation>) -> Result<(), SensorError>;
    fn stop(&mut self);
}

#[derive(Debug, thiserror::Error)]
pub enum SensorError {
    #[error("unsupported: {0}")]
    Unsupported(&'static str),
    #[error("permission denied: {0}")]
    Permission(String),
    #[error("io error: {0}")]
    Io(#[from] std::io::Error),
}

#[cfg(test)]
mod tests {
    use super::*;

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
}
