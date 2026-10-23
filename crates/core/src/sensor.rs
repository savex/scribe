use std::fmt;
use std::sync::mpsc::Sender;

use crate::FlowEvent;

/// A platform capture backend. Implementations push normalized events into `out`.
pub trait Sensor: Send {
    fn name(&self) -> &'static str;
    /// Whether events carry pid / process path.
    fn has_process_info(&self) -> bool;
    fn start(&mut self, out: Sender<FlowEvent>) -> Result<(), SensorError>;
    fn stop(&mut self);
}

#[derive(Debug)]
pub enum SensorError {
    Unsupported(&'static str),
    Permission(String),
    Io(std::io::Error),
}

impl fmt::Display for SensorError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            SensorError::Unsupported(what) => write!(f, "unsupported: {what}"),
            SensorError::Permission(msg) => write!(f, "permission denied: {msg}"),
            SensorError::Io(err) => write!(f, "io error: {err}"),
        }
    }
}

impl std::error::Error for SensorError {}

impl From<std::io::Error> for SensorError {
    fn from(err: std::io::Error) -> Self {
        SensorError::Io(err)
    }
}
