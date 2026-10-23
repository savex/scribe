//! Shared types used by every scribe component: normalized flow events,
//! policy modes and the platform sensor interface.

pub mod event;
pub mod mode;
pub mod sensor;

pub use event::{FlowEvent, FlowKind, Protocol, Security};
pub use mode::Mode;
pub use sensor::{Sensor, SensorError};
