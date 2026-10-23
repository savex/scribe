//! Shared types used by every scribe component: normalized flow events,
//! policy modes, alerts, the clock and the platform sensor interface.

pub mod alert;
pub mod clock;
pub mod event;
pub mod mode;
pub mod sensor;

pub use alert::{Alert, AlertOutput};
pub use clock::{Clock, SystemClock};
pub use event::{FlowEvent, FlowKind, Protocol, Security};
pub use mode::Mode;
pub use sensor::{Sensor, SensorError};
