//! Shared types used by every scribe component: normalized flow events,
//! policy modes, alerts, the clock, the platform sensor interface, module data (flow notes,
//! module records, metric samples), config value units and OS defaults.

pub mod alert;
pub mod clock;
pub mod event;
pub mod mode;
pub mod module;
pub mod platform;
pub mod sensor;
pub mod units;

/// Version from the nearest `v*` git tag, e.g. `1.2.0` or `1.2.0+3.gabc1234` (see `build.rs`).
pub const VERSION: &str = env!("SCRIBE_VERSION");

pub use alert::{Alert, AlertOutput};
pub use clock::{Clock, SystemClock};
pub use event::{FlowEvent, FlowKind, Observation, Protocol, Security, HEAD_MAX};
pub use mode::Mode;
pub use module::{MetricSample, ModuleRecord, Notes};
pub use sensor::{Sensor, SensorError};
pub use units::{HumanDuration, SizeLimit};
