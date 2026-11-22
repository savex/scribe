//! The policy engine (specs 8.1–8.3): decides for each flow whether it is recorded, added to the
//! baseline or alerted on. It does no I/O: the daemon gives it the configuration, the baseline,
//! threat lists and module signals, and stores what it decides.

pub mod signals;
pub mod threat;

pub use threat::{ThreatFormat, ThreatSet};
