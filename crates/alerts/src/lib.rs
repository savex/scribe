//! Alert outputs (specs 7.2, FR-16): the [`Dispatcher`] hands every alert the policy raised to each
//! configured [`AlertOutput`] on that output's own thread, behind a bounded queue and a per-minute
//! rate limit ([`Throttle`]), so a slow or failing output never holds up the pipeline or the other
//! outputs.
//!
//! Outputs here: [`LogOutput`] (a `scribe::alert` line in scribed's log). OS notifications are
//! shown by the `scribe notify` agent in the user's session, which follows the API's alert stream:
//! a system service can't post to a desktop session on any of the three systems.

mod dispatch;
mod log;
mod throttle;

pub use dispatch::{Dispatcher, OutputStats, QUEUE};
pub use log::{alert_line, LogOutput};
pub use scribe_core::{Alert, AlertOutput};
pub use throttle::{Admit, Throttle};
