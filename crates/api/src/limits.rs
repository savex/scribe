//! Transport limits (specs 12.1.1): a misbehaving local client can't make the daemon allocate or
//! wait without bound.

use std::time::Duration;

/// Largest message either side decodes.
pub const MAX_MESSAGE: usize = 4 * 1024 * 1024;
/// Longest a unary call may run on the server.
pub const CALL_TIMEOUT: Duration = Duration::from_secs(30);
/// Calls handled at once on one connection.
pub const PER_CONNECTION: usize = 16;
/// Open HTTP/2 streams per connection (streaming calls such as `WatchAlerts` hold one each).
pub const MAX_STREAMS: u32 = 8;
