//! The platform's transport behind one interface: a Unix socket on Linux and macOS, a named pipe
//! on Windows. The daemon and the clients use this module and need no platform code.

#[cfg(feature = "server")]
use std::path::Path;

#[cfg(unix)]
use crate::unix as platform;
#[cfg(windows)]
use crate::windows as platform;

pub use crate::ServerCheck;
#[cfg(feature = "server")]
pub use platform::serve;
#[cfg(feature = "client")]
pub use platform::{channel, connect};

/// What [`bind`] returns and [`serve`] takes.
#[cfg(all(feature = "server", unix))]
pub type Listener = tokio::net::UnixListener;
#[cfg(all(feature = "server", windows))]
pub use platform::Listener;

/// Starts listening at `path`. On Windows `groups` (the read group and the admin group) are let
/// into the pipe's access list; on Unix the socket's folder (`root:scribe`, `0750`) decides who
/// may connect and `groups` is not used.
#[cfg(feature = "server")]
pub fn bind(path: &Path, groups: &[&str]) -> Result<Listener, crate::TransportError> {
    #[cfg(unix)]
    {
        let _ = groups;
        platform::bind(path)
    }
    #[cfg(windows)]
    {
        platform::bind(path, groups)
    }
}

/// The group that may read (status, hosts, alerts) when it exists (specs 6.3; name Proposed).
pub const READ_GROUP: &str = "scribe";
