//! Local API between `scribed` and its clients (specs 6.3): the gRPC protocol from
//! `proto/scribe/v1/api.proto`, the socket transport, and on the server side the caller's identity
//! and access checks.
//!
//! Features: `server` (daemon side) and `client` (CLI, UI). There is no TCP listener: Unix sockets
//! on Linux and macOS, a named pipe on Windows.

/// Generated messages, and the `scribe_server` / `scribe_client` modules per feature.
#[allow(clippy::all, clippy::pedantic, missing_docs)]
pub mod pb {
    tonic::include_proto!("scribe.v1");
}

#[cfg(feature = "server")]
pub mod access;
mod convert;
pub mod limits;
#[cfg(all(unix, any(feature = "server", feature = "client")))]
pub mod unix;

pub use convert::{mode_from_api, mode_to_api};

/// Version of the protocol; clients compare it with `Status.api_version` to detect a mismatch.
/// Raise it on any incompatible change to the .proto files.
pub const API_VERSION: u32 = 1;

/// Where `scribed` listens unless `[api] socket` says otherwise (specs 12.1.1: the directory is
/// `root:scribe` `0750`; the socket file's own mode isn't relied on).
pub fn default_socket() -> &'static str {
    if cfg!(windows) {
        r"\\.\pipe\scribed"
    } else if cfg!(target_os = "macos") {
        "/var/run/scribe/api.sock"
    } else {
        "/run/scribe/api.sock"
    }
}

/// Environment variable clients read for another socket path (tests, a second daemon).
pub const SOCKET_ENV: &str = "SCRIBE_SOCKET";

/// Errors setting up the transport.
#[derive(Debug, thiserror::Error)]
pub enum TransportError {
    #[error("{path}: {source}")]
    Io {
        path: String,
        #[source]
        source: std::io::Error,
    },
    /// The socket exists but isn't the real `scribed` (specs 12.1.1), or another process listens.
    #[error("{0}")]
    Refused(String),
    #[error("cannot connect: {0}")]
    Connect(String),
}
