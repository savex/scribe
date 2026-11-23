//! Reaching scribed: which socket, the connection and what errors mean to the user.

use std::ffi::OsString;
use std::path::{Path, PathBuf};
use std::time::Duration;

use scribe_api::pb::scribe_client::ScribeClient;
use scribe_api::TransportError;
use tonic::transport::Channel;

use crate::EXIT_FAILURE;

/// How long a call may take unless the command says otherwise.
pub const CALL_TIMEOUT: Duration = Duration::from_secs(10);

/// A command that didn't work: what to tell the user and the exit code.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Failure {
    pub message: String,
    pub code: u8,
}

impl Failure {
    pub fn new(message: impl Into<String>) -> Self {
        Self {
            message: message.into(),
            code: EXIT_FAILURE,
        }
    }
}

/// `--socket`, else `SCRIBE_SOCKET`, else the OS default.
pub fn socket_path(flag: Option<PathBuf>, env: Option<OsString>) -> PathBuf {
    flag.or_else(|| env.filter(|v| !v.is_empty()).map(PathBuf::from))
        .unwrap_or_else(|| PathBuf::from(scribe_api::default_socket()))
}

/// The message for a daemon that can't be reached (specs 6.2.1).
pub fn unreachable(socket: &Path, detail: &str) -> Failure {
    Failure::new(format!(
        "scribed is not running or its socket is not reachable ({}: {detail})",
        socket.display()
    ))
}

/// What a transport error means to the user.
pub fn transport_failure(socket: &Path, e: TransportError) -> Failure {
    match e {
        TransportError::Io { source, .. }
            if source.kind() == std::io::ErrorKind::PermissionDenied =>
        {
            Failure::new(format!(
                "cannot open {} (permission denied): the scribe group may read it",
                socket.display()
            ))
        }
        TransportError::Io { source, .. } => unreachable(socket, &source.to_string()),
        TransportError::Connect(detail) => unreachable(socket, &detail),
        TransportError::Refused(why) => Failure::new(why),
    }
}

/// What a refused or failed call means to the user.
pub fn call_failure(status: tonic::Status) -> Failure {
    use tonic::Code;
    let message = status.message().to_owned();
    match status.code() {
        Code::PermissionDenied if message.starts_with("permission denied") => Failure::new(message),
        Code::PermissionDenied => Failure::new(format!("permission denied: {message}")),
        Code::Unimplemented => Failure::new(format!("this scribed can't do that: {message}")),
        Code::Unavailable | Code::Cancelled | Code::DeadlineExceeded | Code::Unknown
            if message.is_empty() || message.contains("transport") =>
        {
            Failure::new(format!("scribed did not answer ({})", status.code()))
        }
        _ => Failure::new(message),
    }
}

/// A client for scribed at `socket`; `timeout` bounds connecting and each call.
pub async fn connect(socket: &Path, timeout: Duration) -> Result<ScribeClient<Channel>, Failure> {
    scribe_api::transport::connect(socket, scribe_api::ServerCheck::RootOrSelf, timeout)
        .await
        .map_err(|e| transport_failure(socket, e))
}
