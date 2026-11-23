//! Unix socket transport (Linux, macOS).
//!
//! Server: [`bind`] a socket, then [`serve`] routes on it; every connection carries the peer's
//! [`Caller`](crate::access::Caller). Client: [`connect`] checks the socket belongs to root (or to the
//! caller itself) before sending anything.

use std::os::unix::fs::{FileTypeExt, MetadataExt};
use std::path::Path;

use crate::TransportError;

fn io_error(path: &Path, source: std::io::Error) -> TransportError {
    TransportError::Io {
        path: path.display().to_string(),
        source,
    }
}

/// The current process's user id.
pub fn current_uid() -> u32 {
    // SAFETY: getuid has no preconditions and cannot fail.
    unsafe { libc::getuid() }
}

/// Which socket owners a client accepts (specs 12.1.1: the real `scribed` runs as root).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ServerCheck {
    /// Owned by root or by the calling user (a user can't be fooled by their own socket; tests and
    /// development daemons run unprivileged).
    RootOrSelf,
    /// Owned by root only.
    Root,
}

/// Refuses `path` unless it is a socket whose owner `check` accepts.
pub fn check_server(path: &Path, check: ServerCheck) -> Result<(), TransportError> {
    let meta = std::fs::symlink_metadata(path).map_err(|e| io_error(path, e))?;
    if !meta.file_type().is_socket() {
        return Err(TransportError::Refused(format!(
            "{} is not a socket; refusing to talk to it",
            path.display()
        )));
    }
    let owner = meta.uid();
    let ok = owner == 0 || (check == ServerCheck::RootOrSelf && owner == current_uid());
    if ok {
        Ok(())
    } else {
        Err(TransportError::Refused(format!(
            "{} is owned by uid {owner}, not root; refusing to talk to it",
            path.display()
        )))
    }
}

#[cfg(feature = "client")]
pub use client::{channel, connect};

#[cfg(feature = "client")]
mod client {
    use super::*;
    use crate::pb::scribe_client::ScribeClient;
    use hyper_util::rt::TokioIo;
    use std::path::PathBuf;
    use std::time::Duration;
    use tonic::transport::{Channel, Endpoint};

    /// Connects to the daemon at `path` after [`check_server`]. `timeout` bounds the connection and
    /// each call.
    pub async fn connect(
        path: &Path,
        check: ServerCheck,
        timeout: Duration,
    ) -> Result<ScribeClient<Channel>, TransportError> {
        let channel = channel(path, check, timeout).await?;
        Ok(ScribeClient::new(channel).max_decoding_message_size(crate::limits::MAX_MESSAGE))
    }

    /// The connection [`connect`] makes, for other services on the same socket
    /// (`grpc.health.v1`, module services).
    pub async fn channel(
        path: &Path,
        check: ServerCheck,
        timeout: Duration,
    ) -> Result<Channel, TransportError> {
        check_server(path, check)?;
        let path: PathBuf = path.to_owned();
        // The URI is required by the HTTP layer and never resolved.
        let channel = Endpoint::from_static("http://scribed.local")
            .connect_timeout(timeout)
            .timeout(timeout)
            .connect_with_connector(tower::service_fn(move |_| {
                let path = path.clone();
                async move {
                    let stream = tokio::net::UnixStream::connect(path).await?;
                    Ok::<_, std::io::Error>(TokioIo::new(stream))
                }
            }))
            .await
            .map_err(|e| TransportError::Connect(source_chain(&e)))?;
        Ok(channel)
    }

    fn source_chain(e: &dyn std::error::Error) -> String {
        let mut text = e.to_string();
        let mut source = e.source();
        while let Some(s) = source {
            text = format!("{text}: {s}");
            source = s.source();
        }
        text
    }
}

#[cfg(feature = "server")]
pub use server::{bind, identify, serve, service};

#[cfg(feature = "server")]
mod server {
    use super::*;
    use crate::access::Caller;
    use crate::limits;
    use crate::pb::scribe_server::{Scribe, ScribeServer};
    use std::ffi::CStr;
    use std::future::Future;
    use std::os::unix::fs::PermissionsExt;
    use std::pin::Pin;
    use std::task::{Context, Poll};
    use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};
    use tokio::net::{UnixListener, UnixStream};
    use tokio_stream::StreamExt;
    use tonic::service::Routes;
    use tonic::transport::server::Connected;

    /// The `Scribe` service with the message size limit applied.
    pub fn service<T: Scribe>(api: T) -> ScribeServer<T> {
        ScribeServer::new(api)
            .max_decoding_message_size(limits::MAX_MESSAGE)
            .max_encoding_message_size(limits::MAX_MESSAGE)
    }

    /// Listens at `path`. A missing directory is created `0750` (the installer sets its group);
    /// a stale socket left by a crash is replaced; a live one, or anything that isn't a socket,
    /// is refused.
    pub fn bind(path: &Path) -> Result<UnixListener, TransportError> {
        if let Some(dir) = path.parent().filter(|d| !d.as_os_str().is_empty()) {
            if !dir.exists() {
                std::fs::create_dir_all(dir).map_err(|e| io_error(dir, e))?;
                std::fs::set_permissions(dir, std::fs::Permissions::from_mode(0o750))
                    .map_err(|e| io_error(dir, e))?;
            }
        }
        match std::fs::symlink_metadata(path) {
            Ok(meta) if meta.file_type().is_socket() => {
                if std::os::unix::net::UnixStream::connect(path).is_ok() {
                    return Err(TransportError::Refused(format!(
                        "{} is in use: another scribed is listening",
                        path.display()
                    )));
                }
                std::fs::remove_file(path).map_err(|e| io_error(path, e))?;
            }
            Ok(_) => {
                return Err(TransportError::Refused(format!(
                    "{} exists and is not a socket",
                    path.display()
                )))
            }
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
            Err(e) => return Err(io_error(path, e)),
        }
        UnixListener::bind(path).map_err(|e| io_error(path, e))
    }

    /// Serves `routes` on `listener` until `shutdown` completes, with the limits from
    /// [`crate::limits`]. Connections whose peer can't be identified are closed.
    pub async fn serve(
        listener: UnixListener,
        routes: Routes,
        shutdown: impl Future<Output = ()>,
    ) -> Result<(), tonic::transport::Error> {
        let incoming =
            tokio_stream::wrappers::UnixListenerStream::new(listener).then(|accepted| async move {
                let stream = accepted?;
                let cred = stream.peer_cred()?;
                let (uid, gid, pid) = (cred.uid(), cred.gid(), cred.pid());
                let caller = tokio::task::spawn_blocking(move || identify(uid, gid, pid))
                    .await
                    .map_err(std::io::Error::other)?;
                Ok::<_, std::io::Error>(PeerStream { stream, caller })
            });
        tonic::transport::Server::builder()
            .timeout(limits::CALL_TIMEOUT)
            .concurrency_limit_per_connection(limits::PER_CONNECTION)
            .max_concurrent_streams(Some(limits::MAX_STREAMS))
            .add_routes(routes)
            .serve_with_incoming_shutdown(incoming, shutdown)
            .await
    }

    /// A connection and the identity of its peer.
    struct PeerStream {
        stream: UnixStream,
        caller: Caller,
    }

    impl Connected for PeerStream {
        type ConnectInfo = Caller;

        fn connect_info(&self) -> Caller {
            self.caller.clone()
        }
    }

    impl AsyncRead for PeerStream {
        fn poll_read(
            mut self: Pin<&mut Self>,
            cx: &mut Context<'_>,
            buf: &mut ReadBuf<'_>,
        ) -> Poll<std::io::Result<()>> {
            Pin::new(&mut self.stream).poll_read(cx, buf)
        }
    }

    impl AsyncWrite for PeerStream {
        fn poll_write(
            mut self: Pin<&mut Self>,
            cx: &mut Context<'_>,
            buf: &[u8],
        ) -> Poll<std::io::Result<usize>> {
            Pin::new(&mut self.stream).poll_write(cx, buf)
        }

        fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
            Pin::new(&mut self.stream).poll_flush(cx)
        }

        fn poll_shutdown(
            mut self: Pin<&mut Self>,
            cx: &mut Context<'_>,
        ) -> Poll<std::io::Result<()>> {
            Pin::new(&mut self.stream).poll_shutdown(cx)
        }
    }

    /// The caller with user id `uid`, primary group `gid` and process `pid`, with its user and group
    /// names from the user database (blocking: NSS may ask a directory service).
    pub fn identify(uid: u32, gid: u32, pid: Option<i32>) -> Caller {
        let user = user_name(uid);
        let mut groups = match &user {
            Some(name) => group_ids(name, gid),
            None => vec![gid],
        };
        if !groups.contains(&gid) {
            groups.push(gid);
        }
        Caller {
            user: user.unwrap_or_else(|| uid.to_string()),
            uid: Some(uid),
            pid,
            privileged: uid == 0,
            groups: groups.into_iter().filter_map(group_name).collect(),
        }
    }

    const NAME_BUFFER: usize = 16 * 1024;

    fn user_name(uid: u32) -> Option<String> {
        let mut buf = vec![0 as libc::c_char; NAME_BUFFER];
        // SAFETY: passwd is plain data; getpwuid_r writes it and the strings into `buf`.
        let mut pwd: libc::passwd = unsafe { std::mem::zeroed() };
        let mut result = std::ptr::null_mut();
        // SAFETY: all pointers are valid for the given length; `result` tells whether pwd was set.
        let rc =
            unsafe { libc::getpwuid_r(uid, &mut pwd, buf.as_mut_ptr(), buf.len(), &mut result) };
        if rc != 0 || result.is_null() || pwd.pw_name.is_null() {
            return None;
        }
        // SAFETY: pw_name points into `buf` and is NUL-terminated.
        Some(
            unsafe { CStr::from_ptr(pwd.pw_name) }
                .to_string_lossy()
                .into_owned(),
        )
    }

    fn group_name(gid: u32) -> Option<String> {
        let mut buf = vec![0 as libc::c_char; NAME_BUFFER];
        // SAFETY: group is plain data; getgrgid_r writes it and the strings into `buf`.
        let mut grp: libc::group = unsafe { std::mem::zeroed() };
        let mut result = std::ptr::null_mut();
        // SAFETY: as in user_name.
        let rc =
            unsafe { libc::getgrgid_r(gid, &mut grp, buf.as_mut_ptr(), buf.len(), &mut result) };
        if rc != 0 || result.is_null() || grp.gr_name.is_null() {
            return None;
        }
        // SAFETY: gr_name points into `buf` and is NUL-terminated.
        Some(
            unsafe { CStr::from_ptr(grp.gr_name) }
                .to_string_lossy()
                .into_owned(),
        )
    }

    /// Ids of every group `user` belongs to (`getgrouplist`), `gid` included.
    // `GroupId` is `c_int` on macOS and `gid_t` (= u32) elsewhere, so the casts are no-ops on Linux.
    #[allow(clippy::unnecessary_cast)]
    fn group_ids(user: &str, gid: u32) -> Vec<u32> {
        let Ok(name) = std::ffi::CString::new(user) else {
            return vec![gid];
        };
        let mut count: libc::c_int = 64;
        loop {
            let mut ids = vec![0 as GroupId; count as usize];
            let before = count;
            // SAFETY: `ids` holds `count` entries; getgrouplist writes at most that many and sets
            // `count` to the number found (or needed, when it returns -1).
            let rc = unsafe {
                libc::getgrouplist(name.as_ptr(), gid as GroupId, ids.as_mut_ptr(), &mut count)
            };
            if rc >= 0 {
                ids.truncate(count.max(0) as usize);
                return ids.into_iter().map(|g| g as u32).collect();
            }
            // Too small: Linux reports the size needed; macOS doesn't, so double it.
            count = if count > before { count } else { before * 2 };
            if count > 65_536 {
                return vec![gid];
            }
        }
    }

    #[cfg(target_os = "macos")]
    type GroupId = libc::c_int;
    #[cfg(not(target_os = "macos"))]
    type GroupId = libc::gid_t;
}
