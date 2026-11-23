//! Named-pipe transport (Windows), specs 12.1.1.
//!
//! Server: [`bind`] creates the first pipe instance (`first_pipe_instance`, remote clients
//! rejected) with an explicit access list: SYSTEM, Administrators and the daemon's own user get full
//! access; the read and admin groups, when they exist, may read and write but not create pipe
//! instances, so nobody else can squat the name. [`serve`] accepts connections and attaches the
//! client's identity from its process token. Client: [`connect`] refuses a pipe server that doesn't
//! run as SYSTEM (or, with `RootOrSelf`, as the calling user).

// Some helpers serve only the server or only the client side.
#![cfg_attr(
    not(all(feature = "server", feature = "client")),
    allow(dead_code, unused_imports)
)]

use std::ffi::c_void;
use std::io;
use std::path::Path;
use std::ptr::{null, null_mut};

use windows_sys::Win32::Foundation::{CloseHandle, LocalFree, HANDLE};
use windows_sys::Win32::Security::Authorization::{
    ConvertSidToStringSidW, ConvertStringSecurityDescriptorToSecurityDescriptorW,
};
use windows_sys::Win32::Security::{
    GetTokenInformation, LookupAccountNameW, LookupAccountSidW, TokenGroups, TokenUser,
    SECURITY_ATTRIBUTES, SID_AND_ATTRIBUTES, TOKEN_GROUPS, TOKEN_USER,
};
use windows_sys::Win32::System::Threading::{GetCurrentProcess, OpenProcess, OpenProcessToken};

use crate::TransportError;

const PROCESS_QUERY_LIMITED_INFORMATION: u32 = 0x1000;
const TOKEN_QUERY: u32 = 0x0008;
const SE_GROUP_ENABLED: u32 = 0x4;
const SE_GROUP_USE_FOR_DENY_ONLY: u32 = 0x10;
const SDDL_REVISION_1: u32 = 1;
const SID_SYSTEM: &str = "S-1-5-18";
const SID_ADMINISTRATORS: &str = "S-1-5-32-544";
/// Read and write data, but not FILE_CREATE_PIPE_INSTANCE (= FILE_APPEND_DATA).
const CLIENT_RIGHTS: &str = "0x0012019b";

pub use crate::ServerCheck;

fn wide(s: &str) -> Vec<u16> {
    s.encode_utf16().chain(std::iter::once(0)).collect()
}

fn from_wide(buf: &[u16]) -> String {
    let end = buf.iter().position(|&c| c == 0).unwrap_or(buf.len());
    String::from_utf16_lossy(&buf[..end])
}

/// Closes a handle when dropped.
struct Owned(HANDLE);

impl Drop for Owned {
    fn drop(&mut self) {
        if !self.0.is_null() {
            // SAFETY: the handle was opened by this module and is closed once.
            unsafe { CloseHandle(self.0) };
        }
    }
}

fn last_error(what: &str) -> io::Error {
    let e = io::Error::last_os_error();
    io::Error::new(e.kind(), format!("{what}: {e}"))
}

/// A process's access token, for queries.
fn process_token(pid: Option<u32>) -> io::Result<Owned> {
    // SAFETY: plain Win32 calls; every handle is owned and closed by `Owned`.
    unsafe {
        let process = match pid {
            Some(pid) => {
                let h = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, 0, pid);
                if h.is_null() {
                    return Err(last_error("OpenProcess"));
                }
                Owned(h)
            }
            // The pseudo handle needs no closing.
            None => Owned(null_mut()),
        };
        let handle = if process.0.is_null() {
            GetCurrentProcess()
        } else {
            process.0
        };
        let mut token: HANDLE = null_mut();
        if OpenProcessToken(handle, TOKEN_QUERY, &mut token) == 0 {
            return Err(last_error("OpenProcessToken"));
        }
        Ok(Owned(token))
    }
}

/// `GetTokenInformation` into a buffer of the size it asks for.
fn token_info(token: &Owned, class: i32) -> io::Result<Vec<u64>> {
    let mut len = 0u32;
    // SAFETY: a size query with a null buffer, then a call with a buffer of that size
    // (u64 elements keep the structures aligned).
    unsafe {
        GetTokenInformation(token.0, class, null_mut(), 0, &mut len);
        let mut buf = vec![0u64; (len as usize).div_ceil(8).max(1)];
        if GetTokenInformation(token.0, class, buf.as_mut_ptr().cast(), len, &mut len) == 0 {
            return Err(last_error("GetTokenInformation"));
        }
        Ok(buf)
    }
}

fn sid_string(sid: *mut c_void) -> Option<String> {
    let mut text: *mut u16 = null_mut();
    // SAFETY: `sid` points into a token buffer still alive; the string is freed with LocalFree.
    unsafe {
        if ConvertSidToStringSidW(sid, &mut text) == 0 {
            return None;
        }
        let mut n = 0;
        while *text.add(n) != 0 {
            n += 1;
        }
        let s = String::from_utf16_lossy(std::slice::from_raw_parts(text, n));
        LocalFree(text.cast());
        Some(s)
    }
}

/// `(domain, name)` of a SID.
fn account_of(sid: *mut c_void) -> Option<(String, String)> {
    let (mut name, mut domain) = (vec![0u16; 256], vec![0u16; 256]);
    let (mut name_len, mut domain_len) = (name.len() as u32, domain.len() as u32);
    let mut kind = 0;
    // SAFETY: buffers sized as told; `sid` is alive.
    let ok = unsafe {
        LookupAccountSidW(
            null(),
            sid,
            name.as_mut_ptr(),
            &mut name_len,
            domain.as_mut_ptr(),
            &mut domain_len,
            &mut kind,
        )
    };
    (ok != 0).then(|| (from_wide(&domain), from_wide(&name)))
}

/// The string SID of an account or group name, if it exists here.
fn sid_of_name(name: &str) -> Option<String> {
    let name = wide(name);
    let mut sid = vec![0u8; 128];
    let mut sid_len = sid.len() as u32;
    let mut domain = vec![0u16; 256];
    let mut domain_len = domain.len() as u32;
    let mut kind = 0;
    // SAFETY: buffers sized as told.
    let ok = unsafe {
        LookupAccountNameW(
            null(),
            name.as_ptr(),
            sid.as_mut_ptr().cast(),
            &mut sid_len,
            domain.as_mut_ptr(),
            &mut domain_len,
            &mut kind,
        )
    };
    if ok == 0 {
        return None;
    }
    sid_string(sid.as_mut_ptr().cast())
}

/// The user SID (as a string) of process `pid`, or of this process.
fn process_user_sid(pid: Option<u32>) -> io::Result<String> {
    let token = process_token(pid)?;
    let buf = token_info(&token, TokenUser)?;
    // SAFETY: the buffer holds a TOKEN_USER written by GetTokenInformation.
    let user = unsafe { &*(buf.as_ptr() as *const TOKEN_USER) };
    sid_string(user.User.Sid).ok_or_else(|| io::Error::other("cannot read the token's user"))
}

/// Refuses a pipe server whose process isn't run by SYSTEM (or the calling user, with
/// `RootOrSelf`).
fn check_server_pid(pid: u32, check: ServerCheck) -> io::Result<()> {
    let owner = process_user_sid(Some(pid))?;
    let ok = owner == SID_SYSTEM
        || (check == ServerCheck::RootOrSelf && owner == process_user_sid(None)?);
    if ok {
        Ok(())
    } else {
        Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            format!("the pipe server runs as {owner}, not SYSTEM; refusing to talk to it"),
        ))
    }
}

/// The access list of the pipe: SYSTEM, Administrators and this process's user get full
/// access; each of `groups` that exists may read and write.
fn sddl(groups: &[&str]) -> io::Result<String> {
    let me = process_user_sid(None)?;
    let mut text = format!("D:P(A;;GA;;;SY)(A;;GA;;;BA)(A;;GA;;;{me})");
    for group in groups {
        if let Some(sid) = sid_of_name(group) {
            text.push_str(&format!("(A;;{CLIENT_RIGHTS};;;{sid})"));
        }
    }
    Ok(text)
}

/// A security descriptor built from SDDL, freed on drop.
struct Descriptor(*mut c_void);

impl Drop for Descriptor {
    fn drop(&mut self) {
        // SAFETY: allocated by ConvertStringSecurityDescriptorToSecurityDescriptorW.
        unsafe { LocalFree(self.0) };
    }
}

// SAFETY: the descriptor is immutable after creation and only read by CreateNamedPipeW.
unsafe impl Send for Descriptor {}
unsafe impl Sync for Descriptor {}

fn descriptor(groups: &[&str]) -> io::Result<Descriptor> {
    let text = wide(&sddl(groups)?);
    let mut sd: *mut c_void = null_mut();
    // SAFETY: valid NUL-terminated SDDL; the descriptor is freed by `Descriptor`.
    let ok = unsafe {
        ConvertStringSecurityDescriptorToSecurityDescriptorW(
            text.as_ptr(),
            SDDL_REVISION_1,
            &mut sd,
            null_mut(),
        )
    };
    if ok == 0 {
        return Err(last_error(
            "ConvertStringSecurityDescriptorToSecurityDescriptorW",
        ));
    }
    Ok(Descriptor(sd))
}

#[cfg(feature = "server")]
pub use server::{bind, identify, serve, Listener};

#[cfg(feature = "server")]
mod server {
    use super::*;
    use crate::access::Caller;
    use crate::limits;
    use std::os::windows::io::AsRawHandle;
    use std::pin::Pin;
    use std::sync::Arc;
    use std::task::{Context, Poll};
    use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};
    use tokio::net::windows::named_pipe::{NamedPipeServer, ServerOptions};
    use tonic::service::Routes;
    use tonic::transport::server::Connected;
    use windows_sys::Win32::System::Pipes::GetNamedPipeClientProcessId;

    /// The first pipe instance and what is needed to create the next ones.
    pub struct Listener {
        name: String,
        first: NamedPipeServer,
        descriptor: Arc<Descriptor>,
    }

    fn create(name: &str, first: bool, sd: &Descriptor) -> io::Result<NamedPipeServer> {
        let mut attrs = SECURITY_ATTRIBUTES {
            nLength: std::mem::size_of::<SECURITY_ATTRIBUTES>() as u32,
            lpSecurityDescriptor: sd.0,
            bInheritHandle: 0,
        };
        // SAFETY: `attrs` and the descriptor outlive the call.
        unsafe {
            ServerOptions::new()
                .first_pipe_instance(first)
                .reject_remote_clients(true)
                .create_with_security_attributes_raw(
                    name,
                    (&mut attrs as *mut SECURITY_ATTRIBUTES).cast(),
                )
        }
    }

    /// Creates the pipe `name` (`\\.\pipe\…`). `groups` may read and write (the read group and the
    /// admin group); a pipe that another process already holds is refused.
    pub fn bind(name: &Path, groups: &[&str]) -> Result<Listener, TransportError> {
        let text = name.display().to_string();
        let io_error = |source| TransportError::Io {
            path: text.clone(),
            source,
        };
        let sd = descriptor(groups).map_err(io_error)?;
        let first = create(&text, true, &sd).map_err(|e| {
            if e.kind() == io::ErrorKind::PermissionDenied {
                TransportError::Refused(format!(
                    "{text} is in use: another scribed (or another program) holds it"
                ))
            } else {
                io_error(e)
            }
        })?;
        Ok(Listener {
            name: text,
            first,
            descriptor: Arc::new(sd),
        })
    }

    /// The identity of the client of a connected pipe, from its process token.
    pub fn identify(pipe: &NamedPipeServer) -> io::Result<Caller> {
        let mut pid = 0u32;
        // SAFETY: the handle belongs to a live, connected pipe.
        if unsafe { GetNamedPipeClientProcessId(pipe.as_raw_handle() as HANDLE, &mut pid) } == 0 {
            return Err(last_error("GetNamedPipeClientProcessId"));
        }
        let token = process_token(Some(pid))?;
        let user_buf = token_info(&token, TokenUser)?;
        // SAFETY: TOKEN_USER written by GetTokenInformation.
        let user_sid = unsafe { (*(user_buf.as_ptr() as *const TOKEN_USER)).User.Sid };
        let user_sid_text = sid_string(user_sid).unwrap_or_default();
        let user = match account_of(user_sid) {
            Some((domain, name)) if !domain.is_empty() => format!("{domain}\\{name}"),
            Some((_, name)) => name,
            None => user_sid_text.clone(),
        };
        let group_buf = token_info(&token, TokenGroups)?;
        // SAFETY: TOKEN_GROUPS written by GetTokenInformation; GroupCount entries follow.
        let entries: &[SID_AND_ATTRIBUTES] = unsafe {
            let groups = &*(group_buf.as_ptr() as *const TOKEN_GROUPS);
            std::slice::from_raw_parts(groups.Groups.as_ptr(), groups.GroupCount as usize)
        };
        let mut privileged = user_sid_text == SID_SYSTEM;
        let mut names = Vec::new();
        for g in entries {
            let enabled = g.Attributes & SE_GROUP_ENABLED != 0
                && g.Attributes & SE_GROUP_USE_FOR_DENY_ONLY == 0;
            if !enabled {
                continue;
            }
            if sid_string(g.Sid).as_deref() == Some(SID_ADMINISTRATORS) {
                privileged = true;
            }
            if let Some((domain, name)) = account_of(g.Sid) {
                if !domain.is_empty() {
                    names.push(format!("{domain}\\{name}"));
                }
                names.push(name);
            }
        }
        Ok(Caller {
            user,
            uid: None,
            pid: Some(pid as i32),
            privileged,
            groups: names,
        })
    }

    /// Serves `routes` on the pipe until `shutdown` completes, with the limits from
    /// [`crate::limits`]. A new instance is created for each connection; clients that can't be
    /// identified are dropped.
    pub async fn serve(
        listener: Listener,
        routes: Routes,
        shutdown: impl std::future::Future<Output = ()>,
    ) -> Result<(), tonic::transport::Error> {
        let (tx, rx) = tokio::sync::mpsc::channel::<io::Result<PeerPipe>>(16);
        let accept = tokio::spawn(async move {
            let Listener {
                name,
                first,
                descriptor,
            } = listener;
            let mut server = first;
            loop {
                if server.connect().await.is_err() {
                    match create(&name, false, &descriptor) {
                        Ok(next) => server = next,
                        Err(e) => {
                            let _ = tx.send(Err(e)).await;
                            return;
                        }
                    }
                    continue;
                }
                let connected = server;
                server = match create(&name, false, &descriptor) {
                    Ok(next) => next,
                    Err(e) => {
                        let _ = tx.send(Err(e)).await;
                        return;
                    }
                };
                match identify(&connected) {
                    Ok(caller) => {
                        let peer = PeerPipe {
                            pipe: connected,
                            caller,
                        };
                        if tx.send(Ok(peer)).await.is_err() {
                            return;
                        }
                    }
                    Err(e) => tracing_free_warn(&e),
                }
            }
        });
        let result = tonic::transport::Server::builder()
            .timeout(limits::CALL_TIMEOUT)
            .concurrency_limit_per_connection(limits::PER_CONNECTION)
            .max_concurrent_streams(Some(limits::MAX_STREAMS))
            .add_routes(routes)
            .serve_with_incoming_shutdown(tokio_stream::wrappers::ReceiverStream::new(rx), shutdown)
            .await;
        accept.abort();
        result
    }

    /// This crate doesn't log; an unidentifiable client is just dropped.
    fn tracing_free_warn(_e: &io::Error) {}

    struct PeerPipe {
        pipe: NamedPipeServer,
        caller: Caller,
    }

    impl Connected for PeerPipe {
        type ConnectInfo = Caller;

        fn connect_info(&self) -> Caller {
            self.caller.clone()
        }
    }

    impl AsyncRead for PeerPipe {
        fn poll_read(
            mut self: Pin<&mut Self>,
            cx: &mut Context<'_>,
            buf: &mut ReadBuf<'_>,
        ) -> Poll<io::Result<()>> {
            Pin::new(&mut self.pipe).poll_read(cx, buf)
        }
    }

    impl AsyncWrite for PeerPipe {
        fn poll_write(
            mut self: Pin<&mut Self>,
            cx: &mut Context<'_>,
            buf: &[u8],
        ) -> Poll<io::Result<usize>> {
            Pin::new(&mut self.pipe).poll_write(cx, buf)
        }

        fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
            Pin::new(&mut self.pipe).poll_flush(cx)
        }

        fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
            Pin::new(&mut self.pipe).poll_shutdown(cx)
        }
    }
}

#[cfg(feature = "client")]
pub use client::{channel, connect};

#[cfg(feature = "client")]
mod client {
    use super::*;
    use crate::pb::scribe_client::ScribeClient;
    use hyper_util::rt::TokioIo;
    use std::os::windows::io::AsRawHandle;
    use std::time::Duration;
    use tokio::net::windows::named_pipe::ClientOptions;
    use tonic::transport::{Channel, Endpoint};
    use windows_sys::Win32::System::Pipes::GetNamedPipeServerProcessId;

    const ERROR_PIPE_BUSY: i32 = 231;

    /// Opens the pipe, waiting while every instance is busy, and checks who serves it.
    async fn open(
        name: String,
        check: ServerCheck,
    ) -> io::Result<tokio::net::windows::named_pipe::NamedPipeClient> {
        let pipe = loop {
            match ClientOptions::new().open(&name) {
                Ok(pipe) => break pipe,
                Err(e) if e.raw_os_error() == Some(ERROR_PIPE_BUSY) => {
                    tokio::time::sleep(Duration::from_millis(20)).await;
                }
                Err(e) => return Err(e),
            }
        };
        let mut pid = 0u32;
        // SAFETY: the handle belongs to the open pipe.
        if unsafe { GetNamedPipeServerProcessId(pipe.as_raw_handle() as HANDLE, &mut pid) } == 0 {
            return Err(last_error("GetNamedPipeServerProcessId"));
        }
        check_server_pid(pid, check)?;
        Ok(pipe)
    }

    /// Connects to the daemon at the pipe `name`; `timeout` bounds the connection and each call.
    pub async fn connect(
        name: &Path,
        check: ServerCheck,
        timeout: Duration,
    ) -> Result<ScribeClient<Channel>, TransportError> {
        let channel = channel(name, check, timeout).await?;
        Ok(ScribeClient::new(channel).max_decoding_message_size(crate::limits::MAX_MESSAGE))
    }

    /// The connection [`connect`] makes, for other services on the same pipe.
    pub async fn channel(
        name: &Path,
        check: ServerCheck,
        timeout: Duration,
    ) -> Result<Channel, TransportError> {
        let text = name.display().to_string();
        // Fail early with the pipe's own error, and refuse a wrong server before any request.
        match tokio::time::timeout(timeout, open(text.clone(), check)).await {
            Ok(Ok(probe)) => drop(probe),
            Ok(Err(e))
                if e.kind() == io::ErrorKind::PermissionDenied
                    && e.to_string().contains("refusing") =>
            {
                return Err(TransportError::Refused(e.to_string()))
            }
            Ok(Err(e)) => {
                return Err(TransportError::Io {
                    path: text,
                    source: e,
                })
            }
            Err(_) => return Err(TransportError::Connect(format!("{text}: timed out"))),
        }
        Endpoint::from_static("http://scribed.local")
            .connect_timeout(timeout)
            .timeout(timeout)
            .connect_with_connector(tower::service_fn(move |_| {
                let name = text.clone();
                async move { open(name, check).await.map(TokioIo::new) }
            }))
            .await
            .map_err(|e| TransportError::Connect(e.to_string()))
    }
}
