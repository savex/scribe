//! Outgoing HTTPS for scribed (specs 12.1.1, NFR-17): alert webhooks and threat-list downloads.
//!
//! One small blocking HTTP/1.1 client with scribe's rules built in, so no caller can get them
//! wrong:
//! - **HTTPS only.** `http://` only to a loopback host (`localhost`, `127.0.0.0/8`, `::1`).
//! - **Certificates** checked by the operating system's verifier (its trust store, enterprise CAs
//!   included). With `pin_sha256`, the server's leaf certificate must have that SHA-256 (of its
//!   DER bytes) instead, which also allows a self-signed certificate; the handshake signature is
//!   still checked.
//! - **Redirects** followed only to the same scheme, host and port, at most
//!   [`Options::max_redirects`] times; a POST follows only 307 and 308 (same method and body).
//! - **Timeouts** on connecting and on every read and write; a **size cap** on the response.
//! - No proxies, no cookies, no compression; `Connection: close` on every request.

mod tls;
mod url;

use std::io::{self, Read, Write};
use std::net::{TcpStream, ToSocketAddrs};
use std::sync::Arc;
use std::time::Duration;

pub use tls::{config as tls_config, parse_pin};
pub use url::{checked_url, is_loopback, Target};

/// What went wrong with a request; the message is meant for the log.
#[derive(Debug, thiserror::Error)]
pub enum NetError {
    #[error("bad URL `{0}`: {1}")]
    Url(String, String),
    #[error("`{0}`: plain http is allowed only to a loopback host; use https")]
    NotHttps(String),
    #[error("bad pin_sha256: {0}")]
    Pin(String),
    #[error("cannot reach {0}: {1}")]
    Connect(String, String),
    #[error("TLS with {0}: {1}")]
    Tls(String, String),
    #[error("{0} did not answer in time")]
    Timeout(String),
    #[error("{0}: {1}")]
    Io(String, String),
    #[error("{0}: the answer is larger than {1} bytes")]
    TooLarge(String, usize),
    #[error("{0}: {1}")]
    Protocol(String, String),
    #[error("{0}: {1}")]
    Redirect(String, String),
}

impl NetError {
    /// Worth trying again later (network trouble), as opposed to a configuration mistake.
    pub fn is_transient(&self) -> bool {
        matches!(
            self,
            NetError::Connect(..) | NetError::Timeout(_) | NetError::Io(..)
        )
    }
}

/// Client settings.
#[derive(Debug, Clone)]
pub struct Options {
    /// Connecting, and each read or write.
    pub timeout: Duration,
    /// Largest response body kept; a larger one fails with [`NetError::TooLarge`].
    pub max_body: usize,
    /// Hex SHA-256 of the server's leaf certificate (DER), e.g. from
    /// `openssl x509 -in cert.pem -outform der | openssl dgst -sha256`.
    pub pin_sha256: Option<String>,
    pub max_redirects: u8,
}

impl Default for Options {
    fn default() -> Self {
        Self {
            timeout: Duration::from_secs(10),
            max_body: 64 * 1024,
            pin_sha256: None,
            max_redirects: 3,
        }
    }
}

/// An HTTP answer (any status; callers decide what counts as success).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Response {
    pub status: u16,
    pub headers: Vec<(String, String)>,
    pub body: Vec<u8>,
}

impl Response {
    pub fn header(&self, name: &str) -> Option<&str> {
        self.headers
            .iter()
            .find(|(n, _)| n.eq_ignore_ascii_case(name))
            .map(|(_, v)| v.as_str())
    }

    pub fn is_success(&self) -> bool {
        (200..300).contains(&self.status)
    }
}

/// A client for one destination's rules (timeouts, pin); reusable and cheap to clone.
#[derive(Clone)]
pub struct Client {
    options: Options,
    tls: Arc<rustls::ClientConfig>,
}

impl std::fmt::Debug for Client {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Client")
            .field("options", &self.options)
            .finish_non_exhaustive()
    }
}

const MAX_HEAD: usize = 16 * 1024;

impl Client {
    pub fn new(options: Options) -> Result<Self, NetError> {
        let tls = tls::config(options.pin_sha256.as_deref())?;
        Ok(Self { options, tls })
    }

    pub fn options(&self) -> &Options {
        &self.options
    }

    pub fn get(&self, url: &str, headers: &[(&str, &str)]) -> Result<Response, NetError> {
        self.send("GET", url, headers, &[])
    }

    pub fn post(
        &self,
        url: &str,
        headers: &[(&str, &str)],
        body: &[u8],
    ) -> Result<Response, NetError> {
        self.send("POST", url, headers, body)
    }

    /// Send a request, following same-origin redirects.
    pub fn send(
        &self,
        method: &str,
        url: &str,
        headers: &[(&str, &str)],
        body: &[u8],
    ) -> Result<Response, NetError> {
        let mut target = checked_url(url)?;
        let mut redirects = 0;
        loop {
            let response = self.once(method, &target, headers, body)?;
            if !matches!(response.status, 301 | 302 | 303 | 307 | 308) {
                return Ok(response);
            }
            let Some(location) = response.header("location") else {
                return Ok(response);
            };
            if method != "GET" && !matches!(response.status, 307 | 308) {
                return Err(NetError::Redirect(
                    target.to_string(),
                    format!(
                        "{} redirect would turn the {method} into a GET; not followed",
                        response.status
                    ),
                ));
            }
            if redirects == self.options.max_redirects {
                return Err(NetError::Redirect(
                    target.to_string(),
                    format!("more than {} redirects", self.options.max_redirects),
                ));
            }
            redirects += 1;
            let next = target.join(location)?;
            if !next.same_origin(&target) {
                return Err(NetError::Redirect(
                    target.to_string(),
                    format!("redirect to another host or scheme ({next}) not followed"),
                ));
            }
            target = next;
        }
    }

    fn once(
        &self,
        method: &str,
        target: &Target,
        headers: &[(&str, &str)],
        body: &[u8],
    ) -> Result<Response, NetError> {
        let mut conn = self.connect(target)?;
        let mut head = format!(
            "{method} {} HTTP/1.1\r\nHost: {}\r\nUser-Agent: scribe/{}\r\nConnection: close\r\nAccept-Encoding: identity\r\n",
            target.path_query,
            target.host_header(),
            scribe_core::VERSION
        );
        if method != "GET" || !body.is_empty() {
            head.push_str(&format!("Content-Length: {}\r\n", body.len()));
        }
        for (name, value) in headers {
            if name.contains(['\r', '\n', ':']) || value.contains(['\r', '\n']) {
                return Err(NetError::Protocol(
                    target.to_string(),
                    format!("header `{name}` contains a line break"),
                ));
            }
            head.push_str(&format!("{name}: {value}\r\n"));
        }
        head.push_str("\r\n");
        let io = |e: io::Error| self.io_error(target, e);
        conn.write_all(head.as_bytes()).map_err(io)?;
        conn.write_all(body).map_err(io)?;
        conn.flush().map_err(io)?;
        self.read_response(target, &mut conn)
    }

    fn connect(&self, target: &Target) -> Result<Conn, NetError> {
        let addrs = (target.host.as_str(), target.port)
            .to_socket_addrs()
            .map_err(|e| NetError::Connect(target.to_string(), e.to_string()))?;
        let mut last = None;
        let mut stream = None;
        for addr in addrs {
            match TcpStream::connect_timeout(&addr, self.options.timeout) {
                Ok(s) => {
                    stream = Some(s);
                    break;
                }
                Err(e) => last = Some(e),
            }
        }
        let stream = stream.ok_or_else(|| match last {
            Some(e) if is_timeout(&e) => NetError::Timeout(target.to_string()),
            Some(e) => NetError::Connect(target.to_string(), e.to_string()),
            None => NetError::Connect(target.to_string(), "no address".into()),
        })?;
        let io = |e: io::Error| NetError::Connect(target.to_string(), e.to_string());
        stream
            .set_read_timeout(Some(self.options.timeout))
            .map_err(io)?;
        stream
            .set_write_timeout(Some(self.options.timeout))
            .map_err(io)?;
        let _ = stream.set_nodelay(true);
        if !target.tls {
            return Ok(Conn::Plain(stream));
        }
        let name = rustls::pki_types::ServerName::try_from(target.host.clone())
            .map_err(|e| NetError::Url(target.to_string(), e.to_string()))?;
        let session = rustls::ClientConnection::new(self.tls.clone(), name)
            .map_err(|e| NetError::Tls(target.to_string(), e.to_string()))?;
        let mut tls = rustls::StreamOwned::new(session, stream);
        // Finish the handshake here, so certificate errors are reported as such.
        while tls.conn.is_handshaking() {
            tls.conn
                .complete_io(&mut tls.sock)
                .map_err(|e| self.tls_error(target, e))?;
        }
        Ok(Conn::Tls(Box::new(tls)))
    }

    fn tls_error(&self, target: &Target, e: io::Error) -> NetError {
        if is_timeout(&e) {
            return NetError::Timeout(target.to_string());
        }
        match e
            .get_ref()
            .and_then(|inner| inner.downcast_ref::<rustls::Error>())
        {
            Some(tls) => NetError::Tls(target.to_string(), tls.to_string()),
            None => NetError::Tls(target.to_string(), e.to_string()),
        }
    }

    fn io_error(&self, target: &Target, e: io::Error) -> NetError {
        if is_timeout(&e) {
            NetError::Timeout(target.to_string())
        } else {
            NetError::Io(target.to_string(), e.to_string())
        }
    }

    fn read_response(&self, target: &Target, conn: &mut Conn) -> Result<Response, NetError> {
        let mut buf = Vec::with_capacity(4096);
        let mut chunk = [0u8; 4096];
        let (status, headers, body_start) = loop {
            let n = read_some(conn, &mut chunk).map_err(|e| self.io_error(target, e))?;
            if n == 0 {
                return Err(NetError::Protocol(
                    target.to_string(),
                    "the connection closed before an answer".into(),
                ));
            }
            buf.extend_from_slice(&chunk[..n]);
            let mut slots = [httparse::EMPTY_HEADER; 64];
            let mut parsed = httparse::Response::new(&mut slots);
            match parsed.parse(&buf) {
                Ok(httparse::Status::Complete(len)) => {
                    let status = parsed.code.unwrap_or(0);
                    let headers: Vec<(String, String)> = parsed
                        .headers
                        .iter()
                        .map(|h| {
                            (
                                h.name.to_owned(),
                                String::from_utf8_lossy(h.value).trim().to_owned(),
                            )
                        })
                        .collect();
                    break (status, headers, len);
                }
                Ok(httparse::Status::Partial) if buf.len() < MAX_HEAD => continue,
                Ok(httparse::Status::Partial) => {
                    return Err(NetError::Protocol(
                        target.to_string(),
                        "the answer's header is too large".into(),
                    ))
                }
                Err(e) => {
                    return Err(NetError::Protocol(
                        target.to_string(),
                        format!("not an HTTP answer: {e}"),
                    ))
                }
            }
        };
        let mut response = Response {
            status,
            headers,
            body: Vec::new(),
        };
        let rest = buf.split_off(body_start);
        let chunked = response
            .header("transfer-encoding")
            .is_some_and(|v| v.to_ascii_lowercase().contains("chunked"));
        let length = response
            .header("content-length")
            .and_then(|v| v.parse::<usize>().ok());
        let mut reader = Prefixed {
            prefix: rest,
            pos: 0,
            inner: conn,
        };
        let max = self.options.max_body;
        let too_large = || NetError::TooLarge(target.to_string(), max);
        let io = |e: io::Error| self.io_error(target, e);
        if response.status == 204 || response.status == 304 || (100..200).contains(&response.status)
        {
            return Ok(response);
        }
        if chunked {
            response.body = read_chunked(&mut reader, max).map_err(|e| match e {
                ChunkError::TooLarge => too_large(),
                ChunkError::Bad(why) => NetError::Protocol(target.to_string(), why),
                ChunkError::Io(e) => io(e),
            })?;
        } else if let Some(len) = length {
            if len > max {
                return Err(too_large());
            }
            let mut body = vec![0u8; len];
            reader.read_exact(&mut body).map_err(io)?;
            response.body = body;
        } else {
            let mut body = Vec::new();
            loop {
                let n = read_some(&mut reader, &mut chunk).map_err(io)?;
                if n == 0 {
                    break;
                }
                if body.len() + n > max {
                    return Err(too_large());
                }
                body.extend_from_slice(&chunk[..n]);
            }
            response.body = body;
        }
        Ok(response)
    }
}

fn is_timeout(e: &io::Error) -> bool {
    matches!(
        e.kind(),
        io::ErrorKind::TimedOut | io::ErrorKind::WouldBlock
    )
}

/// A read where a TLS peer closing without `close_notify` counts as the end.
fn read_some(r: &mut impl Read, buf: &mut [u8]) -> io::Result<usize> {
    match r.read(buf) {
        Err(e) if e.kind() == io::ErrorKind::UnexpectedEof => Ok(0),
        other => other,
    }
}

enum Conn {
    Plain(TcpStream),
    Tls(Box<rustls::StreamOwned<rustls::ClientConnection, TcpStream>>),
}

impl Read for Conn {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        match self {
            Conn::Plain(s) => s.read(buf),
            Conn::Tls(s) => s.read(buf),
        }
    }
}

impl Write for Conn {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        match self {
            Conn::Plain(s) => s.write(buf),
            Conn::Tls(s) => s.write(buf),
        }
    }
    fn flush(&mut self) -> io::Result<()> {
        match self {
            Conn::Plain(s) => s.flush(),
            Conn::Tls(s) => s.flush(),
        }
    }
}

/// Bytes already read past the header, then the connection.
struct Prefixed<'a> {
    prefix: Vec<u8>,
    pos: usize,
    inner: &'a mut Conn,
}

impl Read for Prefixed<'_> {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        if self.pos < self.prefix.len() {
            let n = (self.prefix.len() - self.pos).min(buf.len());
            buf[..n].copy_from_slice(&self.prefix[self.pos..self.pos + n]);
            self.pos += n;
            return Ok(n);
        }
        read_some(self.inner, buf)
    }
}

enum ChunkError {
    TooLarge,
    Bad(String),
    Io(io::Error),
}

fn read_line(r: &mut impl Read) -> Result<String, ChunkError> {
    let mut line = Vec::new();
    let mut byte = [0u8; 1];
    loop {
        let n = r.read(&mut byte).map_err(ChunkError::Io)?;
        if n == 0 {
            return Err(ChunkError::Bad("the chunked answer ended early".into()));
        }
        if byte[0] == b'\n' {
            break;
        }
        line.push(byte[0]);
        if line.len() > 1024 {
            return Err(ChunkError::Bad("a chunk header is too long".into()));
        }
    }
    if line.last() == Some(&b'\r') {
        line.pop();
    }
    String::from_utf8(line).map_err(|_| ChunkError::Bad("a chunk header is not text".into()))
}

fn read_chunked(r: &mut impl Read, max: usize) -> Result<Vec<u8>, ChunkError> {
    let mut body = Vec::new();
    loop {
        let line = read_line(r)?;
        let size_text = line.split(';').next().unwrap_or("").trim();
        let size = usize::from_str_radix(size_text, 16)
            .map_err(|_| ChunkError::Bad(format!("bad chunk size `{size_text}`")))?;
        if size == 0 {
            // Trailers until an empty line.
            while !read_line(r)?.is_empty() {}
            return Ok(body);
        }
        if body.len() + size > max {
            return Err(ChunkError::TooLarge);
        }
        let start = body.len();
        body.resize(start + size, 0);
        r.read_exact(&mut body[start..]).map_err(ChunkError::Io)?;
        if !read_line(r)?.is_empty() {
            return Err(ChunkError::Bad("a chunk is longer than its size".into()));
        }
    }
}

/// `X-Scribe-Signature` value for a webhook body sent at `ts` (Unix seconds):
/// `t=<ts>,v1=<hex HMAC-SHA256 of "<ts>.<body>" with the secret>`. Receivers recompute it and
/// reject old timestamps to stop replays.
pub fn signature(secret: &[u8], ts: u64, body: &[u8]) -> String {
    let key = ring::hmac::Key::new(ring::hmac::HMAC_SHA256, secret);
    let mut ctx = ring::hmac::Context::with_key(&key);
    ctx.update(ts.to_string().as_bytes());
    ctx.update(b".");
    ctx.update(body);
    let mac = ctx.sign();
    format!("t={ts},v1={}", hex(mac.as_ref()))
}

pub(crate) fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}
