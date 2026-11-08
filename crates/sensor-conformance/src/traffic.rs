//! Local traffic generator. Every case gets its own freshly bound server on 127.0.0.1,
//! so each case has a unique destination port that the suite can match on.
//!
//! TLS cases only send a ClientHello: a sensor needs nothing more, so no TLS library is required.

use std::io::{self, Read, Write};
use std::net::{Shutdown, SocketAddr, TcpListener, TcpStream, UdpSocket};
use std::thread::{self, JoinHandle};
use std::time::Duration;

use scribe_core::{Protocol, Security};
use scribe_test_support::packets::{http, tls};

#[derive(Debug, Clone)]
pub enum Case {
    TlsSni {
        host: &'static str,
    },
    PlainHttp {
        host: &'static str,
        path: &'static str,
    },
    PlainTcp {
        payload: &'static [u8],
    },
    Udp {
        payload: &'static [u8],
    },
}

impl Case {
    fn payload(&self) -> Vec<u8> {
        match self {
            Case::TlsSni { host } => tls::client_hello_sni(host),
            Case::PlainHttp { host, path } => http::get_request(host, path),
            Case::PlainTcp { payload } | Case::Udp { payload } => payload.to_vec(),
        }
    }
}

/// What a sensor must report for a case.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Expected {
    pub proto: Protocol,
    pub dst: SocketAddr,
    pub hostname: Option<String>,
    pub security: Security,
    pub url: Option<String>,
}

/// Bytes the local server received; join to wait for them.
pub struct Receipt(JoinHandle<io::Result<Vec<u8>>>);

impl Receipt {
    pub fn wait(self) -> io::Result<Vec<u8>> {
        self.0
            .join()
            .unwrap_or_else(|_| Err(io::Error::other("server thread panicked")))
    }
}

const SERVER_TIMEOUT: Duration = Duration::from_secs(5);

/// Start a server for `case`, send its traffic from this process, return what to expect.
pub fn send(case: &Case) -> io::Result<(Expected, Receipt)> {
    let payload = case.payload();
    match case {
        Case::Udp { .. } => send_udp(payload),
        _ => {
            let (dst, receipt) = send_tcp(payload)?;
            let (hostname, security, url) = match case {
                Case::TlsSni { host } => (Some(host.to_string()), Security::Tls, None),
                Case::PlainHttp { host, path } => (
                    Some(host.to_string()),
                    Security::Plaintext,
                    Some(format!("http://{host}{path}")),
                ),
                _ => (None, Security::Plaintext, None),
            };
            Ok((
                Expected {
                    proto: Protocol::Tcp,
                    dst,
                    hostname,
                    security,
                    url,
                },
                receipt,
            ))
        }
    }
}

fn send_tcp(payload: Vec<u8>) -> io::Result<(SocketAddr, Receipt)> {
    let listener = TcpListener::bind("127.0.0.1:0")?;
    let dst = listener.local_addr()?;
    let server = thread::spawn(move || {
        let (mut stream, _) = listener.accept()?;
        stream.set_read_timeout(Some(SERVER_TIMEOUT))?;
        let mut buf = Vec::new();
        stream.read_to_end(&mut buf)?;
        Ok(buf)
    });

    let mut client = TcpStream::connect(dst)?;
    client.write_all(&payload)?;
    client.shutdown(Shutdown::Write)?;
    Ok((dst, Receipt(server)))
}

fn send_udp(payload: Vec<u8>) -> io::Result<(Expected, Receipt)> {
    let server = UdpSocket::bind("127.0.0.1:0")?;
    server.set_read_timeout(Some(SERVER_TIMEOUT))?;
    let dst = server.local_addr()?;
    let handle = thread::spawn(move || {
        let mut buf = vec![0u8; 65_535];
        let (n, _) = server.recv_from(&mut buf)?;
        buf.truncate(n);
        Ok(buf)
    });

    let client = UdpSocket::bind("127.0.0.1:0")?;
    client.send_to(&payload, dst)?;
    let expected = Expected {
        proto: Protocol::Udp,
        dst,
        hostname: None,
        security: Security::Unknown,
        url: None,
    };
    Ok((expected, Receipt(handle)))
}
