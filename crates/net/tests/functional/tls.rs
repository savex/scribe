//! HTTPS against a local server with a self-signed certificate: refused by the system verifier,
//! accepted only with the matching `pin_sha256`.

use std::io::Write;
use std::net::TcpListener;
use std::sync::Arc;
use std::thread;
use std::time::Duration;

use rustls::pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer};
use scribe_net::{Client, NetError, Options};

use crate::server::read_request;

struct TlsServer {
    port: u16,
    sha256: String,
}

/// Serves `connections` HTTPS connections on 127.0.0.1 with a fresh self-signed certificate for
/// `localhost` and `127.0.0.1` (the tests use the address: on Windows `localhost` tries `::1` first,
/// and a refused connection there costs about 2 s), answering `200 OK` with body `secure`.
fn start(connections: usize) -> TlsServer {
    let rcgen::CertifiedKey { cert, signing_key } =
        rcgen::generate_simple_self_signed(vec!["localhost".to_owned(), "127.0.0.1".to_owned()])
            .unwrap();
    let der: CertificateDer<'static> = cert.der().clone();
    let sha256: String = ring::digest::digest(&ring::digest::SHA256, der.as_ref())
        .as_ref()
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect();
    let key = PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(signing_key.serialize_der()));
    let config = Arc::new(
        rustls::ServerConfig::builder_with_provider(Arc::new(
            rustls::crypto::ring::default_provider(),
        ))
        .with_safe_default_protocol_versions()
        .unwrap()
        .with_no_client_auth()
        .with_single_cert(vec![der], key)
        .unwrap(),
    );
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let port = listener.local_addr().unwrap().port();
    thread::spawn(move || {
        for _ in 0..connections {
            let Ok((tcp, _)) = listener.accept() else {
                return;
            };
            // One thread per connection: a refused handshake never holds up the next client.
            let config = config.clone();
            thread::spawn(move || {
                let _ = tcp.set_read_timeout(Some(Duration::from_secs(5)));
                let conn = rustls::ServerConnection::new(config).unwrap();
                let mut tls = rustls::StreamOwned::new(conn, tcp);
                let _ = read_request(&mut tls);
                let _ = tls.write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 6\r\n\r\nsecure");
                tls.conn.send_close_notify();
                let _ = tls.flush();
            });
        }
    });
    TlsServer { port, sha256 }
}

fn client(pin: Option<String>) -> Client {
    Client::new(Options {
        timeout: Duration::from_secs(5),
        pin_sha256: pin,
        ..Options::default()
    })
    .unwrap()
}

#[test]
fn a_self_signed_certificate_fails_the_system_trust_check() {
    let server = start(1);
    let url = format!("https://127.0.0.1:{}/hook", server.port);
    let err = client(None).post(&url, &[], b"x").unwrap_err();
    assert!(matches!(err, NetError::Tls(..)), "{err}");
    assert!(!err.is_transient());
}

#[test]
fn a_self_signed_certificate_is_accepted_only_with_its_pin() {
    let server = start(2);
    let url = format!("https://127.0.0.1:{}/hook", server.port);

    let r = client(Some(server.sha256.clone()))
        .post(&url, &[], b"x")
        .unwrap();
    assert_eq!((r.status, r.body.as_slice()), (200, &b"secure"[..]));

    let err = client(Some("00".repeat(32)))
        .post(&url, &[], b"x")
        .unwrap_err();
    assert!(
        matches!(&err, NetError::Tls(_, why) if why.contains("does not match pin_sha256")),
        "{err}"
    );
}

#[test]
fn a_bad_pin_is_a_config_error() {
    let err = Client::new(Options {
        pin_sha256: Some("not-a-pin".into()),
        ..Options::default()
    })
    .unwrap_err();
    assert!(matches!(err, NetError::Pin(_)), "{err}");
}
