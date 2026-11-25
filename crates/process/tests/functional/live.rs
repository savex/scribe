//! This process's own sockets, found in the real socket table of the system the tests run on
//! (no privileges needed for one's own process).

use std::net::{SocketAddr, TcpListener, TcpStream, UdpSocket};
use std::sync::Arc;
use std::time::Duration;

use scribe_core::SystemClock;
use scribe_process::{os_table, Resolver, Transport};

fn resolver() -> Resolver {
    let table = os_table().expect("a socket table on this system");
    Resolver::new(table, Arc::new(SystemClock))
}

fn me() -> String {
    std::env::current_exe()
        .unwrap()
        .file_name()
        .unwrap()
        .to_string_lossy()
        .into_owned()
}

#[test]
fn an_own_tcp_connection_is_found_with_this_process() {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let client = TcpStream::connect(listener.local_addr().unwrap()).unwrap();
    let (_server, _) = listener.accept().unwrap();
    let local: SocketAddr = client.local_addr().unwrap();
    let remote: SocketAddr = client.peer_addr().unwrap();

    let owner = resolver()
        .lookup(Transport::Tcp, local, remote)
        .expect("the client socket is in the table");
    assert_eq!(owner.pid, std::process::id());
    let path = owner.path.expect("our own path is readable");
    assert!(path.contains(&me()), "{path} is not {}", me());
}

#[test]
fn an_own_udp_socket_is_found_by_its_port() {
    let socket = UdpSocket::bind("127.0.0.1:0").unwrap();
    let peer = UdpSocket::bind("127.0.0.1:0").unwrap();
    socket.send_to(b"x", peer.local_addr().unwrap()).unwrap();
    let owner = resolver()
        .lookup(
            Transport::Udp,
            socket.local_addr().unwrap(),
            peer.local_addr().unwrap(),
        )
        .expect("the UDP socket is in the table");
    assert_eq!(owner.pid, std::process::id());
}

#[test]
fn a_socket_that_is_not_open_has_no_owner() {
    let port = TcpListener::bind("127.0.0.1:0")
        .unwrap()
        .local_addr()
        .unwrap()
        .port();
    let local: SocketAddr = format!("127.0.0.1:{port}").parse().unwrap();
    assert!(resolver()
        .lookup(Transport::Tcp, local, "203.0.113.9:443".parse().unwrap())
        .is_none());
}

#[test]
fn many_own_sockets_scan_within_the_budget() {
    // Load check of the real scan: 400 open TCP connections (800 sockets) in this process on
    // top of whatever the system runs. The scan must find them all and stay well within a
    // second; the resolver itself spaces out reads that go over its 50 ms budget.
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let target = listener.local_addr().unwrap();
    let mut pairs = Vec::new();
    for _ in 0..400 {
        let client = TcpStream::connect(target).unwrap();
        let (server, _) = listener.accept().unwrap();
        pairs.push((client, server));
    }
    let mut r = resolver();
    let started = std::time::Instant::now();
    for (client, _) in &pairs {
        let owner = r
            .lookup(
                Transport::Tcp,
                client.local_addr().unwrap(),
                client.peer_addr().unwrap(),
            )
            .expect("every connection is in the table");
        assert_eq!(owner.pid, std::process::id());
    }
    let elapsed = started.elapsed();
    let scans = r.scan_stats();
    assert_eq!(scans.scans, 1, "one read answers all 400 lookups");
    eprintln!(
        "socket table read in {:?} (400 lookups {elapsed:?})",
        scans.last
    );
    assert!(scans.last < Duration::from_secs(1), "{:?}", scans.last);
}
