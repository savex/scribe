//! HTTP request heads and the `Host` header.

use scribe_enrich::http::*;
use scribe_test_support::packets::http::get_request;

#[test]
fn reads_the_request_line_and_host() {
    let head = parse_request_head(&get_request("plain.example.com", "/download?id=42")).unwrap();
    assert_eq!(head.method, "GET");
    assert_eq!(head.target, "/download?id=42");
    assert_eq!(head.host_header.as_deref(), Some("plain.example.com"));
    assert_eq!(
        host_header(&get_request("Plain.Example.COM:8080", "/")).as_deref(),
        Some("plain.example.com")
    );
}

#[test]
fn host_comes_from_proxy_and_connect_targets_too() {
    let proxy = b"GET http://user:pw@proxy.example.com:8080/a HTTP/1.1\r\nAccept: */*\r\n\r\n";
    assert_eq!(host_header(proxy).as_deref(), Some("proxy.example.com"));
    let connect = b"CONNECT tunnel.example.net:443 HTTP/1.1\r\n\r\n";
    assert_eq!(host_header(connect).as_deref(), Some("tunnel.example.net"));
}

#[test]
fn ip_literals_and_bad_hosts_are_not_names() {
    assert_eq!(host_header(&get_request("192.0.2.10", "/")), None);
    assert_eq!(host_header(&get_request("[2001:db8::1]:8080", "/")), None);
    assert_eq!(host_header(&get_request("bad host.example.com", "/")), None);
    assert_eq!(
        split_host_port("[2001:DB8::1]:8080"),
        Some(("[2001:db8::1]".to_owned(), Some(8080)))
    );
}

#[test]
fn headers_are_case_insensitive_and_the_first_host_wins() {
    let req = b"GET / HTTP/1.0\r\nhOsT: a.example.com\r\nHost: b.example.com\r\n\r\n";
    assert_eq!(host_header(req).as_deref(), Some("a.example.com"));
}

#[test]
fn a_head_cut_short_keeps_complete_lines() {
    let full = get_request("cut.example.com", "/x");
    let host_line_end = full.windows(2).position(|w| w == b"\r\n").unwrap() + 2;
    let after_host = host_line_end + "Host: cut.example.com\r\n".len();
    assert_eq!(
        host_header(&full[..after_host]).as_deref(),
        Some("cut.example.com")
    );
    assert_eq!(
        host_header(&full[..after_host - 3]),
        None,
        "host line incomplete"
    );
    for n in 0..full.len() {
        let _ = parse_request_head(&full[..n]); // never panics
    }
}

#[test]
fn not_http() {
    for bad in [
        &b"\x16\x03\x01\x00\x05hello"[..],
        b"get / HTTP/1.1\r\n\r\n",
        b"GET / HTTP/2\r\n\r\n",
        b"GET  / HTTP/1.1\r\n\r\n",
        b"",
    ] {
        assert_eq!(parse_request_head(bad), None, "{bad:?}");
    }
}
