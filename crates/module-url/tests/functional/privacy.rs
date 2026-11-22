//! The URL privacy table of specs 12.2, example by example, and request parsing.

use scribe_module_url::parse::{parse_request, request_url};
use scribe_module_url::privacy::apply;
use scribe_module_url::Query;
use scribe_test_support::packets::http::get_request;

/// (seen URL, full, redact_values, strip, path_only) from specs 12.2.
const TABLE: &[(&str, &str, &str, &str, &str)] = &[
    (
        "http://plain.example.com/download?id=42",
        "http://plain.example.com/download?id=42",
        "http://plain.example.com/download?id=<redacted>",
        "http://plain.example.com/download",
        "http://plain.example.com/download",
    ),
    (
        "http://api.example.com/v1/users/1234/profile?token=eyJhbGciOiJIUzI1NiJ9.e30.Zm9v&lang=en",
        "http://api.example.com/v1/users/1234/profile?token=eyJhbGciOiJIUzI1NiJ9.e30.Zm9v&lang=en",
        "http://api.example.com/v1/users/1234/profile?token=<redacted>&lang=<redacted>",
        "http://api.example.com/v1/users/1234/profile",
        "http://api.example.com/v1/…",
    ),
    (
        "http://admin:s3cret@intranet.example.com/reports/2026/q3.pdf?print=1",
        "http://intranet.example.com/reports/2026/q3.pdf?print=1",
        "http://intranet.example.com/reports/2026/q3.pdf?print=<redacted>",
        "http://intranet.example.com/reports/2026/q3.pdf",
        "http://intranet.example.com/reports/…",
    ),
    (
        "http://cdn.example.net/assets/js/app.js",
        "http://cdn.example.net/assets/js/app.js",
        "http://cdn.example.net/assets/js/app.js",
        "http://cdn.example.net/assets/js/app.js",
        "http://cdn.example.net/assets/…",
    ),
    (
        "http://search.example.com/?q=my+medical+condition&page=2&safe",
        "http://search.example.com/?q=my+medical+condition&page=2&safe",
        "http://search.example.com/?q=<redacted>&page=<redacted>&safe",
        "http://search.example.com/",
        "http://search.example.com/",
    ),
    (
        "http://tracker.example.net/pixel.gif?uid=8f3a2c&uid=8f3a2c&ref=http%3A%2F%2Fshop.example.com%2Fcart",
        "http://tracker.example.net/pixel.gif?uid=8f3a2c&uid=8f3a2c&ref=http%3A%2F%2Fshop.example.com%2Fcart",
        "http://tracker.example.net/pixel.gif?uid=<redacted>&uid=<redacted>&ref=<redacted>",
        "http://tracker.example.net/pixel.gif",
        "http://tracker.example.net/pixel.gif",
    ),
];

/// A proxy-form request for `url`, so user info reaches the parser as in example 3.
fn request_for(url: &str) -> Vec<u8> {
    format!("GET {url} HTTP/1.1\r\nAccept: */*\r\n\r\n").into_bytes()
}

#[test]
fn every_example_of_the_spec_table() {
    for (seen, full, redact, strip, path_only) in TABLE {
        let req = parse_request(&request_for(seen)).unwrap_or_else(|| panic!("{seen}"));
        assert_eq!(apply(&req, Query::Full, None), *full, "full: {seen}");
        assert_eq!(
            apply(&req, Query::RedactValues, None),
            *redact,
            "redact: {seen}"
        );
        assert_eq!(apply(&req, Query::Strip, None), *strip, "strip: {seen}");
        assert_eq!(
            apply(&req, Query::PathOnly, None),
            *path_only,
            "path_only: {seen}"
        );
    }
}

#[test]
fn hash_uses_the_key_or_stores_no_query() {
    let req = parse_request(&request_for("http://plain.example.com/download?id=42")).unwrap();
    let h = |q: &str| format!("{:06x}", q.len());
    assert_eq!(
        apply(&req, Query::Hash, Some(&h)),
        "http://plain.example.com/download?<hash:000005>"
    );
    assert_eq!(
        apply(&req, Query::Hash, None),
        "http://plain.example.com/download"
    );
    let no_query = parse_request(&request_for("http://cdn.example.net/a.js")).unwrap();
    assert_eq!(
        apply(&no_query, Query::Hash, Some(&h)),
        "http://cdn.example.net/a.js"
    );
}

#[test]
fn origin_form_uses_the_host_header_and_keeps_odd_ports() {
    assert_eq!(
        request_url(&get_request("plain.example.com", "/download?id=42")).as_deref(),
        Some("http://plain.example.com/download?id=42")
    );
    assert_eq!(
        request_url(&get_request("plain.example.com:8080", "/x")).as_deref(),
        Some("http://plain.example.com:8080/x")
    );
    assert_eq!(
        request_url(&get_request("plain.example.com:80", "/x")).as_deref(),
        Some("http://plain.example.com/x")
    );
    assert_eq!(
        request_url(&get_request("192.0.2.20", "/x")).as_deref(),
        Some("http://192.0.2.20/x"),
        "IP hosts are fine in URLs"
    );
}

#[test]
fn requests_without_a_url() {
    for head in [
        &b"CONNECT tunnel.example.net:443 HTTP/1.1\r\n\r\n"[..],
        b"OPTIONS * HTTP/1.1\r\nHost: a.example.com\r\n\r\n",
        b"GET /no-host HTTP/1.1\r\n\r\n",
        b"\x16\x03\x01\x00\x05hello",
    ] {
        assert_eq!(request_url(head), None, "{head:?}");
    }
    let post = parse_request(b"POST /api HTTP/1.1\r\nHost: api.example.com\r\n\r\n").unwrap();
    assert_eq!(post.method, "POST");
}
