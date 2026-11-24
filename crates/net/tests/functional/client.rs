use std::time::Duration;

use scribe_net::{Client, NetError, Options};

use crate::server::{answer, start, Answer};

fn client() -> Client {
    Client::new(Options {
        timeout: Duration::from_secs(5),
        max_body: 64,
        ..Options::default()
    })
    .unwrap()
}

#[test]
fn post_sends_the_body_headers_and_host() {
    let server = start(vec![answer("201 Created", &["X-Id: 7"], "ok")]);
    let r = client()
        .post(
            &server.url("/hook?k=v"),
            &[
                ("Content-Type", "application/json"),
                ("X-Scribe-Signature", "t=1,v1=ab"),
            ],
            br#"{"a":1}"#,
        )
        .unwrap();
    assert_eq!(r.status, 201);
    assert!(r.is_success());
    assert_eq!(r.header("x-id"), Some("7"));
    assert_eq!(r.body, b"ok");
    let got = &server.requests()[0];
    assert!(
        got.head.starts_with("POST /hook?k=v HTTP/1.1\r\n"),
        "{}",
        got.head
    );
    assert_eq!(
        got.header("host").unwrap(),
        format!("127.0.0.1:{}", server.port)
    );
    assert_eq!(got.header("content-length").as_deref(), Some("7"));
    assert_eq!(
        got.header("x-scribe-signature").as_deref(),
        Some("t=1,v1=ab")
    );
    assert_eq!(got.header("connection").as_deref(), Some("close"));
    assert!(got.header("user-agent").unwrap().starts_with("scribe/"));
    assert_eq!(got.body, br#"{"a":1}"#);
}

#[test]
fn header_values_with_line_breaks_are_refused() {
    let server = start(vec![]);
    let err = client()
        .post(&server.url("/"), &[("X-A", "1\r\nX-B: 2")], b"")
        .unwrap_err();
    assert!(matches!(err, NetError::Protocol(..)), "{err}");
}

#[test]
fn same_origin_307_is_followed_with_the_body() {
    let server = start(vec![
        answer("307 Temporary Redirect", &["Location: /moved"], ""),
        answer("200 OK", &[], "done"),
    ]);
    let r = client()
        .post(&server.url("/hook"), &[], b"payload")
        .unwrap();
    assert_eq!(r.body, b"done");
    let got = server.requests();
    assert!(got[1].head.starts_with("POST /moved "), "{}", got[1].head);
    assert_eq!(got[1].body, b"payload");
}

#[test]
fn redirects_to_another_host_or_into_a_get_are_not_followed() {
    let server = start(vec![answer(
        "308 Permanent Redirect",
        &["Location: http://localhost:1/elsewhere"],
        "",
    )]);
    let err = client().post(&server.url("/"), &[], b"x").unwrap_err();
    assert!(
        err.to_string().contains("redirect to another host"),
        "{err}"
    );

    let server = start(vec![answer("303 See Other", &["Location: /other"], "")]);
    let err = client().post(&server.url("/"), &[], b"x").unwrap_err();
    assert!(
        err.to_string().contains("would turn the POST into a GET"),
        "{err}"
    );
    assert_eq!(server.requests().len(), 1);

    let server = start(vec![
        answer("302 Found", &["Location: /a"], ""),
        answer("302 Found", &["Location: /b"], ""),
        answer("302 Found", &["Location: /c"], ""),
        answer("302 Found", &["Location: /d"], ""),
    ]);
    let err = client().get(&server.url("/"), &[]).unwrap_err();
    assert!(err.to_string().contains("more than 3 redirects"), "{err}");
}

#[test]
fn bodies_are_read_by_length_chunks_or_until_close_and_capped() {
    let chunked = start(vec![Answer::Raw(
        b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n4\r\nabcd\r\n3;x=y\r\nefg\r\n0\r\nX-Trailer: 1\r\n\r\n"
            .to_vec(),
    )]);
    assert_eq!(
        client().get(&chunked.url("/"), &[]).unwrap().body,
        b"abcdefg"
    );

    let until_close = start(vec![Answer::Raw(
        b"HTTP/1.0 200 OK\r\n\r\nall of it".to_vec(),
    )]);
    assert_eq!(
        client().get(&until_close.url("/"), &[]).unwrap().body,
        b"all of it"
    );

    let big = "x".repeat(65);
    for server in [
        start(vec![answer("200 OK", &[], &big)]),
        start(vec![Answer::Raw(
            format!(
                "HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n41\r\n{big}\r\n0\r\n\r\n"
            )
            .into_bytes(),
        )]),
        start(vec![Answer::Raw(
            format!("HTTP/1.0 200 OK\r\n\r\n{big}").into_bytes(),
        )]),
    ] {
        let err = client().get(&server.url("/"), &[]).unwrap_err();
        assert!(matches!(err, NetError::TooLarge(_, 64)), "{err}");
    }
}

#[test]
fn silence_times_out_and_refusal_is_transient() {
    let server = start(vec![Answer::Silent]);
    let quick = Client::new(Options {
        timeout: Duration::from_millis(200),
        ..Options::default()
    })
    .unwrap();
    let err = quick.post(&server.url("/"), &[], b"x").unwrap_err();
    assert!(matches!(err, NetError::Timeout(_)), "{err}");
    assert!(err.is_transient());

    // A port nobody listens on: bind, note the port, close.
    let port = std::net::TcpListener::bind("127.0.0.1:0")
        .unwrap()
        .local_addr()
        .unwrap()
        .port();
    let err = quick
        .post(&format!("http://127.0.0.1:{port}/"), &[], b"x")
        .unwrap_err();
    // Refused at once on Unix; Windows retries a refused connect for about 2 s, so a short timeout
    // can end it first. Either way it is worth trying again.
    assert!(
        matches!(err, NetError::Connect(..) | NetError::Timeout(_)),
        "{err}"
    );
    assert!(err.is_transient());

    let err = quick
        .post("http://hooks.example.com/", &[], b"x")
        .unwrap_err();
    assert!(!err.is_transient(), "a config mistake is not retried");
}

#[test]
fn garbage_answers_are_protocol_errors() {
    let server = start(vec![Answer::Raw(b"SSH-2.0-OpenSSH\r\n\r\n".to_vec())]);
    let err = client().get(&server.url("/"), &[]).unwrap_err();
    assert!(matches!(err, NetError::Protocol(..)), "{err}");
    let server = start(vec![Answer::Raw(Vec::new())]);
    let err = client().get(&server.url("/"), &[]).unwrap_err();
    assert!(err.to_string().contains("closed before an answer"), "{err}");
}
