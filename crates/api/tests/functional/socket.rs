//! Socket setup, ownership checks and limits.

use std::os::unix::fs::PermissionsExt;
use std::time::{Duration, Instant};

use scribe_api::access::AccessPolicy;
use scribe_api::limits::MAX_MESSAGE;
use scribe_api::pb::{EditBaselineRequest, StatusRequest};
use scribe_api::unix::{self, check_server, current_uid, ServerCheck};
use scribe_api::TransportError;

use crate::mock::{connect, Running};

#[tokio::test]
async fn a_live_socket_is_refused_and_a_stale_one_replaced() {
    let server = Running::start(AccessPolicy::default()).await;
    match unix::bind(&server.socket) {
        Err(TransportError::Refused(msg)) => assert!(msg.contains("in use"), "{msg}"),
        other => panic!("expected a refusal, got {other:?}"),
    }
    let dir = tempfile::tempdir().unwrap();
    let stale = dir.path().join("api.sock");
    drop(unix::bind(&stale).unwrap());
    assert!(stale.exists(), "a dropped listener leaves its socket file");
    let _again = unix::bind(&stale).unwrap();
    server.stop().await;
}

#[tokio::test]
async fn bind_refuses_a_file_that_is_not_a_socket() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("api.sock");
    std::fs::write(&path, "not a socket").unwrap();
    assert!(matches!(unix::bind(&path), Err(TransportError::Refused(_))));
    assert_eq!(std::fs::read_to_string(&path).unwrap(), "not a socket");
}

#[tokio::test]
async fn bind_creates_a_missing_directory_closed_to_others() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("run/scribe/api.sock");
    let _listener = unix::bind(&path).unwrap();
    let mode = std::fs::metadata(path.parent().unwrap())
        .unwrap()
        .permissions()
        .mode();
    assert_eq!(mode & 0o777, 0o750);
}

#[tokio::test]
async fn bind_leaves_the_socket_open_to_its_group() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("api.sock");
    let _listener = unix::bind(&path).unwrap();
    let mode = std::fs::metadata(&path).unwrap().permissions().mode();
    assert_eq!(mode & 0o777, 0o660);
}

#[test]
fn clients_refuse_anything_but_a_socket_of_root_or_their_own() {
    let dir = tempfile::tempdir().unwrap();
    let file = dir.path().join("api.sock");
    assert!(matches!(
        check_server(&file, ServerCheck::RootOrSelf),
        Err(TransportError::Io { .. })
    ));
    std::fs::write(&file, "").unwrap();
    match check_server(&file, ServerCheck::RootOrSelf) {
        Err(TransportError::Refused(msg)) => assert!(msg.contains("not a socket"), "{msg}"),
        other => panic!("expected a refusal, got {other:?}"),
    }
}

#[tokio::test]
async fn root_only_clients_refuse_a_user_socket() {
    let server = Running::start(AccessPolicy::default()).await;
    let result = check_server(&server.socket, ServerCheck::Root);
    if current_uid() == 0 {
        result.unwrap();
    } else {
        match result {
            Err(TransportError::Refused(msg)) => assert!(msg.contains("not root"), "{msg}"),
            other => panic!("expected a refusal, got {other:?}"),
        }
    }
    check_server(&server.socket, ServerCheck::RootOrSelf).unwrap();
    server.stop().await;
}

#[tokio::test]
async fn connecting_to_a_dead_socket_fails_quickly() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("api.sock");
    drop(unix::bind(&path).unwrap());
    let started = Instant::now();
    let err = unix::connect(&path, ServerCheck::RootOrSelf, Duration::from_secs(2))
        .await
        .unwrap_err();
    assert!(matches!(err, TransportError::Connect(_)), "{err:?}");
    assert!(started.elapsed() < Duration::from_secs(2));
}

#[tokio::test]
async fn oversized_messages_are_refused_and_the_server_keeps_serving() {
    let server = Running::start(AccessPolicy::default()).await;
    let mut client = server.client().await;
    let host = "a".repeat(1024);
    let request = EditBaselineRequest {
        add: vec![host; MAX_MESSAGE / 1024 + 16],
        remove: vec![],
    };
    let err = client.edit_baseline(request).await.unwrap_err();
    assert_eq!(err.code(), tonic::Code::OutOfRange, "{err}");
    connect(&server.socket)
        .await
        .get_status(StatusRequest {})
        .await
        .unwrap();
    server.stop().await;
}

#[tokio::test]
async fn many_clients_are_served_at_once() {
    let server = Running::start(AccessPolicy::default()).await;
    let mut calls = Vec::new();
    for _ in 0..12 {
        let socket = server.socket.clone();
        calls.push(tokio::spawn(async move {
            connect(&socket)
                .await
                .get_status(StatusRequest {})
                .await
                .unwrap()
                .into_inner()
                .api_version
        }));
    }
    for call in calls {
        assert_eq!(call.await.unwrap(), scribe_api::API_VERSION);
    }
    assert!(server.dir.path().exists());
    server.stop().await;
}
