//! What works the same over every transport (a Unix socket here, a named pipe on Windows).

use std::time::Duration;

use scribe_api::access::AccessPolicy;
use scribe_api::pb::{SetModeRequest, StatusRequest};
use scribe_api::{transport, ServerCheck, TransportError};

use crate::mock::{connect, endpoint, Running};

#[tokio::test]
async fn a_call_carries_the_callers_identity() {
    let server = Running::start(AccessPolicy::default()).await;
    let status = server
        .client()
        .await
        .get_status(StatusRequest {})
        .await
        .unwrap()
        .into_inner();
    assert_eq!(status.api_version, scribe_api::API_VERSION);
    assert!(!status.profile.is_empty(), "the user name");
    assert!(
        status
            .hibernated_by
            .contains(&format!("pid {}", std::process::id())),
        "{}",
        status.hibernated_by
    );
    server.stop().await;
}

#[tokio::test]
async fn a_second_server_on_the_same_name_is_refused() {
    let server = Running::start(AccessPolicy::default()).await;
    match transport::bind(&server.socket, &[]) {
        Err(TransportError::Refused(msg)) => assert!(msg.contains("in use"), "{msg}"),
        other => panic!("expected a refusal, got {:?}", other.err()),
    }
    // The first one keeps serving.
    connect(&server.socket)
        .await
        .get_status(StatusRequest {})
        .await
        .unwrap();
    server.stop().await;
}

#[tokio::test]
async fn nothing_listening_fails_quickly() {
    let dir = tempfile::tempdir().unwrap();
    let name = endpoint(dir.path());
    let started = std::time::Instant::now();
    let err = transport::connect(&name, ServerCheck::RootOrSelf, Duration::from_secs(2))
        .await
        .unwrap_err();
    assert!(
        matches!(err, TransportError::Io { .. } | TransportError::Connect(_)),
        "{err:?}"
    );
    assert!(started.elapsed() < Duration::from_secs(2));
}

#[tokio::test]
async fn control_calls_follow_the_policy() {
    let server = Running::start(AccessPolicy {
        admin_group: "scribe-test-no-such-group".into(),
    })
    .await;
    let mut client = server.client().await;
    let status = client
        .get_status(StatusRequest {})
        .await
        .unwrap()
        .into_inner();
    let result = client
        .set_mode(SetModeRequest {
            mode: "alert".into(),
        })
        .await;
    // Root / an elevated Administrator may always; anyone else is refused.
    match result {
        Ok(reply) => assert_eq!(reply.into_inner().mode, "alert", "{}", status.profile),
        Err(e) => assert_eq!(e.code(), tonic::Code::PermissionDenied),
    }
    server.stop().await;
}

#[cfg(windows)]
#[tokio::test]
async fn a_pipe_server_must_be_system_or_the_caller() {
    let server = Running::start(AccessPolicy::default()).await;
    // This test's own server runs as the test user: accepted with RootOrSelf, refused with Root
    // (CI does not run tests as SYSTEM).
    let refused = transport::connect(&server.socket, ServerCheck::Root, Duration::from_secs(5))
        .await
        .unwrap_err();
    match refused {
        TransportError::Refused(msg) => assert!(msg.contains("not SYSTEM"), "{msg}"),
        other => panic!("expected a refusal, got {other:?}"),
    }
    server.stop().await;
}
