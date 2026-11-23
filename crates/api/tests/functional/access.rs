//! Caller identity and the access policy.

use scribe_api::access::{Access, AccessPolicy, Caller, ADMIN_GROUP};
use scribe_api::pb::{EditBaselineRequest, SetModeRequest, StatusRequest};
use scribe_api::unix::{current_uid, identify};

use crate::mock::Running;

fn caller(privileged: bool, groups: &[&str]) -> Caller {
    Caller {
        user: "alice".into(),
        uid: Some(if privileged { 0 } else { 1000 }),
        pid: Some(4242),
        privileged,
        groups: groups.iter().map(|g| (*g).to_owned()).collect(),
    }
}

#[test]
fn read_calls_are_open_and_control_calls_need_root_or_the_admin_group() {
    let policy = AccessPolicy::default();
    assert_eq!(policy.admin_group, ADMIN_GROUP);
    let plain = caller(false, &["staff", "scribe"]);
    let admin = caller(false, &["staff", "scribe-admin"]);
    let root = caller(true, &[]);
    for c in [&plain, &admin, &root] {
        assert!(policy.allows(c, Access::Read));
    }
    assert!(!policy.allows(&plain, Access::Control));
    assert!(policy.allows(&admin, Access::Control));
    assert!(policy.allows(&root, Access::Control));
}

#[test]
fn a_caller_is_described_with_its_ids() {
    assert_eq!(caller(false, &[]).describe(), "alice (uid 1000, pid 4242)");
    let bare = Caller {
        uid: None,
        pid: None,
        ..caller(false, &[])
    };
    assert_eq!(bare.describe(), "alice");
}

#[test]
fn identify_finds_the_user_and_the_primary_group() {
    // SAFETY: getgid has no preconditions.
    let gid = unsafe { libc::getgid() };
    let me = identify(current_uid(), gid, Some(7));
    assert_eq!(me.uid, Some(current_uid()));
    assert_eq!(me.pid, Some(7));
    assert_eq!(me.privileged, current_uid() == 0);
    assert!(!me.user.is_empty());
    assert!(
        !me.groups.is_empty(),
        "the primary group has a name: {me:?}"
    );
}

#[tokio::test]
async fn the_server_attaches_the_connecting_user() {
    let server = Running::start(AccessPolicy::default()).await;
    let status = server
        .client()
        .await
        .get_status(StatusRequest {})
        .await
        .unwrap()
        .into_inner();
    // SAFETY: getgid has no preconditions.
    let me = identify(current_uid(), unsafe { libc::getgid() }, None);
    assert_eq!(status.api_version, scribe_api::API_VERSION);
    assert_eq!(status.profile, me.user);
    assert!(
        status
            .hibernated_by
            .contains(&format!("uid {}", current_uid())),
        "{}",
        status.hibernated_by
    );
    server.stop().await;
}

#[tokio::test]
async fn control_calls_are_refused_outside_the_admin_group() {
    let server = Running::start(AccessPolicy {
        admin_group: "scribe-test-no-such-group".into(),
    })
    .await;
    let mut client = server.client().await;
    let result = client
        .set_mode(SetModeRequest {
            mode: "alert".into(),
        })
        .await;
    if current_uid() == 0 {
        assert_eq!(
            result.unwrap().into_inner().mode,
            "alert",
            "root may always"
        );
    } else {
        let err = result.unwrap_err();
        assert_eq!(err.code(), tonic::Code::PermissionDenied);
        assert!(err.message().contains("scribe-test-no-such-group"), "{err}");
    }
    // Read calls still work on the same connection.
    client.get_status(StatusRequest {}).await.unwrap();
    server.stop().await;
}

#[tokio::test]
async fn control_calls_are_allowed_to_the_admin_group() {
    // SAFETY: getgid has no preconditions.
    let me = identify(current_uid(), unsafe { libc::getgid() }, None);
    let server = Running::start(AccessPolicy {
        admin_group: me.groups[0].clone(),
    })
    .await;
    let reply = server
        .client()
        .await
        .edit_baseline(EditBaselineRequest {
            add: vec!["api.example.com".into()],
            remove: vec![],
        })
        .await
        .unwrap()
        .into_inner();
    assert_eq!(reply.added, ["api.example.com"]);
    server.stop().await;
}

#[tokio::test]
async fn bad_mode_names_are_invalid_arguments() {
    let server = Running::start(AccessPolicy {
        admin_group: identify(current_uid(), unsafe { libc::getgid() }, None).groups[0].clone(),
    })
    .await;
    let err = server
        .client()
        .await
        .set_mode(SetModeRequest {
            mode: "paranoid".into(),
        })
        .await
        .unwrap_err();
    assert_eq!(err.code(), tonic::Code::InvalidArgument);
    server.stop().await;
}
