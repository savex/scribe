//! The module's API service and its `scribe url` output.

use std::sync::{Arc, Mutex};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use scribe_api::access::Caller;
use scribe_module_api::{BoxFuture, ModuleRecord, RecordReader};
use scribe_module_url::api::pb::url_server::Url;
use scribe_module_url::api::pb::{ListRequest, Request as UrlRequest, RequestList};
use scribe_module_url::api::{render, UrlApi, DEFAULT_LIMIT, MAX_LIMIT};
use serde_json::json;

/// kind, host, since, limit
type Asked = (String, Option<String>, Option<SystemTime>, usize);

/// Records what was asked and answers with fixed records.
#[derive(Default)]
struct Fake {
    asked: Mutex<Vec<Asked>>,
}

impl RecordReader for Fake {
    fn records<'a>(
        &'a self,
        kind: &'a str,
        host: Option<&'a str>,
        since: Option<SystemTime>,
        limit: usize,
    ) -> BoxFuture<'a, Result<Vec<ModuleRecord>, String>> {
        self.asked
            .lock()
            .unwrap()
            .push((kind.to_owned(), host.map(str::to_owned), since, limit));
        Box::pin(async move {
            Ok(vec![ModuleRecord {
                ts: UNIX_EPOCH + Duration::from_secs(1_700_000_000),
                module: "url".into(),
                kind: "url.request".into(),
                schema: 1,
                host: Some("api.example.com".into()),
                payload: json!({ "method": "GET", "url": "http://api.example.com/v1/items?id=<redacted>" }),
            }])
        })
    }
}

fn request(r: ListRequest) -> tonic::Request<ListRequest> {
    let mut request = tonic::Request::new(r);
    request.extensions_mut().insert(Caller {
        user: "alice".into(),
        uid: Some(1000),
        pid: Some(1),
        privileged: false,
        groups: vec![],
    });
    request
}

async fn list(reader: &Arc<Fake>, r: ListRequest) -> Result<RequestList, tonic::Status> {
    UrlApi::new(reader.clone())
        .list(request(r))
        .await
        .map(tonic::Response::into_inner)
}

#[tokio::test]
async fn list_asks_for_requests_with_defaults_and_caps() {
    let reader = Arc::new(Fake::default());
    let got = list(&reader, ListRequest::default()).await.unwrap();
    assert_eq!(got.items.len(), 1);
    assert_eq!(got.items[0].method, "GET");
    assert_eq!(got.items[0].host, "api.example.com");
    assert_eq!(got.items[0].ts_ms, 1_700_000_000_000);
    list(
        &reader,
        ListRequest {
            host: " API.Example.com. ".into(),
            limit: 1_000_000,
            since_ms: Some(5_000),
        },
    )
    .await
    .unwrap();
    let asked = reader.asked.lock().unwrap().clone();
    assert_eq!(asked[0], ("url.request".into(), None, None, DEFAULT_LIMIT));
    assert_eq!(
        asked[1],
        (
            "url.request".into(),
            Some("api.example.com".into()),
            Some(UNIX_EPOCH + Duration::from_secs(5)),
            MAX_LIMIT
        )
    );
}

#[tokio::test]
async fn a_call_without_an_identity_is_refused() {
    let reader = Arc::new(Fake::default());
    let err = UrlApi::new(reader)
        .list(tonic::Request::new(ListRequest::default()))
        .await
        .unwrap_err();
    assert_eq!(err.code(), tonic::Code::Unauthenticated);
}

#[test]
fn requests_print_one_per_line() {
    let list = RequestList {
        items: vec![UrlRequest {
            ts_ms: 1_700_000_000_000,
            host: "api.example.com".into(),
            method: "GET".into(),
            url: "http://api.example.com/v1/items?id=<redacted>".into(),
        }],
    };
    assert_eq!(
        render(&list),
        "2023-11-14T22:13:20Z  GET     http://api.example.com/v1/items?id=<redacted>\n"
    );
    assert_eq!(render(&RequestList::default()), "no requests stored\n");
}
