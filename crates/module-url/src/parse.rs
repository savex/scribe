//! Plaintext HTTP/1.x requests → URL parts. Uses `scribe_enrich::http` for the request head.

use scribe_enrich::http::{parse_request_head, split_host_port};

/// A request's URL, split for the privacy rules (specs 12.2). User info is never kept.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Request {
    pub method: String,
    /// `http://host` or `http://host:port` (port only when it isn't 80).
    pub origin: String,
    /// Starts with `/`.
    pub path: String,
    /// Text after `?`, if a `?` was present.
    pub query: Option<String>,
}

impl Request {
    /// The URL as seen, minus user info.
    pub fn url(&self) -> String {
        match &self.query {
            Some(q) => format!("{}{}?{}", self.origin, self.path, q),
            None => format!("{}{}", self.origin, self.path),
        }
    }
}

/// Parse the request at the start of `head`. `None` for anything that isn't an HTTP/1.x request
/// with a usable host (origin-form needs a `Host` header; `CONNECT` and `*` have no URL).
pub fn parse_request(head: &[u8]) -> Option<Request> {
    let req = parse_request_head(head)?;
    let (authority, path_query) = if let Some(rest) = req.target.strip_prefix("http://") {
        let (auth, pq) = match rest.find('/') {
            Some(i) => (&rest[..i], &rest[i..]),
            None => (rest, "/"),
        };
        (auth.rsplit('@').next()?.to_owned(), pq.to_owned())
    } else if req.target.starts_with('/') {
        (req.host_header.clone()?, req.target.clone())
    } else {
        return None;
    };
    let (host, port) = split_host_port(&authority)?;
    let origin = match port {
        Some(p) if p != 80 => format!("http://{host}:{p}"),
        _ => format!("http://{host}"),
    };
    let path_query = path_query.split('#').next().unwrap_or("");
    let (path, query) = match path_query.split_once('?') {
        Some((p, q)) => (p, Some(q.to_owned())),
        None => (path_query, None),
    };
    Some(Request {
        method: req.method,
        origin,
        path: if path.is_empty() {
            "/".into()
        } else {
            path.into()
        },
        query,
    })
}

/// The absolute URL (`http://host/path?query`) of the HTTP/1.x request at the start of `head`,
/// without user info. Fuzzed by `fuzz/fuzz_targets/http_request.rs`.
pub fn request_url(head: &[u8]) -> Option<String> {
    parse_request(head).map(|r| r.url())
}
