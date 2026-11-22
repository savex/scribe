//! How much of a URL is stored: `[modules.url] query` (specs 12.2).

use crate::parse::Request;
use crate::Query;

/// The stored form of `req`'s URL. `hash` needs a key (see [`crate::UrlModule`]); without one it
/// falls back to `strip`, which stores no query at all.
pub fn apply(req: &Request, query: Query, hash: Option<&dyn Fn(&str) -> String>) -> String {
    let base = format!("{}{}", req.origin, req.path);
    match (query, &req.query) {
        (Query::Full, _) => req.url(),
        (_, None) if query != Query::PathOnly => base,
        (Query::RedactValues, Some(q)) => format!("{base}?{}", redact_values(q)),
        (Query::Strip, Some(_)) => base,
        (Query::PathOnly, _) => format!("{}{}", req.origin, first_segment(&req.path)),
        (Query::Hash, Some(q)) => match hash {
            Some(h) => format!("{base}?<hash:{}>", h(q)),
            None => base,
        },
        (_, None) => base,
    }
}

/// Every value becomes `<redacted>`; keys, order and repeats stay; `key` and `key=` stay as is.
fn redact_values(query: &str) -> String {
    query
        .split('&')
        .map(|part| match part.split_once('=') {
            Some((key, value)) if !value.is_empty() => format!("{key}=<redacted>"),
            _ => part.to_owned(),
        })
        .collect::<Vec<_>>()
        .join("&")
}

/// `/a` stays `/a`; `/a/b/c` becomes `/a/…`.
fn first_segment(path: &str) -> String {
    let rest = path.trim_start_matches('/');
    match rest.split_once('/') {
        Some((first, _)) => format!("/{first}/…"),
        None => format!("/{rest}"),
    }
}
