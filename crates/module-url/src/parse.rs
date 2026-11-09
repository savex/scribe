//! Plaintext HTTP/1.x request parsing (plan phase 3).

/// The absolute URL (`http://host/path?query`) of the HTTP/1.x request at the start of `head`:
/// request line plus `Host` header, or an absolute-form target. User info is never kept.
pub fn request_url(_head: &[u8]) -> Option<String> {
    // TODO(phase 3): parse the request line and headers; fuzzed by `fuzz/fuzz_targets/http_request.rs`.
    None
}
