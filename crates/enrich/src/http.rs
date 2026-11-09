/// The `Host` header of the plaintext HTTP/1.x request at the start of `request`, for the host name
/// (FR-3). Full request and URL parsing belongs to the URL module (`scribe-module-url`).
pub fn host_header(_request: &[u8]) -> Option<&str> {
    // TODO(phase 3): find the `Host` header in the request head.
    None
}
