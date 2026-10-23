/// Extract the request URL (`http://host/path`) from a plaintext HTTP/1.x request.
pub fn parse_request_url(_request: &[u8]) -> Option<String> {
    // TODO: parse request line and Host header.
    None
}
