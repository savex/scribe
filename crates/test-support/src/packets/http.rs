/// Minimal HTTP/1.1 GET request.
pub fn get_request(host: &str, path: &str) -> Vec<u8> {
    format!(
        "GET {path} HTTP/1.1\r\nHost: {host}\r\nUser-Agent: scribe-fixture/1.0\r\nAccept: */*\r\n\r\n"
    )
    .into_bytes()
}
