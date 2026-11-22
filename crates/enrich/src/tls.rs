use scribe_core::Security;

/// Classify a TCP flow from the first bytes the client sent.
pub fn detect_security(first_bytes: &[u8]) -> Security {
    match first_bytes {
        // TLS record: handshake (0x16), legacy version 0x03xx.
        [0x16, 0x03, ..] => Security::Tls,
        [] => Security::Unknown,
        _ => Security::Plaintext,
    }
}

/// Extract the SNI hostname from a TLS ClientHello.
pub fn parse_sni(_client_hello: &[u8]) -> Option<String> {
    // TODO: parse ClientHello extensions (server_name, type 0).
    None
}
