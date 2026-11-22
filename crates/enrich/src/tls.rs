//! TLS: classify a flow from its first bytes and read the ClientHello (SNI, ECH, ALPN).
//!
//! The parser takes the client's first bytes as the sensor passed them on (TLS records, possibly
//! several, possibly cut short) and never panics on any input. QUIC hands the same handshake
//! message over without the record layer: see [`parse_client_hello_handshake`].

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

/// What a ClientHello says about where the client wants to go.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct ClientHello {
    /// `server_name` (lowercase, no trailing dot); with ECH this is the outer public name.
    pub sni: Option<String>,
    /// An `encrypted_client_hello` extension is present (FR-5).
    pub ech: bool,
    /// Application protocols offered (`h2`, `http/1.1`, `h3`, …).
    pub alpn: Vec<String>,
    /// TLS 1.3 offered (`supported_versions` lists 0x0304).
    pub tls13: bool,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HelloError {
    /// Not a TLS handshake record, or not a ClientHello.
    NotClientHello,
    /// The bytes end before the ClientHello does.
    Incomplete,
    /// Lengths or fields that don't add up.
    Malformed,
}

const EXT_SERVER_NAME: u16 = 0x0000;
const EXT_ALPN: u16 = 0x0010;
const EXT_SUPPORTED_VERSIONS: u16 = 0x002b;
const EXT_ECH: u16 = 0xfe0d;
/// A ClientHello larger than this is treated as malformed.
const MAX_HELLO: usize = 1 << 16;

/// Parse the ClientHello from TLS records: the handshake message may span several records.
pub fn parse_client_hello(records: &[u8]) -> Result<ClientHello, HelloError> {
    let mut handshake = Vec::new();
    let mut rest = records;
    loop {
        if rest.len() < 5 {
            return Err(
                if handshake.is_empty() && !rest.is_empty() && rest[0] != 0x16 {
                    HelloError::NotClientHello
                } else {
                    HelloError::Incomplete
                },
            );
        }
        if rest[0] != 0x16 || rest[1] != 0x03 {
            return Err(HelloError::NotClientHello);
        }
        let len = u16::from_be_bytes([rest[3], rest[4]]) as usize;
        let body = &rest[5..];
        let take = len.min(body.len());
        handshake.extend_from_slice(&body[..take]);
        if handshake.len() > MAX_HELLO + 4 {
            return Err(HelloError::Malformed);
        }
        match parse_client_hello_handshake(&handshake) {
            Err(HelloError::Incomplete) if take == len => rest = &body[take..],
            other => return other,
        }
    }
}

/// Parse a ClientHello handshake message (type, 24-bit length, body), as carried by TLS records
/// or by QUIC CRYPTO frames.
pub fn parse_client_hello_handshake(msg: &[u8]) -> Result<ClientHello, HelloError> {
    let mut r = Reader(msg);
    let kind = r.u8()?;
    if kind != 0x01 {
        return Err(HelloError::NotClientHello);
    }
    let len = r.u24()? as usize;
    if len > MAX_HELLO {
        return Err(HelloError::Malformed);
    }
    let mut body = Reader(r.bytes(len)?);
    body.bytes(2)?; // legacy_version
    body.bytes(32)?; // random
    let sid = body.u8()? as usize;
    body.bytes(sid)?;
    let suites = body.u16()? as usize;
    body.bytes(suites)?;
    let compression = body.u8()? as usize;
    body.bytes(compression)?;
    let mut hello = ClientHello::default();
    if body.0.is_empty() {
        return Ok(hello); // no extensions at all
    }
    let ext_len = body.u16()? as usize;
    let mut exts = Reader(body.bytes(ext_len).map_err(|_| HelloError::Malformed)?);
    while !exts.0.is_empty() {
        let ty = exts.u16().map_err(|_| HelloError::Malformed)?;
        let n = exts.u16().map_err(|_| HelloError::Malformed)? as usize;
        let data = exts.bytes(n).map_err(|_| HelloError::Malformed)?;
        match ty {
            EXT_SERVER_NAME => hello.sni = server_name(data),
            EXT_ALPN => hello.alpn = alpn(data),
            EXT_SUPPORTED_VERSIONS => hello.tls13 = offers_tls13(data),
            EXT_ECH => hello.ech = true,
            _ => {}
        }
    }
    Ok(hello)
}

/// The SNI host name from TLS records, if the ClientHello is complete enough to have one.
pub fn parse_sni(records: &[u8]) -> Option<String> {
    parse_client_hello(records).ok()?.sni
}

fn server_name(data: &[u8]) -> Option<String> {
    let mut r = Reader(data);
    let list = r.u16().ok()? as usize;
    let mut list = Reader(r.bytes(list).ok()?);
    while !list.0.is_empty() {
        let kind = list.u8().ok()?;
        let n = list.u16().ok()? as usize;
        let name = list.bytes(n).ok()?;
        if kind == 0 {
            return valid_host(name);
        }
    }
    None
}

/// A DNS host name: 1–253 characters, labels of letters, digits and `-` (`_` tolerated), lowercase.
pub fn valid_host(name: &[u8]) -> Option<String> {
    let name = std::str::from_utf8(name).ok()?.trim_end_matches('.');
    if name.is_empty() || name.len() > 253 {
        return None;
    }
    let ok = name.split('.').all(|label| {
        !label.is_empty()
            && label.len() <= 63
            && label
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_')
    });
    ok.then(|| name.to_ascii_lowercase())
}

fn alpn(data: &[u8]) -> Vec<String> {
    let mut out = Vec::new();
    let mut r = Reader(data);
    let Ok(n) = r.u16() else { return out };
    let Ok(list) = r.bytes(n as usize) else {
        return out;
    };
    let mut list = Reader(list);
    while let Ok(len) = list.u8() {
        match list.bytes(len as usize) {
            Ok(p) => out.push(String::from_utf8_lossy(p).into_owned()),
            Err(_) => break,
        }
    }
    out
}

fn offers_tls13(data: &[u8]) -> bool {
    let Some((&n, list)) = data.split_first() else {
        return false;
    };
    list.get(..n as usize)
        .is_some_and(|v| v.as_chunks::<2>().0.contains(&[0x03, 0x04]))
}

struct Reader<'a>(&'a [u8]);

impl<'a> Reader<'a> {
    fn bytes(&mut self, n: usize) -> Result<&'a [u8], HelloError> {
        if self.0.len() < n {
            return Err(HelloError::Incomplete);
        }
        let (head, tail) = self.0.split_at(n);
        self.0 = tail;
        Ok(head)
    }
    fn u8(&mut self) -> Result<u8, HelloError> {
        Ok(self.bytes(1)?[0])
    }
    fn u16(&mut self) -> Result<u16, HelloError> {
        let b = self.bytes(2)?;
        Ok(u16::from_be_bytes([b[0], b[1]]))
    }
    fn u24(&mut self) -> Result<u32, HelloError> {
        let b = self.bytes(3)?;
        Ok(u32::from_be_bytes([0, b[0], b[1], b[2]]))
    }
}
