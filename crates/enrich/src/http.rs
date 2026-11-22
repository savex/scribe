//! Plaintext HTTP/1.x request heads: the request line and the `Host` header (FR-3). The URL module
//! builds URLs from [`RequestHead`]; enrichment uses only the host name. Never panics on any input;
//! a head cut short still yields what it has, as long as the request line is complete.

use std::net::IpAddr;

use crate::tls::valid_host;

/// The parts of a request head scribe uses.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RequestHead {
    /// `GET`, `POST`, … (upper case letters only).
    pub method: String,
    /// The request target as sent: `/path?query`, `http://host/path` (proxy form), `host:443`
    /// (`CONNECT`) or `*`.
    pub target: String,
    /// The `Host` header value as sent, if present and complete.
    pub host_header: Option<String>,
}

/// Longest request line or header line considered.
const MAX_LINE: usize = 8 * 1024;

/// Parse the request line and the `Host` header.
pub fn parse_request_head(bytes: &[u8]) -> Option<RequestHead> {
    let mut lines = Lines(bytes);
    let line = lines.next()?;
    let line = std::str::from_utf8(line).ok()?;
    let mut parts = line.split(' ');
    let (method, target, version) = (parts.next()?, parts.next()?, parts.next()?);
    if parts.next().is_some()
        || method.is_empty()
        || method.len() > 16
        || !method.bytes().all(|b| b.is_ascii_uppercase())
        || target.is_empty()
        || !version.starts_with("HTTP/1.")
    {
        return None;
    }
    let mut host_header = None;
    for line in lines {
        if line.is_empty() {
            break; // end of headers
        }
        let Some(colon) = line.iter().position(|&b| b == b':') else {
            continue;
        };
        if line[..colon].eq_ignore_ascii_case(b"host") && host_header.is_none() {
            let value = std::str::from_utf8(&line[colon + 1..]).ok()?.trim();
            host_header = Some(value.to_owned());
        }
    }
    Some(RequestHead {
        method: method.to_owned(),
        target: target.to_owned(),
        host_header,
    })
}

/// Split a `host[:port]` value into a checked, lower-case host and an optional port. IPv6 literals
/// keep their brackets: `[2001:db8::1]:8080`.
pub fn split_host_port(value: &str) -> Option<(String, Option<u16>)> {
    if let Some(rest) = value.strip_prefix('[') {
        let end = rest.find(']')?;
        let ip: IpAddr = rest[..end].parse().ok()?;
        if !ip.is_ipv6() {
            return None;
        }
        let port = match &rest[end + 1..] {
            "" => None,
            p => Some(p.strip_prefix(':')?.parse().ok()?),
        };
        return Some((format!("[{}]", rest[..end].to_ascii_lowercase()), port));
    }
    let (host, port) = match value.rsplit_once(':') {
        Some((h, p)) => (h, Some(p.parse().ok()?)),
        None => (value, None),
    };
    if host.parse::<IpAddr>().is_ok() {
        return Some((host.to_owned(), port));
    }
    Some((valid_host(host.as_bytes())?, port))
}

/// The host name of the request (from the `Host` header, or the proxy-form or `CONNECT` target),
/// lower case, without a port. IP literals are not names, so they give `None`.
pub fn host_header(request: &[u8]) -> Option<String> {
    let head = parse_request_head(request)?;
    let value = match &head.host_header {
        Some(h) => h.clone(),
        None => {
            let t = head.target.as_str();
            let after = t
                .strip_prefix("http://")
                .or_else(|| t.strip_prefix("https://"));
            match after {
                Some(rest) => rest.split('/').next()?.rsplit('@').next()?.to_owned(),
                None if head.method == "CONNECT" => t.to_owned(),
                None => return None,
            }
        }
    };
    let (host, _) = split_host_port(&value)?;
    (host.parse::<IpAddr>().is_err() && !host.starts_with('[')).then_some(host)
}

/// CRLF-separated lines; a final line without CRLF (cut short) is not returned.
struct Lines<'a>(&'a [u8]);

impl<'a> Iterator for Lines<'a> {
    type Item = &'a [u8];

    fn next(&mut self) -> Option<&'a [u8]> {
        let window = &self.0[..self.0.len().min(MAX_LINE + 2)];
        let end = window.windows(2).position(|w| w == b"\r\n")?;
        let line = &self.0[..end];
        self.0 = &self.0[end + 2..];
        Some(line)
    }
}
