use std::fmt;
use std::net::IpAddr;

use crate::NetError;

/// A checked destination: https, or http to a loopback host.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Target {
    pub tls: bool,
    /// Without IPv6 brackets.
    pub host: String,
    pub port: u16,
    /// `/path?query`, never empty.
    pub path_query: String,
}

/// `localhost`, `127.0.0.0/8` or `::1`.
pub fn is_loopback(host: &str) -> bool {
    host.eq_ignore_ascii_case("localhost")
        || host.parse::<IpAddr>().is_ok_and(|ip| ip.is_loopback())
}

/// Parse `url` and apply the scheme rule (https, or http to loopback only).
pub fn checked_url(url: &str) -> Result<Target, NetError> {
    let bad = |why: &str| NetError::Url(url.to_owned(), why.to_owned());
    let uri: http::Uri = url
        .parse()
        .map_err(|e: http::uri::InvalidUri| bad(&e.to_string()))?;
    let tls = match uri.scheme_str() {
        Some("https") => true,
        Some("http") => false,
        Some(other) => return Err(bad(&format!("scheme {other} is not http or https"))),
        None => return Err(bad("not an absolute URL")),
    };
    let authority = uri.authority().ok_or_else(|| bad("no host"))?;
    if authority.as_str().contains('@') {
        return Err(bad(
            "user names and passwords don't belong in the URL; use `secret`",
        ));
    }
    let host = authority
        .host()
        .trim_start_matches('[')
        .trim_end_matches(']')
        .to_owned();
    if host.is_empty() {
        return Err(bad("no host"));
    }
    if !tls && !is_loopback(&host) {
        return Err(NetError::NotHttps(url.to_owned()));
    }
    let port = authority.port_u16().unwrap_or(if tls { 443 } else { 80 });
    let path_query = uri
        .path_and_query()
        .map(|p| p.as_str().to_owned())
        .filter(|p| !p.is_empty())
        .unwrap_or_else(|| "/".to_owned());
    Ok(Target {
        tls,
        host,
        port,
        path_query,
    })
}

impl Target {
    pub fn same_origin(&self, other: &Target) -> bool {
        self.tls == other.tls
            && self.host.eq_ignore_ascii_case(&other.host)
            && self.port == other.port
    }

    fn default_port(&self) -> bool {
        self.port == if self.tls { 443 } else { 80 }
    }

    /// The `Host` header.
    pub fn host_header(&self) -> String {
        let host = if self.host.contains(':') {
            format!("[{}]", self.host)
        } else {
            self.host.clone()
        };
        if self.default_port() {
            host
        } else {
            format!("{host}:{}", self.port)
        }
    }

    /// Resolve a `Location` header against this target (absolute, `/path` or relative path).
    pub fn join(&self, location: &str) -> Result<Target, NetError> {
        if location.contains("://") {
            return checked_url(location);
        }
        if location.starts_with("//") {
            let scheme = if self.tls { "https:" } else { "http:" };
            return checked_url(&format!("{scheme}{location}"));
        }
        let path_query = if location.starts_with('/') {
            location.to_owned()
        } else {
            let path = self.path_query.split('?').next().unwrap_or("/");
            let dir = &path[..=path.rfind('/').unwrap_or(0)];
            format!("{dir}{location}")
        };
        if path_query.contains(char::is_whitespace) {
            return Err(NetError::Url(
                location.to_owned(),
                "redirect target contains spaces".into(),
            ));
        }
        Ok(Target {
            path_query,
            ..self.clone()
        })
    }
}

impl fmt::Display for Target {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let scheme = if self.tls { "https" } else { "http" };
        // Only the path: query strings may carry tokens.
        let path = self.path_query.split('?').next().unwrap_or("/");
        write!(f, "{scheme}://{}{path}", self.host_header())
    }
}
