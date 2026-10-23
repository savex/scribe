//! Source of truth for `testdata/pcap/` and `fuzz/corpus/`.
//!
//! Every fixture is built from code, so the committed files can be regenerated and checked
//! (`tests/fixtures_up_to_date.rs`). Each `<name>.pcap` has a `<name>.json` with the flows
//! a decoder plus enrichment must produce from it.

use std::fs;
use std::io;
use std::net::SocketAddr;
use std::path::{Path, PathBuf};

use crate::packets::dns::{self, Answer};
use crate::packets::tls::{client_hello, client_hello_sni, ClientHelloOptions};
use crate::packets::{http, udp_frame, write_pcap, TcpFlow};

pub struct Fixture {
    pub name: &'static str,
    pub description: &'static str,
    pub frames: Vec<Vec<u8>>,
    pub expected: Vec<ExpectedFlow>,
}

pub struct ExpectedFlow {
    pub proto: &'static str,
    pub dst: SocketAddr,
    pub hostname: Option<&'static str>,
    pub security: &'static str,
    pub url: Option<&'static str>,
    pub ech: bool,
}

impl ExpectedFlow {
    fn tcp(dst: &str, hostname: Option<&'static str>, security: &'static str) -> Self {
        Self {
            proto: "tcp",
            dst: addr(dst),
            hostname,
            security,
            url: None,
            ech: false,
        }
    }

    fn dns(dst: &str) -> Self {
        Self {
            proto: "udp",
            dst: addr(dst),
            hostname: None,
            security: "plaintext",
            url: None,
            ech: false,
        }
    }
}

impl Fixture {
    pub fn pcap(&self) -> Vec<u8> {
        write_pcap(&self.frames)
    }

    pub fn golden_json(&self) -> String {
        let flows: Vec<String> = self
            .expected
            .iter()
            .map(|f| {
                format!(
                    "    {{ \"proto\": \"{}\", \"dst_ip\": \"{}\", \"dst_port\": {}, \"hostname\": {}, \"security\": \"{}\", \"url\": {}, \"ech\": {} }}",
                    f.proto,
                    f.dst.ip(),
                    f.dst.port(),
                    json_opt(f.hostname),
                    f.security,
                    json_opt(f.url),
                    f.ech
                )
            })
            .collect();
        let flows = if flows.is_empty() {
            "[]".to_owned()
        } else {
            format!("[\n{}\n  ]", flows.join(",\n"))
        };
        format!(
            "{{\n  \"fixture\": \"{}.pcap\",\n  \"description\": {},\n  \"expected_flows\": {}\n}}\n",
            self.name,
            json_str(self.description),
            flows
        )
    }
}

fn addr(s: &str) -> SocketAddr {
    s.parse().expect("fixture address")
}

fn json_str(s: &str) -> String {
    format!("\"{}\"", s.replace('\\', "\\\\").replace('"', "\\\""))
}

fn json_opt(s: Option<&str>) -> String {
    s.map_or_else(|| "null".to_owned(), json_str)
}

/// One TCP connection: handshake, then each payload as its own segment.
fn tcp_session(client: &str, server: &str, payloads: &[&[u8]]) -> Vec<Vec<u8>> {
    let mut flow = TcpFlow::new(addr(client), addr(server));
    let mut frames = flow.handshake();
    for payload in payloads {
        frames.push(flow.client_data(payload));
    }
    frames
}

fn dns_exchange(
    client: &str,
    server: &str,
    id: u16,
    name: &str,
    qtype: u16,
    answers: &[Answer],
) -> Vec<Vec<u8>> {
    let (c, s) = (addr(client), addr(server));
    vec![
        udp_frame(c, s, &dns::query(id, name, qtype), true),
        udp_frame(s, c, &dns::response(id, name, qtype, answers, 300), false),
    ]
}

fn no_sni_hello() -> Vec<u8> {
    client_hello(&ClientHelloOptions {
        sni: None,
        tls13: true,
        ech: false,
    })
}

/// Frames that a decoder must reject without panicking.
fn malformed_frames() -> Vec<Vec<u8>> {
    let valid = TcpFlow::new(addr("10.0.0.2:50012"), addr("192.0.2.99:443"))
        .handshake()
        .remove(0);

    let mut bad_ihl = valid.clone();
    bad_ihl[14] = 0x4f; // IHL 15 words = 60 bytes, longer than the real header

    let mut bad_total_len = valid.clone();
    bad_total_len[16..18].copy_from_slice(&9000u16.to_be_bytes());

    let mut unknown_ethertype = valid.clone();
    unknown_ethertype[12..14].copy_from_slice(&0x88b5u16.to_be_bytes());

    let mut bad_tcp_offset = valid.clone();
    bad_tcp_offset[14 + 20 + 12] = 0x10; // data offset 1 word, below the 5-word minimum

    vec![
        valid[..10].to_vec(),
        valid[..20].to_vec(),
        bad_ihl,
        bad_total_len,
        unknown_ethertype,
        bad_tcp_offset,
    ]
}

pub fn all() -> Vec<Fixture> {
    let fragmented_hello = client_hello_sni("split.example.com");
    let (frag_a, frag_b) = fragmented_hello.split_at(40);

    let ooo_hello = client_hello_sni("ooo.example.com");
    let (ooo_a, ooo_b) = ooo_hello.split_at(40);
    let ooo_frames = {
        let mut flow = TcpFlow::new(addr("10.0.0.2:50010"), addr("192.0.2.31:443"));
        let mut frames = flow.handshake();
        let first = flow.client_data(ooo_a);
        let second = flow.client_data(ooo_b);
        frames.push(second);
        frames.push(first);
        frames
    };

    let truncated_hello = client_hello_sni("truncated.example.com");

    let mut dns_cname = dns_exchange(
        "10.0.0.2:53001",
        "192.0.2.53:53",
        0x1001,
        "cdn.example.com",
        dns::TYPE_A,
        &[
            Answer::Cname("cdn.example.com", "edge.example.net"),
            Answer::A("edge.example.net", "192.0.2.50".parse().unwrap()),
        ],
    );
    dns_cname.extend(tcp_session(
        "10.0.0.2:50006",
        "192.0.2.50:443",
        &[&no_sni_hello()],
    ));

    let mut dns_aaaa = dns_exchange(
        "[fd00::2]:53002",
        "[2001:db8::53]:53",
        0x1002,
        "v6.example.com",
        dns::TYPE_AAAA,
        &[Answer::Aaaa(
            "v6.example.com",
            "2001:db8::50".parse().unwrap(),
        )],
    );
    dns_aaaa.extend(tcp_session(
        "[fd00::2]:50007",
        "[2001:db8::50]:443",
        &[&no_sni_hello()],
    ));

    vec![
        Fixture {
            name: "tls13_sni_ipv4",
            description: "TLS 1.3 ClientHello with SNI over IPv4.",
            frames: tcp_session("10.0.0.2:50001", "192.0.2.10:443", &[&client_hello_sni("api.example.com")]),
            expected: vec![ExpectedFlow::tcp("192.0.2.10:443", Some("api.example.com"), "tls")],
        },
        Fixture {
            name: "tls12_sni_ipv6",
            description: "TLS 1.2-only ClientHello with SNI over IPv6.",
            frames: tcp_session(
                "[fd00::2]:50002",
                "[2001:db8::10]:443",
                &[&client_hello(&ClientHelloOptions {
                    sni: Some("legacy.example.com".into()),
                    tls13: false,
                    ech: false,
                })],
            ),
            expected: vec![ExpectedFlow::tcp("[2001:db8::10]:443", Some("legacy.example.com"), "tls")],
        },
        Fixture {
            name: "tls_no_sni",
            description: "ClientHello without SNI and no prior DNS answer: hostname stays unknown.",
            frames: tcp_session("10.0.0.2:50003", "192.0.2.11:443", &[&no_sni_hello()]),
            expected: vec![ExpectedFlow::tcp("192.0.2.11:443", None, "tls")],
        },
        Fixture {
            name: "tls_ech",
            description: "ClientHello with encrypted_client_hello: only the outer public name is visible.",
            frames: tcp_session(
                "10.0.0.2:50004",
                "192.0.2.12:443",
                &[&client_hello(&ClientHelloOptions {
                    sni: Some("public.example.com".into()),
                    tls13: true,
                    ech: true,
                })],
            ),
            expected: vec![ExpectedFlow {
                ech: true,
                ..ExpectedFlow::tcp("192.0.2.12:443", Some("public.example.com"), "tls")
            }],
        },
        Fixture {
            name: "http_plain",
            description: "Plaintext HTTP/1.1 GET: full URL is visible.",
            frames: tcp_session(
                "10.0.0.2:50005",
                "192.0.2.20:80",
                &[&http::get_request("plain.example.com", "/download?id=42")],
            ),
            expected: vec![ExpectedFlow {
                url: Some("http://plain.example.com/download?id=42"),
                ..ExpectedFlow::tcp("192.0.2.20:80", Some("plain.example.com"), "plaintext")
            }],
        },
        Fixture {
            name: "dns_cname_then_tls",
            description: "DNS A query answered through a CNAME, then TLS without SNI to the answer IP: hostname is the name that was queried.",
            frames: dns_cname,
            expected: vec![
                ExpectedFlow::dns("192.0.2.53:53"),
                ExpectedFlow::tcp("192.0.2.50:443", Some("cdn.example.com"), "tls"),
            ],
        },
        Fixture {
            name: "dns_aaaa_then_tls",
            description: "DNS AAAA over IPv6, then TLS without SNI to the answer IP.",
            frames: dns_aaaa,
            expected: vec![
                ExpectedFlow::dns("[2001:db8::53]:53"),
                ExpectedFlow::tcp("[2001:db8::50]:443", Some("v6.example.com"), "tls"),
            ],
        },
        Fixture {
            name: "raw_ip_odd_port",
            description: "Binary plaintext to an IP with no DNS lookup, on an unusual port.",
            frames: tcp_session("10.0.0.2:50008", "198.51.100.7:8443", &[b"\x00\x01SCRIBE-BINARY"]),
            expected: vec![ExpectedFlow::tcp("198.51.100.7:8443", None, "plaintext")],
        },
        Fixture {
            name: "tls_fragmented",
            description: "ClientHello split across two in-order TCP segments; SNI spans the split.",
            frames: tcp_session("10.0.0.2:50009", "192.0.2.30:443", &[frag_a, frag_b]),
            expected: vec![ExpectedFlow::tcp("192.0.2.30:443", Some("split.example.com"), "tls")],
        },
        Fixture {
            name: "tls_out_of_order",
            description: "ClientHello split across two TCP segments that arrive in reverse order.",
            frames: ooo_frames,
            expected: vec![ExpectedFlow::tcp("192.0.2.31:443", Some("ooo.example.com"), "tls")],
        },
        Fixture {
            name: "tls_truncated",
            description: "ClientHello cut off before the SNI extension: detected as TLS, hostname unknown.",
            frames: tcp_session("10.0.0.2:50011", "192.0.2.32:443", &[&truncated_hello[..60]]),
            expected: vec![ExpectedFlow::tcp("192.0.2.32:443", None, "tls")],
        },
        Fixture {
            name: "malformed",
            description: "Short frames, bad IPv4 header length, bad total length, unknown ethertype, bad TCP data offset: no flows and no panic.",
            frames: malformed_frames(),
            expected: vec![],
        },
        Fixture {
            name: "doh",
            description: "TLS to a public DNS-over-HTTPS resolver; later DNS lookups from this client are invisible.",
            frames: tcp_session("10.0.0.2:50013", "8.8.8.8:443", &[&client_hello_sni("dns.google")]),
            expected: vec![ExpectedFlow::tcp("8.8.8.8:443", Some("dns.google"), "tls")],
        },
    ]
}

/// Seed inputs for `fuzz/corpus/<target>/<name>`.
pub fn fuzz_seeds() -> Vec<(&'static str, &'static str, Vec<u8>)> {
    let hello = client_hello_sni("seed.example.com");
    vec![
        ("tls_client_hello", "tls13_sni", hello.clone()),
        ("tls_client_hello", "tls13_no_sni", no_sni_hello()),
        (
            "tls_client_hello",
            "tls12_sni",
            client_hello(&ClientHelloOptions {
                sni: Some("seed.example.com".into()),
                tls13: false,
                ech: false,
            }),
        ),
        (
            "tls_client_hello",
            "ech",
            client_hello(&ClientHelloOptions {
                sni: Some("public.example.com".into()),
                tls13: true,
                ech: true,
            }),
        ),
        ("tls_client_hello", "truncated", hello[..60].to_vec()),
        ("tls_client_hello", "empty", vec![]),
        (
            "http_request",
            "get",
            http::get_request("seed.example.com", "/"),
        ),
        (
            "http_request",
            "get_query",
            http::get_request("seed.example.com", "/a/b?c=d&e=f"),
        ),
        (
            "http_request",
            "no_host",
            b"GET / HTTP/1.0\r\n\r\n".to_vec(),
        ),
        ("http_request", "binary", b"\x00\x01\x02\xff".to_vec()),
    ]
}

/// Every generated file as (path relative to repo root, contents).
pub fn generated_files() -> Vec<(PathBuf, Vec<u8>)> {
    let mut files = Vec::new();
    for fixture in all() {
        let dir = Path::new("testdata/pcap");
        files.push((dir.join(format!("{}.pcap", fixture.name)), fixture.pcap()));
        files.push((
            dir.join(format!("{}.json", fixture.name)),
            fixture.golden_json().into_bytes(),
        ));
    }
    for (target, name, data) in fuzz_seeds() {
        files.push((Path::new("fuzz/corpus").join(target).join(name), data));
    }
    files
}

pub fn write_all(root: &Path) -> io::Result<usize> {
    let files = generated_files();
    for (rel, data) in &files {
        let path = root.join(rel);
        if let Some(parent) = path.parent() {
            fs::create_dir_all(parent)?;
        }
        fs::write(path, data)?;
    }
    Ok(files.len())
}

/// Generated files that are missing or differ on disk.
pub fn stale(root: &Path) -> Vec<PathBuf> {
    generated_files()
        .into_iter()
        .filter(|(rel, data)| fs::read(root.join(rel)).map_or(true, |disk| &disk != data))
        .map(|(rel, _)| rel)
        .collect()
}
