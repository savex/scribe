//! A scripted HTTP server on 127.0.0.1:0: answers each connection with the next canned answer
//! and keeps what it received.

use std::io::{Read, Write};
use std::net::{TcpListener, TcpStream};
use std::sync::{Arc, Mutex};
use std::thread;

/// One received request: the head (request line and headers) and the body.
#[derive(Debug, Clone, Default)]
pub struct Received {
    pub head: String,
    pub body: Vec<u8>,
}

impl Received {
    pub fn header(&self, name: &str) -> Option<String> {
        self.head.lines().find_map(|l| {
            let (n, v) = l.split_once(':')?;
            n.eq_ignore_ascii_case(name).then(|| v.trim().to_owned())
        })
    }
}

/// What to do with one connection.
pub enum Answer {
    /// Send these bytes and close.
    Raw(Vec<u8>),
    /// Read the request, then never answer (hold the connection until the test ends).
    Silent,
}

pub fn answer(status: &str, headers: &[&str], body: &str) -> Answer {
    let mut text = format!("HTTP/1.1 {status}\r\n");
    for h in headers {
        text.push_str(h);
        text.push_str("\r\n");
    }
    if !headers.iter().any(|h| {
        let h = h.to_ascii_lowercase();
        h.starts_with("content-length") || h.starts_with("transfer-encoding")
    }) {
        text.push_str(&format!("Content-Length: {}\r\n", body.len()));
    }
    text.push_str("\r\n");
    text.push_str(body);
    Answer::Raw(text.into_bytes())
}

pub struct Server {
    pub port: u16,
    pub received: Arc<Mutex<Vec<Received>>>,
}

impl Server {
    pub fn url(&self, path: &str) -> String {
        format!("http://127.0.0.1:{}{path}", self.port)
    }

    pub fn requests(&self) -> Vec<Received> {
        self.received.lock().unwrap().clone()
    }
}

/// Read one request (head and `Content-Length` body).
pub fn read_request(stream: &mut impl Read) -> Received {
    let mut buf = Vec::new();
    let mut byte = [0u8; 1];
    while !buf.ends_with(b"\r\n\r\n") {
        if stream.read(&mut byte).unwrap_or(0) == 0 {
            break;
        }
        buf.push(byte[0]);
    }
    let head = String::from_utf8_lossy(&buf).into_owned();
    let mut got = Received {
        head,
        body: Vec::new(),
    };
    let len: usize = got
        .header("content-length")
        .and_then(|v| v.parse().ok())
        .unwrap_or(0);
    let mut body = vec![0u8; len];
    let _ = stream.read_exact(&mut body);
    got.body = body;
    got
}

pub fn start(answers: Vec<Answer>) -> Server {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let port = listener.local_addr().unwrap().port();
    let received = Arc::new(Mutex::new(Vec::new()));
    let log = received.clone();
    thread::spawn(move || {
        let mut held: Vec<TcpStream> = Vec::new();
        for answer in answers {
            let Ok((mut stream, _)) = listener.accept() else {
                return;
            };
            let request = read_request(&mut stream);
            log.lock().unwrap().push(request);
            match answer {
                Answer::Raw(bytes) => {
                    let _ = stream.write_all(&bytes);
                }
                Answer::Silent => held.push(stream),
            }
        }
        // Keep silent connections open until the process ends.
        thread::park();
        drop(held);
    });
    Server { port, received }
}
