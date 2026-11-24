//! FUN-A04 `threat_list_integrity`: pinned SHA-256 and minisign checks, the entry cap, the last
//! good copy, and downloads from a local server on port 0.

use std::io::{Read, Write};
use std::net::TcpListener;
use std::path::Path;
use std::sync::Arc;
use std::time::Duration;

use ring::signature::{Ed25519KeyPair, KeyPair};
use scribe_daemon::config::{ThreatOrigin, ThreatSource};
use scribe_daemon::threats::{fetch, load_all, merged, parse, signature_url, verify, Feeds};
use scribe_policy::ThreatFormat;
use scribe_test_support::FakeClock;

const LIST: &str = "# test list\nbad.example.com\nworse.example.net\n";

fn b64(bytes: &[u8]) -> String {
    const A: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let mut out = String::new();
    for chunk in bytes.chunks(3) {
        let n = chunk
            .iter()
            .enumerate()
            .fold(0u32, |n, (i, b)| n | u32::from(*b) << (16 - 8 * i));
        for i in 0..4 {
            if i <= chunk.len() {
                out.push(A[(n >> (18 - 6 * i) & 63) as usize] as char);
            } else {
                out.push('=');
            }
        }
    }
    out
}

/// A minisign key pair (legacy `Ed` signatures, made with ring) for test lists.
struct Signer {
    pair: Ed25519KeyPair,
    key_id: [u8; 8],
}

impl Signer {
    fn new(seed: u8) -> Self {
        Self {
            pair: Ed25519KeyPair::from_seed_unchecked(&[seed; 32]).unwrap(),
            key_id: [seed, 1, 2, 3, 4, 5, 6, 7],
        }
    }

    fn public_key(&self) -> String {
        let mut bin = b"Ed".to_vec();
        bin.extend_from_slice(&self.key_id);
        bin.extend_from_slice(self.pair.public_key().as_ref());
        b64(&bin)
    }

    fn sign(&self, body: &[u8]) -> String {
        let sig = self.pair.sign(body);
        let mut bin = b"Ed".to_vec();
        bin.extend_from_slice(&self.key_id);
        bin.extend_from_slice(sig.as_ref());
        let comment = "timestamp:1800000000";
        let mut global = sig.as_ref().to_vec();
        global.extend_from_slice(comment.as_bytes());
        format!(
            "untrusted comment: signature from a test key\n{}\ntrusted comment: {comment}\n{}\n",
            b64(&bin),
            b64(self.pair.sign(&global).as_ref())
        )
    }
}

fn sha256(body: &[u8]) -> String {
    ring::digest::digest(&ring::digest::SHA256, body)
        .as_ref()
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect()
}

#[test]
fn a_pinned_hash_must_match() {
    verify(LIST.as_bytes(), Some(&sha256(LIST.as_bytes())), None, None).unwrap();
    verify(
        LIST.as_bytes(),
        Some(&sha256(LIST.as_bytes()).to_uppercase()),
        None,
        None,
    )
    .unwrap();
    let err = verify(b"changed", Some(&sha256(LIST.as_bytes())), None, None).unwrap_err();
    assert!(err.contains("not the pinned"), "{err}");
}

#[test]
fn a_minisign_signature_must_match_the_key_and_the_body() {
    let signer = Signer::new(7);
    let signature = signer.sign(LIST.as_bytes());
    verify(
        LIST.as_bytes(),
        None,
        Some(&signer.public_key()),
        Some(&signature),
    )
    .unwrap();

    let tampered = verify(
        b"evil.example.com\n",
        None,
        Some(&signer.public_key()),
        Some(&signature),
    )
    .unwrap_err();
    assert!(tampered.contains("does not match"), "{tampered}");
    let other_key = verify(
        LIST.as_bytes(),
        None,
        Some(&Signer::new(9).public_key()),
        Some(&signature),
    )
    .unwrap_err();
    assert!(other_key.contains("does not match"), "{other_key}");
    let missing = verify(LIST.as_bytes(), None, Some(&signer.public_key()), None).unwrap_err();
    assert!(missing.contains("missing"), "{missing}");
    let garbage = verify(
        LIST.as_bytes(),
        None,
        Some(&signer.public_key()),
        Some("nope"),
    )
    .unwrap_err();
    assert!(garbage.contains("can't be read"), "{garbage}");
}

fn source(name: &str, origin: ThreatOrigin, max_entries: usize) -> ThreatSource {
    ThreatSource {
        name: name.into(),
        format: ThreatFormat::Domains,
        max_entries,
        origin,
    }
}

#[test]
fn lists_over_their_entry_cap_are_refused() {
    let s = source("feed", ThreatOrigin::File("/x".into()), 2);
    let (set, skipped) = parse(&s, LIST).unwrap();
    assert_eq!((set.len(), skipped), (2, 0));
    let err = parse(&s, "a.example.com\nb.example.com\nc.example.com\n").unwrap_err();
    assert_eq!(err, "3 entries, more than max_entries = 2");
    assert_eq!(
        signature_url("https://lists.example.com/d.txt?k=1"),
        "https://lists.example.com/d.txt.minisig?k=1"
    );
}

/// Serves `/list.txt` and `/list.txt.minisig` from the answers given per request, in order.
fn server(answers: Vec<(u16, Vec<u8>)>) -> (String, Arc<std::sync::Mutex<Vec<String>>>) {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let base = format!("http://127.0.0.1:{}", listener.local_addr().unwrap().port());
    let paths = Arc::new(std::sync::Mutex::new(Vec::new()));
    let seen = paths.clone();
    std::thread::spawn(move || {
        for (status, body) in answers {
            let Ok((mut s, _)) = listener.accept() else {
                return;
            };
            let mut head = Vec::new();
            let mut b = [0u8; 1];
            while !head.ends_with(b"\r\n\r\n") && s.read(&mut b).unwrap_or(0) == 1 {
                head.push(b[0]);
            }
            let line = String::from_utf8_lossy(&head)
                .lines()
                .next()
                .unwrap_or("")
                .to_owned();
            seen.lock()
                .unwrap()
                .push(line.split(' ').nth(1).unwrap_or("").to_owned());
            let _ = write!(
                s,
                "HTTP/1.1 {status} X\r\nContent-Length: {}\r\n\r\n",
                body.len()
            );
            let _ = s.write_all(&body);
        }
    });
    (format!("{base}/list.txt"), paths)
}

fn download(url: &str, cache: &Path, sha: Option<String>, key: Option<String>) -> ThreatSource {
    source(
        "feed",
        ThreatOrigin::Download {
            url: url.into(),
            refresh: Duration::from_millis(100),
            sha256: sha,
            minisign_key: key,
            cache: cache.to_owned(),
        },
        100,
    )
}

#[test]
fn downloads_are_checked_before_use() {
    let dir = tempfile::tempdir().unwrap();
    let cache = dir.path().join("feed.txt");
    let signer = Signer::new(3);

    let (url, paths) = server(vec![
        (200, LIST.as_bytes().to_vec()),
        (200, signer.sign(LIST.as_bytes()).into_bytes()),
    ]);
    let (text, set) = fetch(&download(&url, &cache, None, Some(signer.public_key()))).unwrap();
    assert_eq!(text, LIST);
    assert!(set.matches_host("www.bad.example.com"));
    assert_eq!(*paths.lock().unwrap(), ["/list.txt", "/list.txt.minisig"]);

    let (url, _) = server(vec![(200, b"evil.example.com\n".to_vec())]);
    let err = fetch(&download(&url, &cache, Some(sha256(LIST.as_bytes())), None)).unwrap_err();
    assert!(err.contains("not the pinned"), "{err}");

    let (url, _) = server(vec![(404, Vec::new())]);
    let err = fetch(&download(&url, &cache, None, None)).unwrap_err();
    assert!(err.ends_with("answered 404"), "{err}");

    let err = fetch(&download(
        "http://lists.example.com/l.txt",
        &cache,
        None,
        None,
    ))
    .unwrap_err();
    assert!(
        err.contains("plain http is allowed only to a loopback host"),
        "{err}"
    );
}

#[test]
fn files_must_load_and_downloads_start_from_their_last_good_copy() {
    let dir = tempfile::tempdir().unwrap();
    let file = dir.path().join("local.txt");
    std::fs::write(&file, "local.example.com\n").unwrap();
    let cache = dir.path().join("threat-lists/feed.txt");
    let sources = vec![
        source("local", ThreatOrigin::File(file.clone()), 10),
        download("https://lists.example.com/l.txt", &cache, None, None),
    ];
    let lists = load_all(&sources).unwrap();
    assert_eq!(lists.keys().collect::<Vec<_>>(), ["local"], "no copy yet");

    std::fs::create_dir_all(cache.parent().unwrap()).unwrap();
    std::fs::write(&cache, LIST).unwrap();
    let lists = load_all(&sources).unwrap();
    let all = merged(&lists);
    assert!(all.matches_host("local.example.com") && all.matches_host("bad.example.com"));

    std::fs::write(&file, "a.example.com\nb.example.com\n").unwrap();
    let small = vec![source("local", ThreatOrigin::File(file.clone()), 1)];
    let err = load_all(&small).unwrap_err().to_string();
    assert!(err.contains("more than max_entries = 1"), "{err}");
    std::fs::remove_file(&file).unwrap();
    assert!(load_all(&sources).is_err(), "a missing file stops scribed");
}

#[tokio::test(flavor = "multi_thread")]
async fn a_failed_refresh_keeps_the_last_good_list() {
    let dir = tempfile::tempdir().unwrap();
    let cache = dir.path().join("threat-lists/feed.txt");
    let pin = sha256(LIST.as_bytes());
    // First download good, then a changed list that fails the pin, then the server is gone.
    let (url, paths) = server(vec![
        (200, LIST.as_bytes().to_vec()),
        (200, b"evil.example.com\n".to_vec()),
    ]);
    let clock = Arc::new(FakeClock::at_unix(1_800_000_000));
    let mut feeds = Feeds::start(&[download(&url, &cache, Some(pin), None)], clock);
    let (name, set) = tokio::time::timeout(Duration::from_secs(10), feeds.next())
        .await
        .expect("the first download arrives")
        .unwrap();
    assert_eq!(name, "feed");
    assert!(set.matches_host("bad.example.com"));
    assert_eq!(std::fs::read_to_string(&cache).unwrap(), LIST);

    // The second fetch is refused: nothing new arrives and the copy stays.
    let deadline = tokio::time::Instant::now() + Duration::from_secs(10);
    while paths.lock().unwrap().len() < 2 {
        assert!(tokio::time::Instant::now() < deadline, "no second fetch");
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
    assert!(
        tokio::time::timeout(Duration::from_millis(300), feeds.next())
            .await
            .is_err(),
        "a refused list is not handed over"
    );
    assert_eq!(std::fs::read_to_string(&cache).unwrap(), LIST);
    drop(feeds);
}
