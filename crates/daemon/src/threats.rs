//! Threat lists (specs 8.3, 12.1.1): local files and downloads.
//!
//! - A **file** list is read at start and on reload; one that can't be read stops scribed (or
//!   rejects the reload).
//! - A **download** starts from its last good copy in `<data_dir>/threat-lists/<name>.txt`, so a
//!   restart without network keeps protecting, and is fetched again every `refresh` (default 24h)
//!   through `scribe-net` (https only, certificate checks, size cap). A new copy replaces the old
//!   one only if it passes every check: the `sha256` pin, the `minisign_key` signature from
//!   `<url>.minisig`, and `max_entries`. Anything else keeps the last good list and logs why.
//!
//! The downloads run as background tasks ([`Feeds`]) and hand verified lists to the main loop,
//! which merges every list into the policy's [`ThreatSet`].

use std::collections::BTreeMap;
use std::path::Path;
use std::sync::Arc;
use std::time::Duration;

use scribe_core::Clock;
use scribe_policy::ThreatSet;
use tokio::sync::mpsc;
use tracing::{info, warn};

use crate::config::{ThreatOrigin, ThreatSource};

/// Largest list download.
pub const MAX_DOWNLOAD: usize = 64 * 1024 * 1024;
/// Largest signature file.
const MAX_SIGNATURE: usize = 4096;
/// Wait before trying a failed download again (or `refresh`, if shorter).
pub const RETRY_AFTER: Duration = Duration::from_secs(15 * 60);
const TIMEOUT: Duration = Duration::from_secs(30);

/// Check a downloaded body against its pin and signature.
pub fn verify(
    body: &[u8],
    sha256: Option<&str>,
    minisign_key: Option<&str>,
    signature: Option<&str>,
) -> Result<(), String> {
    if let Some(want) = sha256 {
        let got = ring::digest::digest(&ring::digest::SHA256, body);
        let got: String = got.as_ref().iter().map(|b| format!("{b:02x}")).collect();
        if !got.eq_ignore_ascii_case(want.trim()) {
            return Err(format!("SHA-256 is {got}, not the pinned {want}"));
        }
    }
    if let Some(key) = minisign_key {
        let key = minisign_verify::PublicKey::from_base64(key.trim())
            .map_err(|e| format!("minisign_key: {e}"))?;
        let signature = signature.ok_or("the minisign signature is missing")?;
        let signature = minisign_verify::Signature::decode(signature)
            .map_err(|e| format!("the minisign signature can't be read: {e}"))?;
        key.verify(body, &signature, true)
            .map_err(|e| format!("the minisign signature does not match: {e}"))?;
    }
    Ok(())
}

/// Parse one list's text into its own set, refusing it when it has more than `max_entries`.
pub fn parse(source: &ThreatSource, text: &str) -> Result<(ThreatSet, usize), String> {
    let mut set = ThreatSet::default();
    let report = set.load(source.format, text);
    if set.len() > source.max_entries {
        return Err(format!(
            "{} entries, more than max_entries = {}",
            set.len(),
            source.max_entries
        ));
    }
    Ok((set, report.skipped))
}

/// Download, check and parse a list; returns its text too, for the cache.
pub fn fetch(source: &ThreatSource) -> Result<(String, ThreatSet), String> {
    let ThreatOrigin::Download {
        url,
        sha256,
        minisign_key,
        ..
    } = &source.origin
    else {
        return Err("not a download".into());
    };
    let client = scribe_net::Client::new(scribe_net::Options {
        timeout: TIMEOUT,
        max_body: MAX_DOWNLOAD,
        ..scribe_net::Options::default()
    })
    .map_err(|e| e.to_string())?;
    let get = |url: &str, max: usize| -> Result<Vec<u8>, String> {
        let r = client.get(url, &[]).map_err(|e| e.to_string())?;
        if !r.is_success() {
            return Err(format!(
                "{} answered {}",
                scribe_net::checked_url(url)
                    .map(|t| t.to_string())
                    .unwrap_or_default(),
                r.status
            ));
        }
        if r.body.len() > max {
            return Err(format!("the answer is larger than {max} bytes"));
        }
        Ok(r.body)
    };
    let body = get(url, MAX_DOWNLOAD)?;
    let signature = match minisign_key {
        Some(_) => {
            let sig = get(&signature_url(url), MAX_SIGNATURE)?;
            Some(String::from_utf8(sig).map_err(|_| "the minisign signature is not text")?)
        }
        None => None,
    };
    verify(
        &body,
        sha256.as_deref(),
        minisign_key.as_deref(),
        signature.as_deref(),
    )?;
    let text = String::from_utf8(body).map_err(|_| "the list is not UTF-8 text".to_owned())?;
    let (set, _) = parse(source, &text)?;
    Ok((text, set))
}

/// `<url>.minisig`, before any query string.
pub fn signature_url(url: &str) -> String {
    match url.split_once('?') {
        Some((path, query)) => format!("{path}.minisig?{query}"),
        None => format!("{url}.minisig"),
    }
}

/// Write the last good copy (temporary file, then rename).
pub fn save_cache(path: &Path, text: &str) -> std::io::Result<()> {
    if let Some(dir) = path.parent() {
        std::fs::create_dir_all(dir)?;
    }
    let tmp = path.with_extension("txt.new");
    std::fs::write(&tmp, text)?;
    std::fs::rename(&tmp, path)
}

/// Every list as it can be loaded now: files read (an unreadable or oversized one is an error),
/// downloads from their last good copy (absent until the first download).
pub fn load_all(sources: &[ThreatSource]) -> anyhow::Result<BTreeMap<String, ThreatSet>> {
    use anyhow::Context as _;
    let mut lists = BTreeMap::new();
    for source in sources {
        match &source.origin {
            ThreatOrigin::File(path) => {
                let text = std::fs::read_to_string(path).with_context(|| {
                    format!(
                        "cannot read threat list \"{}\" from {}",
                        source.name,
                        path.display()
                    )
                })?;
                let (set, skipped) = parse(source, &text)
                    .map_err(|e| anyhow::anyhow!("threat list \"{}\": {e}", source.name))?;
                info!(list = %source.name, entries = set.len(), skipped_lines = skipped, "threat list loaded");
                lists.insert(source.name.clone(), set);
            }
            ThreatOrigin::Download { cache, .. } => match std::fs::read_to_string(cache) {
                Ok(text) => match parse(source, &text) {
                    Ok((set, _)) => {
                        info!(list = %source.name, entries = set.len(), "threat list loaded from its last good copy");
                        lists.insert(source.name.clone(), set);
                    }
                    Err(e) => {
                        warn!(list = %source.name, "the last good copy is not usable ({e}); waiting for a download")
                    }
                },
                Err(_) => info!(list = %source.name, "threat list not downloaded yet"),
            },
        }
    }
    Ok(lists)
}

/// All lists in one set for the policy.
pub fn merged(lists: &BTreeMap<String, ThreatSet>) -> ThreatSet {
    let mut all = ThreatSet::default();
    for set in lists.values() {
        all.merge(set);
    }
    all
}

/// The background downloads; dropping it stops them.
pub struct Feeds {
    updates: mpsc::Receiver<(String, ThreatSet)>,
    tasks: Vec<tokio::task::JoinHandle<()>>,
}

impl Feeds {
    /// One task per download. The first fetch waits until the last good copy is `refresh` old
    /// (`clock` against the file's modification time), so restarts don't download each time.
    pub fn start(sources: &[ThreatSource], clock: Arc<dyn Clock>) -> Self {
        let (tx, updates) = mpsc::channel(16);
        let tasks = sources
            .iter()
            .filter(|s| matches!(s.origin, ThreatOrigin::Download { .. }))
            .map(|source| tokio::spawn(follow(source.clone(), clock.clone(), tx.clone())))
            .collect();
        Self { updates, tasks }
    }

    /// No downloads.
    pub fn none() -> Self {
        let (_, updates) = mpsc::channel(1);
        Self {
            updates,
            tasks: Vec::new(),
        }
    }

    /// The next verified list (name and entries); pending forever without downloads.
    pub async fn next(&mut self) -> Option<(String, ThreatSet)> {
        if self.tasks.is_empty() {
            return std::future::pending().await;
        }
        self.updates.recv().await
    }
}

impl Drop for Feeds {
    fn drop(&mut self) {
        for task in &self.tasks {
            task.abort();
        }
    }
}

async fn follow(
    source: ThreatSource,
    clock: Arc<dyn Clock>,
    tx: mpsc::Sender<(String, ThreatSet)>,
) {
    let ThreatOrigin::Download { refresh, cache, .. } = &source.origin else {
        return;
    };
    let (refresh, cache) = (*refresh, cache.clone());
    let age = std::fs::metadata(&cache)
        .and_then(|m| m.modified())
        .ok()
        .and_then(|modified| clock.now().duration_since(modified).ok());
    let mut wait = match age {
        Some(age) if age < refresh => refresh - age,
        _ => Duration::ZERO,
    };
    let mut failing = false;
    loop {
        tokio::time::sleep(wait).await;
        let job = source.clone();
        let result = tokio::task::spawn_blocking(move || fetch(&job))
            .await
            .unwrap_or_else(|e| Err(format!("download task failed: {e}")));
        match result {
            Ok((text, set)) => {
                if let Err(e) = save_cache(&cache, &text) {
                    warn!(list = %source.name, "cannot keep the downloaded list in {}: {e}", cache.display());
                }
                info!(list = %source.name, entries = set.len(), "threat list downloaded and checked");
                failing = false;
                if tx.send((source.name.clone(), set)).await.is_err() {
                    return;
                }
                wait = refresh;
            }
            Err(e) => {
                if !failing {
                    warn!(list = %source.name, "threat list download refused, keeping the last good list: {e}");
                }
                failing = true;
                wait = refresh.min(RETRY_AFTER);
            }
        }
    }
}
