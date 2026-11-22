//! Tamper evidence (NFR-18, specs 12.1.1): every audit and alert record gets the next sequence
//! number and the HMAC of the record before it. A deleted row leaves a gap in the sequence; an
//! edited row no longer matches the `prev_hmac` its successor carries.
//!
//! The key is a per-install secret (`audit.key` in `data_dir`, created on first start, mode 600);
//! the last sequence number and HMAC live in `audit.chain` so the chain continues across restarts.

use std::fs;
use std::io;
use std::path::{Path, PathBuf};

use ring::hmac;
use scribe_secrets::SecretRef;
use scribe_storage_api::codec::chain_bytes;
use scribe_storage_api::{ChainLink, StoredEvent};

pub const KEY_FILE: &str = "audit.key";
pub const STATE_FILE: &str = "audit.chain";

pub struct Chain {
    key: hmac::Key,
    seq: u64,
    last: String,
    state: PathBuf,
}

/// The HMAC of one sealed record, as lowercase hex.
pub fn record_hmac(key: &hmac::Key, event: &StoredEvent) -> Option<String> {
    let link = link(event)?;
    let mut ctx = hmac::Context::with_key(key);
    ctx.update(format!("{}\n{}\n", link.seq, link.prev_hmac).as_bytes());
    ctx.update(&chain_bytes(event));
    Some(hex(ctx.sign().as_ref()))
}

fn link(event: &StoredEvent) -> Option<&ChainLink> {
    match event {
        StoredEvent::Audit(a) => a.link.as_ref(),
        StoredEvent::Alert(a) => a.link.as_ref(),
        _ => None,
    }
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

impl Chain {
    /// Open (or start) the chain in `data_dir`.
    pub fn open(data_dir: &Path) -> Result<Self, String> {
        let secret = scribe_secrets::read_or_create(&SecretRef::File(data_dir.join(KEY_FILE)), 32)
            .map_err(|e| format!("audit chain key: {e}"))?;
        let key = hmac::Key::new(hmac::HMAC_SHA256, secret.expose());
        let state = data_dir.join(STATE_FILE);
        let (seq, last) = match fs::read_to_string(&state) {
            Ok(text) => {
                let mut parts = text.split_whitespace();
                let seq = parts.next().and_then(|s| s.parse().ok());
                let last = parts.next().unwrap_or("").to_owned();
                match seq {
                    Some(seq) => (seq, last),
                    None => return Err(format!("{}: unreadable chain state", state.display())),
                }
            }
            Err(e) if e.kind() == io::ErrorKind::NotFound => (0, String::new()),
            Err(e) => return Err(format!("{}: {e}", state.display())),
        };
        Ok(Self {
            key,
            seq,
            last,
            state,
        })
    }

    /// The key, for verification.
    pub fn key(&self) -> &hmac::Key {
        &self.key
    }

    /// Sequence number of the last sealed record (0 before the first).
    pub fn seq(&self) -> u64 {
        self.seq
    }

    /// Link every audit and alert record in `events`, in order, and save the chain state.
    pub fn seal(&mut self, events: &mut [StoredEvent]) -> io::Result<()> {
        let mut sealed = false;
        for event in events.iter_mut() {
            let slot = match event {
                StoredEvent::Audit(a) => &mut a.link,
                StoredEvent::Alert(a) => &mut a.link,
                _ => continue,
            };
            *slot = Some(ChainLink {
                seq: self.seq + 1,
                prev_hmac: self.last.clone(),
            });
            self.seq += 1;
            self.last = record_hmac(&self.key, event).expect("just linked");
            sealed = true;
        }
        if sealed {
            self.save()?;
        }
        Ok(())
    }

    fn save(&self) -> io::Result<()> {
        let tmp = self.state.with_extension("chain.tmp");
        fs::write(&tmp, format!("{} {}\n", self.seq, self.last))?;
        fs::rename(&tmp, &self.state)
    }
}

/// What [`verify`] found wrong.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ChainProblem {
    /// Records `after + 1 .. next` are missing (deleted, or never stored).
    Gap { after: u64, next: u64 },
    /// Record `seq` doesn't carry the HMAC of the record before it: one of the two was edited.
    Mismatch { seq: u64 },
    /// An audit or alert record without a chain link (written before the chain existed).
    Unlinked,
}

/// Check sealed audit and alert records, in sequence order (other events are ignored).
pub fn verify(key: &hmac::Key, events: &[StoredEvent]) -> Vec<ChainProblem> {
    let mut linked: Vec<&StoredEvent> = Vec::new();
    let mut problems = Vec::new();
    for e in events {
        match e {
            StoredEvent::Audit(_) | StoredEvent::Alert(_) => match link(e) {
                Some(_) => linked.push(e),
                None => problems.push(ChainProblem::Unlinked),
            },
            _ => {}
        }
    }
    linked.sort_by_key(|e| link(e).map(|l| l.seq));
    for pair in linked.windows(2) {
        let (a, b) = (link(pair[0]).unwrap(), link(pair[1]).unwrap());
        if b.seq != a.seq + 1 {
            problems.push(ChainProblem::Gap {
                after: a.seq,
                next: b.seq,
            });
        } else if record_hmac(key, pair[0]).as_deref() != Some(b.prev_hmac.as_str()) {
            problems.push(ChainProblem::Mismatch { seq: b.seq });
        }
    }
    problems
}
