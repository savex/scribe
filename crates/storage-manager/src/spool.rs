//! On-disk spool for one event sink while it is down (FR-19, specs 8.4).
//!
//! Layout: `<spool dir>/<sink name>/<sequence>.jsonl`, one stored row (`scribe_storage_api::codec`)
//! per line, oldest segment first. Replay is at-least-once: a crash during replay can write some
//! events twice, never lose them. Limits are shared by all sinks ([`SpoolBudget`]): the total size
//! stays under `max_size` and free disk space above `min_free`; when a new batch doesn't fit, the
//! sink's oldest segments are dropped first, and the drops are counted.

use std::fs::{self, File, OpenOptions};
use std::io::{self, BufRead, BufReader, Write};
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};

use scribe_storage_api::codec::{decode, encode, from_millis, to_millis, Row};
use scribe_storage_api::StoredEvent;
use serde_json::{json, Value};

/// Free bytes on the volume holding a path (a function so tests can fake a full disk).
pub type FreeSpace = Arc<dyn Fn(&Path) -> io::Result<u64> + Send + Sync>;

/// Spool settings shared by every sink.
#[derive(Clone)]
pub struct SpoolOptions {
    pub dir: PathBuf,
    /// Total size of all spools.
    pub max_size: u64,
    /// Stop growing when the volume has less free space than this.
    pub min_free: u64,
    /// Start a new segment file at this size.
    pub segment_max: u64,
    pub free_space: FreeSpace,
}

impl SpoolOptions {
    pub fn new(dir: impl Into<PathBuf>, max_size: u64, min_free: u64) -> Self {
        Self {
            dir: dir.into(),
            max_size,
            min_free,
            segment_max: 4 << 20,
            free_space: Arc::new(|p: &Path| {
                scribe_core::platform::volume_space(p).map(|v| v.available)
            }),
        }
    }
}

/// Bytes used by all spools together.
pub(crate) struct SpoolBudget {
    options: SpoolOptions,
    used: Mutex<u64>,
}

impl SpoolBudget {
    pub(crate) fn new(options: SpoolOptions) -> Arc<Self> {
        Arc::new(Self {
            options,
            used: Mutex::new(0),
        })
    }

    fn fits(&self, extra: u64) -> bool {
        let used = *self.used.lock().unwrap();
        if used + extra > self.options.max_size {
            return false;
        }
        match (self.options.free_space)(&self.options.dir) {
            Ok(free) => free.saturating_sub(extra) >= self.options.min_free,
            Err(_) => true,
        }
    }

    fn add(&self, n: u64) {
        *self.used.lock().unwrap() += n;
    }

    fn sub(&self, n: u64) {
        let mut used = self.used.lock().unwrap();
        *used = used.saturating_sub(n);
    }
}

struct Segment {
    seq: u64,
    path: PathBuf,
    bytes: u64,
    events: u64,
}

/// What an append did.
#[derive(Debug, Default, PartialEq, Eq)]
pub(crate) struct Appended {
    pub(crate) stored: u64,
    /// Events dropped to make room: old spooled ones, or the new batch if nothing older is left.
    pub(crate) dropped: u64,
}

pub(crate) struct Spool {
    dir: PathBuf,
    budget: Arc<SpoolBudget>,
    segments: Vec<Segment>,
    next_seq: u64,
}

fn row_json(e: &StoredEvent) -> String {
    let r = encode(e);
    json!({
        "ts": to_millis(r.ts),
        "kind": r.kind,
        "module": r.module,
        "host": r.host,
        "schema": r.schema,
        "payload": r.payload,
    })
    .to_string()
}

fn parse_row(line: &str) -> Option<StoredEvent> {
    let v: Value = serde_json::from_str(line).ok()?;
    let row = Row {
        ts: from_millis(v.get("ts")?.as_i64()?),
        kind: v.get("kind")?.as_str()?.to_owned(),
        module: v.get("module").and_then(Value::as_str).map(str::to_owned),
        host: v.get("host").and_then(Value::as_str).map(str::to_owned),
        schema: v.get("schema")?.as_u64()? as u32,
        payload: v.get("payload")?.clone(),
    };
    decode(row).ok()
}

impl Spool {
    /// Open the spool for `sink`, picking up segments left by an earlier run.
    pub(crate) fn open(budget: Arc<SpoolBudget>, sink: &str) -> io::Result<Self> {
        let safe: String = sink
            .chars()
            .map(|c| {
                if c.is_ascii_alphanumeric() || c == '-' || c == '_' {
                    c
                } else {
                    '_'
                }
            })
            .collect();
        let dir = budget.options.dir.join(safe);
        fs::create_dir_all(&dir)?;
        let mut segments = Vec::new();
        for entry in fs::read_dir(&dir)? {
            let path = entry?.path();
            let Some(seq) = path
                .file_name()
                .and_then(|n| n.to_str())
                .and_then(|n| n.strip_suffix(".jsonl"))
                .and_then(|n| n.parse::<u64>().ok())
            else {
                continue;
            };
            let bytes = fs::metadata(&path)?.len();
            let events = BufReader::new(File::open(&path)?).lines().count() as u64;
            budget.add(bytes);
            segments.push(Segment {
                seq,
                path,
                bytes,
                events,
            });
        }
        segments.sort_by_key(|s| s.seq);
        let next_seq = segments.last().map_or(1, |s| s.seq + 1);
        Ok(Self {
            dir,
            budget,
            segments,
            next_seq,
        })
    }

    pub(crate) fn is_empty(&self) -> bool {
        self.segments.is_empty()
    }

    pub(crate) fn events(&self) -> u64 {
        self.segments.iter().map(|s| s.events).sum()
    }

    pub(crate) fn bytes(&self) -> u64 {
        self.segments.iter().map(|s| s.bytes).sum()
    }

    /// Append events after everything already spooled.
    pub(crate) fn append(&mut self, events: &[StoredEvent]) -> io::Result<Appended> {
        let mut text = String::new();
        for e in events {
            text.push_str(&row_json(e));
            text.push('\n');
        }
        let size = text.len() as u64;
        let mut out = Appended::default();
        while !self.budget.fits(size) {
            match self.drop_oldest()? {
                Some(n) => out.dropped += n,
                None => {
                    out.dropped += events.len() as u64;
                    return Ok(out);
                }
            }
        }
        let start_new = self
            .segments
            .last()
            .is_none_or(|s| s.bytes >= self.budget.options.segment_max);
        if start_new {
            let seq = self.next_seq;
            self.next_seq += 1;
            self.segments.push(Segment {
                seq,
                path: self.dir.join(format!("{seq:010}.jsonl")),
                bytes: 0,
                events: 0,
            });
        }
        let seg = self.segments.last_mut().expect("pushed above");
        let mut file = OpenOptions::new()
            .create(true)
            .append(true)
            .open(&seg.path)?;
        file.write_all(text.as_bytes())?;
        file.sync_data()?;
        seg.bytes += size;
        seg.events += events.len() as u64;
        self.budget.add(size);
        out.stored = events.len() as u64;
        Ok(out)
    }

    /// Remove the oldest segment; returns how many events it held.
    fn drop_oldest(&mut self) -> io::Result<Option<u64>> {
        if self.segments.is_empty() {
            return Ok(None);
        }
        let seg = self.segments.remove(0);
        fs::remove_file(&seg.path)?;
        self.budget.sub(seg.bytes);
        Ok(Some(seg.events))
    }

    /// The events of the oldest segment, in order, plus how many lines couldn't be read.
    pub(crate) fn oldest(&self) -> io::Result<Option<(Vec<StoredEvent>, u64)>> {
        let Some(seg) = self.segments.first() else {
            return Ok(None);
        };
        let mut events = Vec::new();
        let mut unreadable = 0;
        for line in BufReader::new(File::open(&seg.path)?).lines() {
            match parse_row(&line?) {
                Some(e) => events.push(e),
                None => unreadable += 1,
            }
        }
        Ok(Some((events, unreadable)))
    }

    /// The oldest segment was replayed up to `written` events: delete it, or keep the rest.
    pub(crate) fn consumed(&mut self, written: usize, events: &[StoredEvent]) -> io::Result<()> {
        if written >= events.len() {
            self.drop_oldest()?;
            return Ok(());
        }
        let seg = &mut self.segments[0];
        let mut text = String::new();
        for e in &events[written..] {
            text.push_str(&row_json(e));
            text.push('\n');
        }
        let tmp = seg.path.with_extension("tmp");
        fs::write(&tmp, &text)?;
        fs::rename(&tmp, &seg.path)?;
        let size = text.len() as u64;
        self.budget.sub(seg.bytes.saturating_sub(size));
        seg.bytes = size;
        seg.events = (events.len() - written) as u64;
        Ok(())
    }
}
