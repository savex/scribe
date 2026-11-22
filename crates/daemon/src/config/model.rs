//! The config file as written: config format version 1, `config/scribe.toml`.
//!
//! Every `Default` here equals the value in `config/scribe.toml`; a test keeps them in sync.
//! Types reject what they can on their own (unknown keys, bad enums, out-of-range numbers), so
//! those errors carry the line from the TOML parser. Cross-field rules live in `validate`.

use std::collections::BTreeMap;
use std::num::{NonZeroU16, NonZeroU32, NonZeroU64};
use std::path::PathBuf;

use scribe_core::units::optional_duration;
use scribe_core::{HumanDuration, Mode, SizeLimit};
use serde::{de, Deserialize, Deserializer, Serialize};
use toml::Spanned;

pub const CONFIG_VERSION: u32 = 1;

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields, default)]
pub struct Config {
    pub version: Spanned<u32>,
    pub mode: Mode,
    pub profile: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub data_dir: Option<Spanned<PathBuf>>,
    pub policy: Policy,
    #[serde(skip_serializing_if = "Privacy::is_empty")]
    pub privacy: Privacy,
    pub modules: Modules,
    pub storage: Storage,
    pub log: Log,
}

impl Default for Config {
    fn default() -> Self {
        Self {
            version: Spanned::new(0..0, CONFIG_VERSION),
            mode: Mode::Learn,
            profile: "default".into(),
            data_dir: None,
            policy: Policy::default(),
            privacy: Privacy::default(),
            modules: Modules::default(),
            storage: Storage::default(),
            log: Log::default(),
        }
    }
}

// ─── Policy ─────────────────────────────────────────────────────────────────

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields, default)]
pub struct Policy {
    #[serde(with = "optional_duration")]
    pub learn_for: Option<HumanDuration>,
    pub then: AfterLearn,
    pub dedupe_window: HumanDuration,
    pub threshold: Score,
    pub scores: Scores,
    pub usual_ports: UsualPorts,
    pub entropy: Entropy,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub threat_lists: Vec<Spanned<ThreatList>>,
}

impl Default for Policy {
    fn default() -> Self {
        Self {
            learn_for: None,
            then: AfterLearn::Caution,
            dedupe_window: HumanDuration::from_secs(600),
            threshold: Score(50),
            scores: Scores::default(),
            usual_ports: UsualPorts::default(),
            entropy: Entropy::default(),
            threat_lists: vec![],
        }
    }
}

/// The mode learn mode switches to; `learn` itself is not allowed.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum AfterLearn {
    Caution,
    Alert,
}

impl From<AfterLearn> for Mode {
    fn from(m: AfterLearn) -> Self {
        match m {
            AfterLearn::Caution => Mode::Caution,
            AfterLearn::Alert => Mode::Alert,
        }
    }
}

/// A score or threshold from 0 to 100.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize)]
pub struct Score(pub u8);

impl<'de> Deserialize<'de> for Score {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        let value = i64::deserialize(deserializer)?;
        match u8::try_from(value) {
            Ok(v) if v <= 100 => Ok(Score(v)),
            _ => Err(de::Error::custom(format!(
                "score {value} is out of range: must be between 0 and 100"
            ))),
        }
    }
}

/// Built-in signal scores, plus module signals by their namespaced reason, written with quotes:
/// `"url.credentials_in_query" = 40`. The loader checks that every other key names a signal of an
/// enabled module and holds a score from 0 to 100 (`flatten` loses spans, so the loader checks
/// these values itself to report the right line).
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(default)]
pub struct Scores {
    pub raw_ip: Score,
    pub unusual_port: Score,
    pub high_entropy: Score,
    pub new_tld: Score,
    pub new_process: Score,
    pub threat_list: Score,
    #[serde(flatten)]
    pub modules: BTreeMap<String, toml::Value>,
}

impl Default for Scores {
    fn default() -> Self {
        Self {
            raw_ip: Score(60),
            unusual_port: Score(30),
            high_entropy: Score(50),
            new_tld: Score(20),
            new_process: Score(25),
            threat_list: Score(100),
            modules: BTreeMap::new(),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields, default)]
pub struct UsualPorts {
    pub tcp: Vec<NonZeroU16>,
    pub udp: Vec<NonZeroU16>,
}

fn ports(list: &[u16]) -> Vec<NonZeroU16> {
    list.iter().filter_map(|&p| NonZeroU16::new(p)).collect()
}

impl Default for UsualPorts {
    fn default() -> Self {
        Self {
            tcp: ports(&[22, 53, 80, 443, 465, 587, 853, 993, 995]),
            udp: ports(&[53, 123, 443, 853, 5353]),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields, default)]
pub struct Entropy {
    pub min_label_length: NonZeroU32,
    pub min_bits_per_char: Spanned<f64>,
}

impl Default for Entropy {
    fn default() -> Self {
        Self {
            min_label_length: NonZeroU32::new(10).unwrap(),
            min_bits_per_char: Spanned::new(0..0, 3.5),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ThreatList {
    pub name: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub path: Option<PathBuf>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub url: Option<String>,
    pub format: ThreatFormat,
    #[serde(
        default,
        with = "optional_duration",
        skip_serializing_if = "Option::is_none"
    )]
    pub refresh: Option<HumanDuration>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum ThreatFormat {
    Domains,
    Hosts,
    Ips,
}

// ─── Privacy ────────────────────────────────────────────────────────────────

#[derive(Debug, Clone, PartialEq, Default, Serialize, Deserialize)]
#[serde(deny_unknown_fields, default)]
pub struct Privacy {
    /// Deprecated: replaced by `[modules.url] query`, still read by the URL module for one minor
    /// version. Kept here so the value is checked and the deprecation can be reported.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub url_query: Option<Spanned<UrlQuery>>,
}

impl Privacy {
    pub fn is_empty(&self) -> bool {
        self.url_query.is_none()
    }
}

/// How plaintext HTTP URLs are stored; see `workfiles/specs.md` section 12.2.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum UrlQuery {
    Full,
    #[default]
    RedactValues,
    Strip,
    PathOnly,
    Hash,
}

// ─── Modules ────────────────────────────────────────────────────────────────

/// `[modules]`: which compiled-in modules run, plus one `[modules.<id>]` table per module. Each
/// module reads and checks its own table (specs 7.4.5); `validate` checks the ids.
#[derive(Debug, Clone, PartialEq)]
pub struct Modules {
    pub enabled: Spanned<Vec<String>>,
    /// `[modules.<id>]` tables as written.
    pub sections: BTreeMap<String, Spanned<toml::Value>>,
}

fn default_enabled() -> Spanned<Vec<String>> {
    Spanned::new(0..0, vec!["url".into()])
}

impl Default for Modules {
    fn default() -> Self {
        let mut url = toml::Table::new();
        url.insert("query".into(), "redact_values".into());
        Self {
            enabled: default_enabled(),
            sections: BTreeMap::from([("url".into(), Spanned::new(0..0, toml::Value::Table(url)))]),
        }
    }
}

impl<'de> Deserialize<'de> for Modules {
    fn deserialize<D: Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        let mut map = BTreeMap::<String, Spanned<toml::Value>>::deserialize(d)?;
        let enabled = match map.remove("enabled") {
            None => default_enabled(),
            Some(value) => {
                let span = value.span();
                let ids = value.into_inner().try_into::<Vec<String>>().map_err(|_| {
                    de::Error::custom("`modules.enabled` must be a list of module ids")
                })?;
                Spanned::new(span, ids)
            }
        };
        if let Some((id, _)) = map.iter().find(|(_, v)| !v.get_ref().is_table()) {
            return Err(de::Error::custom(format!(
                "`modules.{id}` must be a table ([modules.{id}])"
            )));
        }
        Ok(Self {
            enabled,
            sections: map,
        })
    }
}

impl Serialize for Modules {
    fn serialize<S: serde::Serializer>(&self, s: S) -> Result<S::Ok, S::Error> {
        use serde::ser::SerializeMap;
        let mut map = s.serialize_map(Some(1 + self.sections.len()))?;
        map.serialize_entry("enabled", self.enabled.get_ref())?;
        for (id, table) in &self.sections {
            map.serialize_entry(id, table.get_ref())?;
        }
        map.end()
    }
}

// ─── Storage ────────────────────────────────────────────────────────────────

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields, default)]
pub struct Storage {
    pub state: Spanned<Backend>,
    pub cache: Cache,
    pub buffer: Buffer,
    pub spool: Spool,
    pub sinks: Vec<Spanned<Sink>>,
}

impl Default for Storage {
    fn default() -> Self {
        Self {
            state: Spanned::new(0..0, Backend::sqlite("state.db")),
            cache: Cache::default(),
            buffer: Buffer::default(),
            spool: Spool::default(),
            sinks: vec![Spanned::new(0..0, Sink::default())],
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum StorageKind {
    #[default]
    Sqlite,
    Postgres,
}

impl StorageKind {
    pub fn name(self) -> &'static str {
        match self {
            StorageKind::Sqlite => "sqlite",
            StorageKind::Postgres => "postgres",
        }
    }
}

/// A storage backend table: `kind` plus that backend's options.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Backend {
    #[serde(default)]
    pub kind: StorageKind,
    /// SQLite database file.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub path: Option<PathBuf>,
    /// PostgreSQL connection string without password.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub url: Option<String>,
    /// PostgreSQL secret reference: `keychain:`, `dpapi:`, `secret-service:` or `file:`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub credentials: Option<String>,
}

impl Backend {
    pub fn sqlite(path: &str) -> Self {
        Self {
            kind: StorageKind::Sqlite,
            path: Some(path.into()),
            url: None,
            credentials: None,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields, default)]
pub struct Cache {
    pub max_hosts: NonZeroU64,
    pub max_memory: SizeLimit,
}

impl Default for Cache {
    fn default() -> Self {
        Self {
            max_hosts: NonZeroU64::new(50_000).unwrap(),
            max_memory: SizeLimit::mib(32),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields, default)]
pub struct Buffer {
    pub max_events: NonZeroU64,
    pub max_memory: SizeLimit,
}

impl Default for Buffer {
    fn default() -> Self {
        Self {
            max_events: NonZeroU64::new(50_000).unwrap(),
            max_memory: SizeLimit::mib(32),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields, default)]
pub struct Spool {
    pub dir: PathBuf,
    pub max_size: SizeLimit,
    pub min_free_disk: SizeLimit,
}

impl Default for Spool {
    fn default() -> Self {
        Self {
            dir: "spool".into(),
            max_size: SizeLimit::mib(512),
            min_free_disk: SizeLimit::Percent(5.0),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Sink {
    pub name: String,
    #[serde(default)]
    pub kind: StorageKind,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub path: Option<PathBuf>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub url: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub credentials: Option<String>,
    /// Event kind names (`flow`, `alert`, `audit`, `metric`, module kinds like `url.request`);
    /// checked in `validate`. Empty means all kinds.
    #[serde(default)]
    pub events: Vec<Spanned<String>>,
    #[serde(default = "default_retention", with = "optional_duration")]
    pub retention: Option<HumanDuration>,
    #[serde(default = "default_batch_events")]
    pub batch_max_events: NonZeroU32,
    #[serde(default = "default_batch_wait")]
    pub batch_max_wait: HumanDuration,
}

fn default_retention() -> Option<HumanDuration> {
    Some(HumanDuration::from_secs(30 * 86_400))
}

fn default_batch_events() -> NonZeroU32 {
    NonZeroU32::new(500).unwrap()
}

fn default_batch_wait() -> HumanDuration {
    HumanDuration::from_secs(1)
}

impl Default for Sink {
    fn default() -> Self {
        Self {
            name: "local-history".into(),
            kind: StorageKind::Sqlite,
            path: Some("events.db".into()),
            url: None,
            credentials: None,
            events: vec![],
            retention: default_retention(),
            batch_max_events: default_batch_events(),
            batch_max_wait: default_batch_wait(),
        }
    }
}

impl Sink {
    /// The backend part of this sink.
    pub fn backend(&self) -> Backend {
        Backend {
            kind: self.kind,
            path: self.path.clone(),
            url: self.url.clone(),
            credentials: self.credentials.clone(),
        }
    }
}

// ─── Logging ────────────────────────────────────────────────────────────────

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields, default)]
pub struct Log {
    pub level: LogLevel,
    pub format: LogFormat,
    pub output: Spanned<LogOutput>,
    /// `None` = OS default; `""` = stderr only.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub file: Option<PathBuf>,
    pub rotate: Rotate,
    pub max_size: Spanned<SizeLimit>,
    pub keep: NonZeroU32,
}

impl Default for Log {
    fn default() -> Self {
        Self {
            level: LogLevel::Info,
            format: LogFormat::Text,
            output: Spanned::new(0..0, LogOutput::File),
            file: None,
            rotate: Rotate::Daily,
            max_size: Spanned::new(0..0, SizeLimit::mib(50)),
            keep: NonZeroU32::new(14).unwrap(),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum LogLevel {
    Error,
    Warn,
    Info,
    Debug,
    Trace,
}

impl LogLevel {
    pub fn as_str(self) -> &'static str {
        match self {
            LogLevel::Error => "error",
            LogLevel::Warn => "warn",
            LogLevel::Info => "info",
            LogLevel::Debug => "debug",
            LogLevel::Trace => "trace",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum LogFormat {
    Text,
    Json,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum LogOutput {
    File,
    System,
    Both,
}

impl LogOutput {
    pub fn uses_file(self) -> bool {
        matches!(self, LogOutput::File | LogOutput::Both)
    }

    pub fn uses_system(self) -> bool {
        matches!(self, LogOutput::System | LogOutput::Both)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Rotate {
    Daily,
    Size,
}
