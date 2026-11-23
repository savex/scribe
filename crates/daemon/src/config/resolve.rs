//! Turns a checked config into runtime settings: absolute paths, byte limits, storage config.

use std::collections::BTreeMap;
use std::io;
use std::path::{Path, PathBuf};

use scribe_core::platform::{self, DefaultPaths};
use scribe_core::units::human_bytes;
use scribe_core::{Mode, SizeLimit};
use scribe_module_api::ConfigDoc;
use scribe_policy::{PolicyConfig, Scores, ThreatFormat, UsualPorts};
use scribe_storage_api::{BackendOptions, EventKind};
use scribe_storage_manager::{BackendConfig, SinkConfig, StorageConfig};
use toml::Spanned;

use super::load::{ConfigError, Context, Source};
use super::model::{Backend, Config, LogFormat, LogLevel, LogOutput, Rotate, StorageKind};

/// Host facts needed to resolve percentages; a trait so tests can supply fixed numbers.
pub trait SystemFacts {
    fn total_memory(&self) -> io::Result<u64>;
    fn volume_total(&self, path: &Path) -> io::Result<u64>;
}

/// The real host.
pub struct HostFacts;

impl SystemFacts for HostFacts {
    fn total_memory(&self) -> io::Result<u64> {
        platform::total_memory()
    }

    fn volume_total(&self, path: &Path) -> io::Result<u64> {
        platform::volume_space(path).map(|v| v.total)
    }
}

/// Cache, buffer and spool limits in absolute numbers.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Limits {
    pub cache_hosts: u64,
    pub cache_memory: u64,
    pub buffer_events: u64,
    pub buffer_memory: u64,
    pub spool_dir: PathBuf,
    pub spool_max_size: u64,
    pub spool_min_free: u64,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LogSettings {
    pub level: LogLevel,
    pub format: LogFormat,
    pub output: LogOutput,
    /// `None` writes the file part to stderr.
    pub file: Option<PathBuf>,
    pub rotate: Rotate,
    pub max_size: u64,
    pub keep: u32,
}

/// Everything scribed needs from its config, resolved for this host.
#[derive(Debug, Clone)]
pub struct Settings {
    pub source: Source,
    /// The checked config as written (relative paths, percentages).
    pub config: Config,
    pub data_dir: PathBuf,
    /// Where the local API listens: `[api] socket`, or the OS default.
    pub api_socket: PathBuf,
    pub mode: Mode,
    pub profile: String,
    pub storage: StorageConfig,
    pub limits: Limits,
    pub log: LogSettings,
    /// How each percentage was resolved, for the startup log.
    pub notes: Vec<String>,
    /// Problems worth a warning that don't stop scribed (deprecated keys).
    pub warnings: Vec<String>,
    /// The config file text (empty for built-in defaults); modules read their sections from it.
    pub text: String,
    /// Enabled modules and the settings each reports (`Module::effective_config`).
    pub modules: BTreeMap<String, toml::Table>,
}

/// Configure every enabled module from `text` (already checked) and collect what it reports.
pub fn module_settings(
    config: &Config,
    text: &str,
    ctx: &Context,
) -> BTreeMap<String, toml::Table> {
    let doc = ConfigDoc::new(text);
    ctx.modules
        .iter()
        .filter(|m| config.modules.enabled.get_ref().iter().any(|id| id == m.id))
        .map(|spec| {
            let mut module = (spec.make)();
            let _ = module.configure(&doc);
            (
                spec.id.to_owned(),
                module.effective_config().unwrap_or_default(),
            )
        })
        .collect()
}

pub fn resolve(
    config: Config,
    source: Source,
    defaults: &DefaultPaths,
    facts: &dyn SystemFacts,
) -> Result<Settings, ConfigError> {
    let data_dir = config
        .data_dir
        .as_ref()
        .map(|d| d.get_ref().clone())
        .unwrap_or_else(|| defaults.data_dir.clone());
    let abs = |p: &Path| absolute(&data_dir, p);
    let mut notes = Vec::new();

    let mut memory = |limit: SizeLimit, what: &str| -> Result<u64, ConfigError> {
        let SizeLimit::Percent(_) = limit else {
            return Ok(limit.resolve(0));
        };
        let total = facts.total_memory().map_err(|e| {
            ConfigError::new(
                &source,
                format!("cannot read total memory to resolve {what} = \"{limit}\": {e}"),
            )
        })?;
        let bytes = limit.resolve(total);
        notes.push(format!(
            "{what} = {limit} of {} RAM = {}",
            human_bytes(total),
            human_bytes(bytes)
        ));
        Ok(bytes)
    };
    let cache_memory = memory(config.storage.cache.max_memory, "storage.cache.max_memory")?;
    let buffer_memory = memory(
        config.storage.buffer.max_memory,
        "storage.buffer.max_memory",
    )?;

    let spool_dir = abs(&config.storage.spool.dir);
    let mut disk = |limit: SizeLimit, what: &str| -> Result<u64, ConfigError> {
        let SizeLimit::Percent(_) = limit else {
            return Ok(limit.resolve(0));
        };
        let total = facts.volume_total(&spool_dir).map_err(|e| {
            ConfigError::new(
                &source,
                format!(
                    "cannot read the size of the volume holding {} to resolve {what} = \"{limit}\": {e}",
                    spool_dir.display()
                ),
            )
        })?;
        let bytes = limit.resolve(total);
        notes.push(format!(
            "{what} = {limit} of a {} volume = {}",
            human_bytes(total),
            human_bytes(bytes)
        ));
        Ok(bytes)
    };
    let spool_max_size = disk(config.storage.spool.max_size, "storage.spool.max_size")?;
    let spool_min_free = disk(
        config.storage.spool.min_free_disk,
        "storage.spool.min_free_disk",
    )?;

    let storage = StorageConfig {
        state: backend_config(config.storage.state.get_ref(), &abs),
        sinks: config
            .storage
            .sinks
            .iter()
            .map(|s| {
                let s = s.get_ref();
                SinkConfig {
                    name: s.name.clone(),
                    backend: backend_config(&s.backend(), &abs),
                    events: s
                        .events
                        .iter()
                        .filter_map(|e| EventKind::parse(e.get_ref()))
                        .collect(),
                    retention: s.retention.map(|d| d.get()),
                    batch_max_events: s.batch_max_events.get(),
                    batch_max_wait: s.batch_max_wait.get(),
                }
            })
            .collect(),
    };

    let log_cfg = &config.log;
    let log = LogSettings {
        level: log_cfg.level,
        format: log_cfg.format,
        output: *log_cfg.output.get_ref(),
        file: match &log_cfg.file {
            None => Some(defaults.log_file.clone()),
            Some(p) if p.as_os_str().is_empty() => None,
            Some(p) => Some(abs(p)),
        },
        rotate: log_cfg.rotate,
        max_size: log_cfg.max_size.get_ref().resolve(0),
        keep: log_cfg.keep.get(),
    };

    let mut warnings = Vec::new();
    if config.daemon.max_hibernate.is_none() {
        warnings.push(
            "daemon.max_hibernate is unlimited: `scribe daemon hibernate` can silence scribed until someone wakes it up".to_owned(),
        );
    }
    if let Some(q) = &config.privacy.url_query {
        let value = toml::Value::try_from(q.get_ref())
            .ok()
            .and_then(|v| v.as_str().map(str::to_owned))
            .unwrap_or_default();
        warnings.push(format!(
            "privacy.url_query is deprecated: write `[modules.url] query = \"{value}\"` instead (the old key is read for one more minor version)"
        ));
    }

    let api_socket = match config.api.socket.get_ref().as_str() {
        "" => PathBuf::from(scribe_api::default_socket()),
        socket => PathBuf::from(socket),
    };
    Ok(Settings {
        api_socket,
        limits: Limits {
            cache_hosts: config.storage.cache.max_hosts.get(),
            cache_memory,
            buffer_events: config.storage.buffer.max_events.get(),
            buffer_memory,
            spool_dir,
            spool_max_size,
            spool_min_free,
        },
        mode: config.mode,
        profile: config.profile.clone(),
        storage,
        log,
        notes,
        warnings,
        text: String::new(),
        modules: BTreeMap::new(),
        data_dir,
        config,
        source,
    })
}

fn absolute(base: &Path, p: &Path) -> PathBuf {
    if p.is_absolute() {
        p.to_path_buf()
    } else {
        base.join(p)
    }
}

fn backend_config(b: &Backend, abs: &dyn Fn(&Path) -> PathBuf) -> BackendConfig {
    let mut options = BackendOptions::new();
    if let Some(path) = &b.path {
        options.insert("path".into(), abs(path).to_string_lossy().into_owned());
    }
    if let Some(url) = &b.url {
        options.insert("url".into(), url.clone());
    }
    if let Some(credentials) = &b.credentials {
        options.insert("credentials".into(), credentials.clone());
    }
    BackendConfig {
        kind: b.kind.name().into(),
        options,
    }
}

impl Settings {
    /// What the policy engine needs (`mode` and `[policy]`).
    pub fn policy_config(&self) -> PolicyConfig {
        let p = &self.config.policy;
        let s = &p.scores;
        PolicyConfig {
            mode: self.mode,
            learn_for: p.learn_for.map(|d| d.get()),
            then: p.then.into(),
            dedupe_window: p.dedupe_window.get(),
            threshold: p.threshold.0,
            scores: Scores {
                raw_ip: s.raw_ip.0,
                unusual_port: s.unusual_port.0,
                high_entropy: s.high_entropy.0,
                new_tld: s.new_tld.0,
                new_process: s.new_process.0,
                threat_list: s.threat_list.0,
                modules: s
                    .modules
                    .iter()
                    .filter_map(|(k, v)| Some((k.clone(), u8::try_from(v.as_integer()?).ok()?)))
                    .collect(),
            },
            usual_ports: UsualPorts {
                tcp: p.usual_ports.tcp.iter().map(|p| p.get()).collect(),
                udp: p.usual_ports.udp.iter().map(|p| p.get()).collect(),
            },
            entropy_min_length: p.entropy.min_label_length.get() as usize,
            entropy_min_bits: *p.entropy.min_bits_per_char.get_ref(),
        }
    }

    /// Threat lists to read from files, with absolute paths. Lists with a `url` are downloaded
    /// from phase 11 on; until then they are skipped (returned in the second list).
    pub fn threat_files(&self) -> (Vec<(String, PathBuf, ThreatFormat)>, Vec<String>) {
        let mut files = Vec::new();
        let mut skipped = Vec::new();
        for list in &self.config.policy.threat_lists {
            let list = list.get_ref();
            let format = match list.format {
                super::model::ThreatFormat::Domains => ThreatFormat::Domains,
                super::model::ThreatFormat::Hosts => ThreatFormat::Hosts,
                super::model::ThreatFormat::Ips => ThreatFormat::Ips,
            };
            match &list.path {
                Some(path) => {
                    files.push((list.name.clone(), absolute(&self.data_dir, path), format))
                }
                None => skipped.push(list.name.clone()),
            }
        }
        (files, skipped)
    }

    /// The config as scribed will use it: data_dir, log file and every path made absolute.
    pub fn effective(&self) -> Config {
        let abs = |p: &Path| absolute(&self.data_dir, p);
        let mut c = self.config.clone();
        c.data_dir = Some(Spanned::new(0..0, self.data_dir.clone()));
        c.log.file = Some(self.log.file.clone().unwrap_or_default());
        c.storage.spool.dir = self.limits.spool_dir.clone();
        c.api.socket = Spanned::new(0..0, self.api_socket.display().to_string());
        let fix = |kind: StorageKind, path: &mut Option<PathBuf>| {
            if kind == StorageKind::Sqlite {
                *path = path.as_deref().map(abs);
            }
        };
        let mut state = c.storage.state.get_ref().clone();
        fix(state.kind, &mut state.path);
        c.storage.state = Spanned::new(0..0, state);
        c.storage.sinks = c
            .storage
            .sinks
            .iter()
            .map(|s| {
                let mut s = s.get_ref().clone();
                fix(s.kind, &mut s.path);
                Spanned::new(0..0, s)
            })
            .collect();
        c.policy.threat_lists = c
            .policy
            .threat_lists
            .iter()
            .map(|t| {
                let mut t = t.get_ref().clone();
                t.path = t.path.as_deref().map(abs);
                Spanned::new(0..0, t)
            })
            .collect();
        if !self.modules.is_empty() {
            // Each module reports what it uses; the deprecated key has been folded in.
            c.privacy = Default::default();
            c.modules.sections = self
                .modules
                .iter()
                .map(|(id, t)| {
                    (
                        id.clone(),
                        Spanned::new(0..0, toml::Value::Table(t.clone())),
                    )
                })
                .collect();
        }
        c
    }

    /// `effective()` as TOML, headed by where it came from and how percentages were resolved.
    pub fn effective_toml(&self) -> String {
        let mut out = format!(
            "# Effective scribed configuration (source: {})\n",
            self.source
        );
        for note in &self.notes {
            out.push_str(&format!("# {note}\n"));
        }
        for warning in &self.warnings {
            out.push_str(&format!("# warning: {warning}\n"));
        }
        out.push('\n');
        out.push_str(
            &toml::to_string_pretty(&self.effective())
                .expect("config types always serialize to TOML"),
        );
        out
    }

    /// One line per setting worth logging at startup.
    pub fn summary(&self) -> Vec<String> {
        let mut lines = vec![
            format!("config: {}", self.source),
            format!("mode: {}, profile: {}", self.mode, self.profile),
            format!("data dir: {}", self.data_dir.display()),
            format!(
                "state store: {} {}",
                self.storage.state.kind,
                describe_options(&self.storage.state.options)
            ),
        ];
        for sink in &self.storage.sinks {
            lines.push(format!(
                "event sink \"{}\": {} {}",
                sink.name,
                sink.backend.kind,
                describe_options(&sink.backend.options)
            ));
        }
        let enabled = self.config.modules.enabled.get_ref();
        lines.push(if enabled.is_empty() {
            "modules: none".to_owned()
        } else {
            format!("modules: {}", enabled.join(", "))
        });
        let l = &self.limits;
        lines.push(format!(
            "cache: {} hosts / {}; buffer: {} events / {}; spool: {} max, {} kept free, in {}",
            l.cache_hosts,
            human_bytes(l.cache_memory),
            l.buffer_events,
            human_bytes(l.buffer_memory),
            human_bytes(l.spool_max_size),
            human_bytes(l.spool_min_free),
            l.spool_dir.display()
        ));
        lines.extend(self.notes.iter().cloned());
        lines
    }
}

/// `path=/var/lib/scribe/state.db`; credentials are never printed.
fn describe_options(options: &BackendOptions) -> String {
    let mut parts: Vec<String> = options
        .iter()
        .map(|(k, v)| {
            if k == "credentials" {
                format!("{k}=<secret>")
            } else {
                format!("{k}={v}")
            }
        })
        .collect();
    parts.sort();
    parts.join(" ")
}
