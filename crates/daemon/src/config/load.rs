//! Finding, parsing and checking the config file.

use std::collections::HashSet;
use std::ffi::OsString;
use std::fmt;
use std::ops::Range;
use std::path::{Path, PathBuf};

use scribe_core::platform::Os;
use scribe_module_api::{ConfigDoc, ModuleError};
use scribe_storage_api::EventKind;

use crate::modules::ModuleSpec;

use super::model::{Backend, Config, LogOutput, StorageKind, CONFIG_VERSION};

/// Where the config came from.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Source {
    File(PathBuf),
    /// No file found: built-in defaults.
    BuiltIn,
}

impl fmt::Display for Source {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Source::File(path) => write!(f, "{}", path.display()),
            Source::BuiltIn => f.write_str("built-in defaults"),
        }
    }
}

/// A config problem, with the position in the file when known.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ConfigError {
    pub source: String,
    pub line: Option<usize>,
    pub column: Option<usize>,
    pub message: String,
}

impl ConfigError {
    pub fn new(source: &Source, message: impl Into<String>) -> Self {
        Self {
            source: source.to_string(),
            line: None,
            column: None,
            message: message.into(),
        }
    }

    /// An error at byte `span` of `text`. An empty span at 0 (a built-in default) has no position.
    pub fn at(source: &Source, text: &str, span: Range<usize>, message: impl Into<String>) -> Self {
        let mut err = Self::new(source, message);
        if span != (0..0) || !text.is_empty() {
            let (line, column) = line_column(text, span.start);
            err.line = Some(line);
            err.column = Some(column);
        }
        err
    }
}

impl fmt::Display for ConfigError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match (self.line, self.column) {
            (Some(line), Some(column)) => write!(
                f,
                "{}, line {line}, column {column}: {}",
                self.source, self.message
            ),
            _ => write!(f, "{}: {}", self.source, self.message),
        }
    }
}

impl std::error::Error for ConfigError {}

/// 1-based line and column of byte `offset`.
fn line_column(text: &str, offset: usize) -> (usize, usize) {
    let before = &text[..offset.min(text.len())];
    let line = before.matches('\n').count() + 1;
    let column = before.rsplit('\n').next().map_or(0, |l| l.chars().count()) + 1;
    (line, column)
}

/// Picks the config file: `--config`, then `SCRIBE_CONFIG`, then the OS default if it exists,
/// otherwise built-in defaults. An explicitly named file must exist.
pub fn discover(
    flag: Option<&Path>,
    env: Option<OsString>,
    default_file: &Path,
) -> Result<Source, ConfigError> {
    let named = |path: PathBuf, origin: &str| {
        if path.is_file() {
            Ok(Source::File(path))
        } else {
            Err(ConfigError::new(
                &Source::File(path),
                format!("config file not found (named by {origin})"),
            ))
        }
    };
    if let Some(path) = flag {
        return named(path.to_path_buf(), "--config");
    }
    if let Some(path) = env.filter(|p| !p.is_empty()) {
        return named(PathBuf::from(path), "SCRIBE_CONFIG");
    }
    if default_file.is_file() {
        return Ok(Source::File(default_file.to_path_buf()));
    }
    Ok(Source::BuiltIn)
}

/// What the checks need to know about this build and host.
#[derive(Debug, Clone)]
pub struct Context {
    pub os: Os,
    /// Storage kinds built into this binary (Cargo features).
    pub storage_kinds: Vec<&'static str>,
    /// Modules built into this binary (Cargo features).
    pub modules: Vec<ModuleSpec>,
}

/// Reads and checks the config from `source`. Returns the config and its text (empty for built-in).
pub fn load(source: &Source, ctx: &Context) -> Result<(Config, String), ConfigError> {
    let text = match source {
        Source::BuiltIn => String::new(),
        Source::File(path) => std::fs::read_to_string(path)
            .map_err(|e| ConfigError::new(source, format!("cannot read config file: {e}")))?,
    };
    let config = parse(&text, source, ctx)?;
    Ok((config, text))
}

/// Parses and checks config text.
pub fn parse(text: &str, source: &Source, ctx: &Context) -> Result<Config, ConfigError> {
    let config: Config = toml::from_str(text).map_err(|e| {
        let span = e.span().unwrap_or(0..0);
        ConfigError::at(source, text, span, e.message().trim())
    })?;
    validate(&config, text, source, ctx)?;
    Ok(config)
}

/// A socket path (Unix) or pipe name (`\\.\pipe\…` on Windows) that doesn't depend on the
/// working directory.
fn api_socket_is_absolute(socket: &str) -> bool {
    std::path::Path::new(socket).is_absolute() || socket.starts_with(r"\\.\pipe\")
}

/// Rules that span several fields or depend on the build and OS.
pub fn validate(
    config: &Config,
    text: &str,
    source: &Source,
    ctx: &Context,
) -> Result<(), ConfigError> {
    let at = |span: Range<usize>, message: String| ConfigError::at(source, text, span, message);

    if *config.version.get_ref() != CONFIG_VERSION {
        return Err(at(
            config.version.span(),
            format!(
                "unsupported config version {}: this scribed reads version {CONFIG_VERSION}",
                config.version.get_ref()
            ),
        ));
    }

    if let Some(dir) = &config.data_dir {
        if !dir.get_ref().is_absolute() {
            return Err(at(
                dir.span(),
                format!(
                    "data_dir must be an absolute path, got \"{}\"",
                    dir.get_ref().display()
                ),
            ));
        }
    }

    let socket = config.api.socket.get_ref();
    if !socket.is_empty() && !api_socket_is_absolute(socket) {
        return Err(at(
            config.api.socket.span(),
            format!("api socket must be an absolute path, got \"{socket}\""),
        ));
    }
    if config.api.admin_group.get_ref().trim().is_empty() {
        return Err(at(
            config.api.admin_group.span(),
            "api admin_group must name a group".into(),
        ));
    }

    let bits = *config.policy.entropy.min_bits_per_char.get_ref();
    if !(bits > 0.0 && bits <= 8.0) {
        return Err(at(
            config.policy.entropy.min_bits_per_char.span(),
            format!(
                "min_bits_per_char {bits} is out of range: must be greater than 0 and at most 8"
            ),
        ));
    }

    for list in &config.policy.threat_lists {
        let span = list.span();
        let list = list.get_ref();
        match (&list.path, &list.url) {
            (Some(_), Some(_)) | (None, None) => {
                return Err(at(
                    span,
                    format!(
                        "threat list \"{}\" needs exactly one of `path` or `url`",
                        list.name
                    ),
                ))
            }
            (None, Some(url)) if !(url.starts_with("https://") || url.starts_with("http://")) => {
                return Err(at(
                    span,
                    format!(
                        "threat list \"{}\": url must start with https:// or http://",
                        list.name
                    ),
                ))
            }
            (Some(_), None) if list.refresh.is_some() => {
                return Err(at(
                    span,
                    format!(
                        "threat list \"{}\": `refresh` only applies to a `url`",
                        list.name
                    ),
                ))
            }
            _ => {}
        }
    }

    check_backend(config.storage.state.get_ref(), "[storage.state]", ctx)
        .map_err(|m| at(config.storage.state.span(), m))?;

    let mut names = HashSet::new();
    for sink in &config.storage.sinks {
        let span = sink.span();
        let s = sink.get_ref();
        if s.name.trim().is_empty() {
            return Err(at(span, "sink name must not be empty".into()));
        }
        if !names.insert(s.name.as_str()) {
            return Err(at(span, format!("sink name \"{}\" is used twice", s.name)));
        }
        check_backend(&s.backend(), &format!("sink \"{}\"", s.name), ctx)
            .map_err(|m| at(span, m))?;
    }

    let enabled = check_modules(config, text, source, ctx)?;
    check_module_scores(config, text, source, &enabled)?;
    let known: Vec<&str> = EventKind::CORE
        .iter()
        .map(EventKind::name)
        .chain(enabled.iter().flat_map(|m| m.record_kinds()))
        .collect();
    for sink in &config.storage.sinks {
        for name in &sink.get_ref().events {
            if !known.contains(&name.get_ref().as_str()) {
                return Err(at(
                    name.span(),
                    format!(
                        "unknown event kind \"{}\" in sink \"{}\": known kinds are {}",
                        name.get_ref(),
                        sink.get_ref().name,
                        known.join(", ")
                    ),
                ));
            }
        }
    }

    let output = *config.log.output.get_ref();
    if ctx.os == Os::Windows && output.uses_system() {
        return Err(at(
            config.log.output.span(),
            format!(
                "log output \"{}\" is not available on Windows yet: the Event Log source is registered by the installer (plan phase 13); use output = \"file\"",
                if output == LogOutput::Both { "both" } else { "system" }
            ),
        ));
    }
    if ctx.os == Os::Windows && !config.daemon.user.trim().is_empty() {
        return Err(at(
            0..0,
            "daemon.user is for Unix; on Windows the installer sets the service account (plan phase 13)".into(),
        ));
    }
    if config.log.max_size.get_ref().is_percent() {
        return Err(at(
            config.log.max_size.span(),
            "log max_size must be an absolute size such as \"50MiB\", not a percentage".into(),
        ));
    }
    Ok(())
}

/// `[modules]`: enabled ids are built in and listed once, every section names a built-in module,
/// and each enabled module accepts its section. Returns the enabled modules.
fn check_modules(
    config: &Config,
    text: &str,
    source: &Source,
    ctx: &Context,
) -> Result<Vec<ModuleSpec>, ConfigError> {
    let at = |span: Range<usize>, message: String| ConfigError::at(source, text, span, message);
    let built = || {
        let ids: Vec<_> = ctx.modules.iter().map(|m| m.id).collect();
        if ids.is_empty() {
            "none".to_owned()
        } else {
            ids.join(", ")
        }
    };
    let find = |id: &str| ctx.modules.iter().find(|m| m.id == id).copied();
    let enabled_span = config.modules.enabled.span();
    let written = enabled_span != (0..0);
    let mut enabled = Vec::new();
    for id in config.modules.enabled.get_ref() {
        match find(id) {
            Some(_) if enabled.iter().any(|m: &ModuleSpec| m.id == id) => {
                return Err(at(
                    enabled_span,
                    format!("module \"{id}\" is listed twice in modules.enabled"),
                ))
            }
            Some(spec) => enabled.push(spec),
            // The built-in default list may name modules this build leaves out.
            None if !written => {}
            None => {
                return Err(at(
                    enabled_span,
                    format!(
                        "module \"{id}\" is not built into this scribed (built: {}); rebuild with `--features {id}`",
                        built()
                    ),
                ))
            }
        }
    }
    for (id, section) in &config.modules.sections {
        // A built-in default section (no span) for a module this build leaves out is fine.
        if find(id).is_none() && section.span() != (0..0) {
            return Err(at(
                section.span(),
                format!(
                    "[modules.{id}]: no module \"{id}\" is built into this scribed (built: {})",
                    built()
                ),
            ));
        }
    }
    let doc = ConfigDoc::new(text);
    for spec in &enabled {
        let mut module = (spec.make)();
        match module.configure(&doc) {
            Ok(_) => {}
            Err(ModuleError::Config(e)) => {
                let span = e.span.clone().unwrap_or(0..0);
                return Err(at(span, format!("module {}: {}", spec.id, e.message)));
            }
            Err(e) => return Err(at(0..0, format!("module {}: {e}", spec.id))),
        }
    }
    Ok(enabled)
}

/// `[policy.scores]` keys beyond the built-in signals must be `"<module>.<reason>"` for an
/// enabled module.
fn check_module_scores(
    config: &Config,
    text: &str,
    source: &Source,
    enabled: &[ModuleSpec],
) -> Result<(), ConfigError> {
    let doc = ConfigDoc::new(text);
    for key in config.policy.scores.modules.keys() {
        let span = doc
            .span_of(&["policy", "scores", key])
            .or_else(|| doc.span_of(&["policy", "scores"]))
            .unwrap_or(0..0);
        let at = |message: String| ConfigError::at(source, text, span.clone(), message);
        let Some((module, reason)) = key.split_once('.') else {
            return Err(at(format!(
                "unknown signal \"{key}\" in [policy.scores]: built-in signals are raw_ip, unusual_port, high_entropy, new_tld, new_process, threat_list; module signals are written \"<module>.<reason>\" in quotes"
            )));
        };
        if reason.is_empty() {
            return Err(at(format!(
                "signal \"{key}\" has no reason after the module id"
            )));
        }
        if !enabled.iter().any(|m| m.id == module) {
            return Err(at(format!(
                "signal \"{key}\": module \"{module}\" is not enabled (modules.enabled), so it never sends this signal"
            )));
        }
        match config.policy.scores.modules[key].as_integer() {
            Some(v) if (0..=100).contains(&v) => {}
            Some(v) => {
                return Err(at(format!(
                    "score {v} is out of range: must be between 0 and 100"
                )))
            }
            None => {
                return Err(at(format!(
                    "signal \"{key}\": the score must be a whole number between 0 and 100"
                )))
            }
        }
    }
    Ok(())
}

fn check_backend(backend: &Backend, what: &str, ctx: &Context) -> Result<(), String> {
    let kind = backend.kind.name();
    if !ctx.storage_kinds.contains(&kind) {
        return Err(format!(
            "{what}: storage kind \"{kind}\" is not built into this scribed (built: {}); rebuild with `--features {kind}`",
            ctx.storage_kinds.join(", ")
        ));
    }
    let forbid = |field: &str, present: bool| {
        if present {
            Err(format!("{what}: `{field}` is not an option of {kind}"))
        } else {
            Ok(())
        }
    };
    match backend.kind {
        StorageKind::Sqlite => {
            if backend
                .path
                .as_ref()
                .is_none_or(|p| p.as_os_str().is_empty())
            {
                return Err(format!("{what}: sqlite needs `path`"));
            }
            forbid("url", backend.url.is_some())?;
            forbid("credentials", backend.credentials.is_some())
        }
        StorageKind::Postgres => {
            match &backend.url {
                None => return Err(format!("{what}: postgres needs `url`")),
                Some(url) if !(url.starts_with("postgres://") || url.starts_with("postgresql://")) => {
                    return Err(format!("{what}: url must start with postgres:// or postgresql://"))
                }
                Some(url) if url_has_password(url) => {
                    return Err(format!(
                        "{what}: url must not contain a password; use `credentials` to name a stored secret"
                    ))
                }
                _ => {}
            }
            forbid("path", backend.path.is_some())
        }
    }
}

/// `postgres://user:secret@host/db` has a password; `postgres://user@host/db` doesn't.
fn url_has_password(url: &str) -> bool {
    let rest = url.split_once("://").map_or(url, |(_, r)| r);
    let authority = rest.split(['/', '?']).next().unwrap_or("");
    authority
        .rsplit_once('@')
        .is_some_and(|(user_info, _)| user_info.contains(':'))
}

#[cfg(test)]
mod tests {
    use super::*;

    mod functional {
        use super::*;

        #[test]
        fn line_and_column() {
            let text = "a = 1\nbb = 2\n";
            assert_eq!(line_column(text, 0), (1, 1));
            assert_eq!(line_column(text, 6), (2, 1));
            assert_eq!(line_column(text, 9), (2, 4));
        }

        #[test]
        fn spots_passwords_in_urls() {
            assert!(url_has_password("postgres://scribe:secret@db/scribe"));
            assert!(!url_has_password("postgres://scribe@db:5432/scribe"));
            assert!(!url_has_password("postgres://db/scribe?sslmode=require"));
        }
    }
}
