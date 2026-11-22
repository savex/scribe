//! scribed's log output: filter, text or JSON lines, a log file (daily or size rotation) and the
//! OS system log (journald on Linux, unified logging on macOS).
//!
//! If the log file or system log can't be used, logging falls back to stderr and the reason is
//! returned as a warning, so scribed still starts and says why.

use std::fs::{self, File, OpenOptions};
use std::io::{self, IsTerminal, Write};
use std::path::{Path, PathBuf};
use std::sync::OnceLock;

use tracing::Dispatch;
use tracing_appender::non_blocking::WorkerGuard;
use tracing_appender::rolling::{Builder as RollingBuilder, Rotation};
use tracing_subscriber::layer::SubscriberExt;
use tracing_subscriber::{fmt, reload, EnvFilter, Layer, Registry};

use crate::config::{LogFormat, LogSettings, Rotate};

type BoxedLayer = Box<dyn Layer<Registry> + Send + Sync>;

#[derive(Debug, thiserror::Error)]
pub enum LogError {
    #[error("invalid log filter \"{filter}\": {reason}")]
    Filter { filter: String, reason: String },
    #[error("a global logger is already installed")]
    AlreadySet,
}

/// Keeps background log writers alive; dropping it flushes them.
#[must_use = "dropping the guard stops log writing"]
pub struct LogGuard {
    _guards: Vec<WorkerGuard>,
}

pub struct LogSetup {
    pub dispatch: Dispatch,
    pub guard: LogGuard,
    /// Problems that made logging fall back to stderr.
    pub warnings: Vec<String>,
    /// Changes the level of this logger (config reload).
    pub level: LevelHandle,
}

/// Changes a logger's level while it runs. Does nothing when `SCRIBE_LOG` set the filter: the
/// environment wins over the config, at start and on reload.
type SetLevel = Box<dyn Fn(&str) -> Result<(), String> + Send + Sync>;

pub struct LevelHandle {
    set: SetLevel,
    from_env: bool,
}

impl LevelHandle {
    /// Apply `level` (`error` … `trace`); returns whether it changed anything.
    pub fn set(&self, level: &str) -> Result<bool, String> {
        if self.from_env {
            return Ok(false);
        }
        (self.set)(level).map(|()| true)
    }
}

static LEVEL: OnceLock<LevelHandle> = OnceLock::new();

/// Change the installed logger's level (config reload). `Ok(false)` when no logger was installed
/// by [`init`] or `SCRIBE_LOG` overrides the config.
pub fn set_level(level: &str) -> Result<bool, String> {
    match LEVEL.get() {
        Some(handle) => handle.set(level),
        None => Ok(false),
    }
}

/// Builds the logger without installing it. `filter` (from `SCRIBE_LOG`, `RUST_LOG` syntax)
/// overrides the configured level.
pub fn build(settings: &LogSettings, filter: Option<&str>) -> Result<LogSetup, LogError> {
    let from_env = filter.map(str::trim).is_some_and(|f| !f.is_empty());
    let filter_text = filter
        .map(str::trim)
        .filter(|f| !f.is_empty())
        .unwrap_or(settings.level.as_str());
    let env_filter = EnvFilter::try_new(filter_text).map_err(|e| LogError::Filter {
        filter: filter_text.into(),
        reason: e.to_string(),
    })?;

    let mut layers: Vec<BoxedLayer> = Vec::new();
    let mut guards = Vec::new();
    let mut warnings = Vec::new();
    let mut need_stderr = false;

    if settings.output.uses_file() {
        match &settings.file {
            Some(path) => match open_file(path, settings) {
                Ok(writer) => {
                    let (writer, guard) = tracing_appender::non_blocking(writer);
                    guards.push(guard);
                    layers.push(format_layer(settings.format, writer, false));
                }
                Err(e) => {
                    warnings.push(format!(
                        "cannot write log file {}: {e}; logging to stderr instead",
                        path.display()
                    ));
                    need_stderr = true;
                }
            },
            None => need_stderr = true,
        }
    }

    if settings.output.uses_system() {
        match system_layer() {
            Ok(layer) => layers.push(layer),
            Err(e) => {
                warnings.push(format!(
                    "system log not available: {e}; logging to stderr instead"
                ));
                need_stderr = true;
            }
        }
    }

    if need_stderr || layers.is_empty() {
        layers.push(stderr_layer(settings.format));
    }

    let (env_filter, handle) = reload::Layer::new(env_filter);
    let subscriber = Registry::default().with(layers).with(env_filter);
    let level = LevelHandle {
        set: Box::new(move |level: &str| {
            let filter = EnvFilter::try_new(level).map_err(|e| e.to_string())?;
            handle.reload(filter).map_err(|e| e.to_string())
        }),
        from_env,
    };
    Ok(LogSetup {
        dispatch: Dispatch::new(subscriber),
        guard: LogGuard { _guards: guards },
        warnings,
        level,
    })
}

/// Builds and installs the logger for the whole process.
pub fn init(
    settings: &LogSettings,
    filter: Option<&str>,
) -> Result<(LogGuard, Vec<String>), LogError> {
    let setup = build(settings, filter)?;
    tracing::dispatcher::set_global_default(setup.dispatch).map_err(|_| LogError::AlreadySet)?;
    let _ = LEVEL.set(setup.level);
    Ok((setup.guard, setup.warnings))
}

fn format_layer<W>(format: LogFormat, writer: W, ansi: bool) -> BoxedLayer
where
    W: for<'w> fmt::MakeWriter<'w> + Send + Sync + 'static,
{
    match format {
        LogFormat::Text => fmt::layer().with_writer(writer).with_ansi(ansi).boxed(),
        LogFormat::Json => fmt::layer()
            .json()
            .with_writer(writer)
            .with_ansi(false)
            .boxed(),
    }
}

fn stderr_layer(format: LogFormat) -> BoxedLayer {
    format_layer(format, io::stderr, io::stderr().is_terminal())
}

/// The log file writer for the configured rotation.
fn open_file(path: &Path, settings: &LogSettings) -> io::Result<Box<dyn Write + Send>> {
    let dir = path
        .parent()
        .filter(|p| !p.as_os_str().is_empty())
        .unwrap_or_else(|| Path::new("."));
    fs::create_dir_all(dir)?;
    match settings.rotate {
        Rotate::Size => Ok(Box::new(SizeRotatingFile::open(
            path,
            settings.max_size,
            settings.keep,
        )?)),
        Rotate::Daily => {
            let file_name = path
                .file_name()
                .and_then(|n| n.to_str())
                .unwrap_or("scribed.log");
            let (prefix, suffix) = file_name.rsplit_once('.').unwrap_or((file_name, ""));
            let mut builder = RollingBuilder::new()
                .rotation(Rotation::DAILY)
                .filename_prefix(prefix)
                .max_log_files(settings.keep as usize + 1);
            if !suffix.is_empty() {
                builder = builder.filename_suffix(suffix);
            }
            if cfg!(unix) {
                // `scribed.log` always points at today's `scribed.<date>.log`.
                builder = builder.latest_symlink(file_name);
            }
            builder
                .build(dir)
                .map(|w| Box::new(w) as Box<dyn Write + Send>)
                .map_err(io::Error::other)
        }
    }
}

#[cfg(target_os = "linux")]
fn system_layer() -> io::Result<BoxedLayer> {
    Ok(tracing_journald::layer()?
        .with_syslog_identifier("scribed".into())
        .boxed())
}

#[cfg(target_os = "macos")]
fn system_layer() -> io::Result<BoxedLayer> {
    Ok(tracing_oslog::OsLogger::new("com.scribe.daemon", "default").boxed())
}

#[cfg(not(any(target_os = "linux", target_os = "macos")))]
fn system_layer() -> io::Result<BoxedLayer> {
    Err(io::Error::new(
        io::ErrorKind::Unsupported,
        "no system log integration on this OS yet",
    ))
}

/// A log file that rotates by size: `scribed.log` → `scribed.log.1` → … → `scribed.log.<keep>`.
pub struct SizeRotatingFile {
    path: PathBuf,
    max_size: u64,
    keep: u32,
    file: File,
    written: u64,
}

impl SizeRotatingFile {
    pub fn open(path: &Path, max_size: u64, keep: u32) -> io::Result<Self> {
        let file = OpenOptions::new().create(true).append(true).open(path)?;
        let written = file.metadata()?.len();
        Ok(Self {
            path: path.to_path_buf(),
            max_size: max_size.max(1),
            keep: keep.max(1),
            file,
            written,
        })
    }

    fn numbered(&self, n: u32) -> PathBuf {
        let mut name = self.path.as_os_str().to_owned();
        name.push(format!(".{n}"));
        PathBuf::from(name)
    }

    fn rotate(&mut self) -> io::Result<()> {
        self.file.flush()?;
        let oldest = self.numbered(self.keep);
        if oldest.exists() {
            fs::remove_file(&oldest)?;
        }
        for n in (1..self.keep).rev() {
            let from = self.numbered(n);
            if from.exists() {
                fs::rename(&from, self.numbered(n + 1))?;
            }
        }
        fs::rename(&self.path, self.numbered(1))?;
        self.file = OpenOptions::new()
            .create(true)
            .append(true)
            .open(&self.path)?;
        self.written = 0;
        Ok(())
    }
}

impl Write for SizeRotatingFile {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        if self.written > 0 && self.written + buf.len() as u64 > self.max_size {
            self.rotate()?;
        }
        let n = self.file.write(buf)?;
        self.written += n as u64;
        Ok(n)
    }

    fn flush(&mut self) -> io::Result<()> {
        self.file.flush()
    }
}
