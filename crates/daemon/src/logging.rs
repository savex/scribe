//! scribed's log output: filter, text or JSON lines, a log file (daily or size rotation) and the
//! OS system log (journald on Linux, unified logging on macOS).
//!
//! If the log file or system log can't be used, logging falls back to stderr and the reason is
//! returned as a warning, so scribed still starts and says why.

use std::fs::{self, File, OpenOptions};
use std::io::{self, IsTerminal, Write};
use std::path::{Path, PathBuf};

use tracing::Dispatch;
use tracing_appender::non_blocking::WorkerGuard;
use tracing_appender::rolling::{Builder as RollingBuilder, Rotation};
use tracing_subscriber::layer::SubscriberExt;
use tracing_subscriber::{fmt, EnvFilter, Layer, Registry};

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
}

/// Builds the logger without installing it. `filter` (from `SCRIBE_LOG`, `RUST_LOG` syntax)
/// overrides the configured level.
pub fn build(settings: &LogSettings, filter: Option<&str>) -> Result<LogSetup, LogError> {
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

    let subscriber = Registry::default().with(layers).with(env_filter);
    Ok(LogSetup {
        dispatch: Dispatch::new(subscriber),
        guard: LogGuard { _guards: guards },
        warnings,
    })
}

/// Builds and installs the logger for the whole process.
pub fn init(
    settings: &LogSettings,
    filter: Option<&str>,
) -> Result<(LogGuard, Vec<String>), LogError> {
    let setup = build(settings, filter)?;
    tracing::dispatcher::set_global_default(setup.dispatch).map_err(|_| LogError::AlreadySet)?;
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::{LogLevel, LogOutput};

    fn settings(file: Option<PathBuf>) -> LogSettings {
        LogSettings {
            level: LogLevel::Info,
            format: LogFormat::Text,
            output: LogOutput::File,
            file,
            rotate: Rotate::Size,
            max_size: 1 << 20,
            keep: 2,
        }
    }

    /// Logs through `s`, drops the logger to flush it, and returns all text written under `dir`.
    fn log_and_read(s: &LogSettings, filter: Option<&str>, dir: &Path) -> (String, Vec<String>) {
        let setup = build(s, filter).unwrap();
        tracing::dispatcher::with_default(&setup.dispatch, || {
            tracing::debug!("debug line");
            tracing::info!(host = "api.example.com", "info line");
            tracing::warn!("warn line");
        });
        let warnings = setup.warnings.clone();
        drop(setup);
        let mut text = String::new();
        for entry in fs::read_dir(dir).unwrap() {
            let path = entry.unwrap().path();
            if path.is_file() {
                text.push_str(&fs::read_to_string(path).unwrap());
            }
        }
        (text, warnings)
    }

    mod functional {
        use super::*;

        #[test]
        fn writes_text_at_the_configured_level() {
            let dir = tempfile::tempdir().unwrap();
            let s = settings(Some(dir.path().join("scribed.log")));
            let (text, warnings) = log_and_read(&s, None, dir.path());
            assert!(warnings.is_empty(), "{warnings:?}");
            assert!(
                text.contains("info line") && text.contains("api.example.com"),
                "{text}"
            );
            assert!(text.contains("warn line"));
            assert!(!text.contains("debug line"));
            assert!(!text.contains('\u{1b}'), "no colour codes in files");
        }

        #[test]
        fn filter_override_wins() {
            let dir = tempfile::tempdir().unwrap();
            let s = settings(Some(dir.path().join("scribed.log")));
            let (text, _) = log_and_read(&s, Some("debug"), dir.path());
            assert!(text.contains("debug line"), "{text}");

            let dir = tempfile::tempdir().unwrap();
            let s = settings(Some(dir.path().join("scribed.log")));
            let (text, _) = log_and_read(&s, Some("warn"), dir.path());
            assert!(
                text.contains("warn line") && !text.contains("info line"),
                "{text}"
            );
        }

        #[test]
        fn rejects_bad_filters() {
            let Err(err) = build(&settings(None), Some("scribed=loud")) else {
                panic!("the filter should be rejected");
            };
            assert!(
                err.to_string()
                    .contains("invalid log filter \"scribed=loud\""),
                "{err}"
            );
        }

        #[test]
        fn writes_json_lines() {
            let dir = tempfile::tempdir().unwrap();
            let mut s = settings(Some(dir.path().join("scribed.log")));
            s.format = LogFormat::Json;
            let (text, _) = log_and_read(&s, None, dir.path());
            let line = text.lines().find(|l| l.contains("info line")).unwrap();
            assert!(line.starts_with('{') && line.ends_with('}'), "{line}");
            assert!(line.contains("\"level\":\"INFO\""), "{line}");
            assert!(line.contains("\"host\":\"api.example.com\""), "{line}");
        }

        #[test]
        fn daily_rotation_writes_dated_files() {
            let dir = tempfile::tempdir().unwrap();
            let mut s = settings(Some(dir.path().join("logs").join("scribed.log")));
            s.rotate = Rotate::Daily;
            let (text, warnings) = log_and_read(&s, None, &dir.path().join("logs"));
            assert!(warnings.is_empty(), "{warnings:?}");
            assert!(text.contains("info line"), "{text}");
            let names: Vec<String> = fs::read_dir(dir.path().join("logs"))
                .unwrap()
                .map(|e| e.unwrap().file_name().to_string_lossy().into_owned())
                .collect();
            assert!(
                names.iter().any(|n| n.starts_with("scribed.")
                    && n.ends_with(".log")
                    && n != "scribed.log"),
                "{names:?}"
            );
        }

        #[test]
        fn falls_back_to_stderr_when_the_file_cannot_be_written() {
            let dir = tempfile::tempdir().unwrap();
            let blocker = dir.path().join("not-a-dir");
            fs::write(&blocker, "").unwrap();
            let s = settings(Some(blocker.join("scribed.log")));
            let setup = build(&s, None).unwrap();
            assert_eq!(setup.warnings.len(), 1);
            assert!(
                setup.warnings[0].contains("logging to stderr instead"),
                "{:?}",
                setup.warnings
            );
        }

        #[test]
        fn stderr_only_and_system_outputs_build() {
            assert!(build(&settings(None), None).unwrap().warnings.is_empty());

            let mut s = settings(None);
            s.output = LogOutput::System;
            let setup = build(&s, None).unwrap();
            // journald may be missing (containers, CI); then there is exactly one warning.
            assert!(setup.warnings.len() <= 1, "{:?}", setup.warnings);
        }

        #[test]
        fn size_rotation_keeps_the_newest_files() {
            let dir = tempfile::tempdir().unwrap();
            let path = dir.path().join("scribed.log");
            let mut f = SizeRotatingFile::open(&path, 10, 2).unwrap();
            for chunk in ["aaaaaaaa\n", "bbbbbbbb\n", "cccccccc\n", "dddddddd\n"] {
                f.write_all(chunk.as_bytes()).unwrap();
            }
            f.flush().unwrap();
            assert_eq!(fs::read_to_string(&path).unwrap(), "dddddddd\n");
            assert_eq!(
                fs::read_to_string(dir.path().join("scribed.log.1")).unwrap(),
                "cccccccc\n"
            );
            assert_eq!(
                fs::read_to_string(dir.path().join("scribed.log.2")).unwrap(),
                "bbbbbbbb\n"
            );
            assert!(
                !dir.path().join("scribed.log.3").exists(),
                "only `keep` rotated files"
            );
        }

        #[test]
        fn size_rotation_appends_to_an_existing_file() {
            let dir = tempfile::tempdir().unwrap();
            let path = dir.path().join("scribed.log");
            fs::write(&path, "old\n").unwrap();
            let mut f = SizeRotatingFile::open(&path, 1 << 20, 3).unwrap();
            f.write_all(b"new\n").unwrap();
            assert_eq!(fs::read_to_string(&path).unwrap(), "old\nnew\n");
        }
    }
}
