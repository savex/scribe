//! Config reload (`scribe daemon reset --config`, SIGHUP; specs 8.5.2): re-read the file `scribed`
//! started with, run the same checks, and split the changes into what applies live and what needs
//! a restart. All-or-nothing: a file that fails any check changes nothing.

use super::context;
use super::load::{load, ConfigError, Source};
use super::resolve::{module_settings, resolve, HostFacts, Settings};
use scribe_core::platform::DefaultPaths;

/// What a reload would change.
#[derive(Debug, Clone)]
pub struct ReloadPlan {
    /// The running settings with every live change applied (restart-only changes left out, so a
    /// later reload reports them again until scribed restarts).
    pub settings: Settings,
    /// Config keys that changed and apply now.
    pub applied: Vec<&'static str>,
    /// Config keys that changed but only apply after a restart.
    pub needs_restart: Vec<&'static str>,
}

impl ReloadPlan {
    pub fn changed(&self, key: &str) -> bool {
        self.applied.contains(&key)
    }
}

/// Read and check the file `running` came from, as at start.
pub fn reread(running: &Settings) -> Result<Settings, ConfigError> {
    let source: Source = running.source.clone();
    let defaults = DefaultPaths::current().map_err(|e| {
        ConfigError::new(
            &source,
            format!("cannot locate scribed's default paths: {e}"),
        )
    })?;
    let ctx = context();
    let (config, text) = load(&source, &ctx)?;
    let mut settings = resolve(config, source, &defaults, &HostFacts)?;
    settings.modules = module_settings(&settings.config, &text, &ctx);
    settings.text = text;
    Ok(settings)
}

/// Compare `new` with `running`.
pub fn plan(running: &Settings, new: Settings) -> ReloadPlan {
    let (old, cfg) = (&running.config, &new.config);
    let mut applied = Vec::new();
    let mut needs_restart = Vec::new();
    let mut live = |key, changed: bool| {
        if changed {
            applied.push(key);
        }
    };
    live("mode", old.mode != cfg.mode);
    live("profile", old.profile != cfg.profile);
    live("policy", old.policy != cfg.policy);
    live(
        "modules",
        old.modules != cfg.modules || old.privacy != cfg.privacy,
    );
    live("daemon", old.daemon != cfg.daemon);
    live("log.level", old.log.level != cfg.log.level);
    let mut restart = |key, changed: bool| {
        if changed {
            needs_restart.push(key);
        }
    };
    restart("data_dir", running.data_dir != new.data_dir);
    restart("api", old.api != cfg.api);
    restart("sensor", old.sensor != cfg.sensor);
    restart("storage.state", old.storage.state != cfg.storage.state);
    restart("storage.sinks", old.storage.sinks != cfg.storage.sinks);
    restart(
        "storage limits (cache, buffer, spool)",
        old.storage.cache != cfg.storage.cache
            || old.storage.buffer != cfg.storage.buffer
            || old.storage.spool != cfg.storage.spool,
    );
    restart(
        "log (file, output, format, rotation)",
        old.log.file != cfg.log.file
            || old.log.output != cfg.log.output
            || old.log.format != cfg.log.format
            || old.log.rotate != cfg.log.rotate
            || old.log.max_size != cfg.log.max_size
            || old.log.keep != cfg.log.keep,
    );

    let mut settings = running.clone();
    settings.config.mode = cfg.mode;
    settings.mode = new.mode;
    settings.config.profile = cfg.profile.clone();
    settings.profile = new.profile.clone();
    settings.config.policy = cfg.policy.clone();
    settings.config.modules = cfg.modules.clone();
    settings.config.privacy = cfg.privacy.clone();
    settings.config.daemon = cfg.daemon.clone();
    settings.config.log.level = cfg.log.level;
    settings.log.level = new.log.level;
    settings.modules = new.modules;
    settings.text = new.text;
    settings.warnings = new.warnings;
    ReloadPlan {
        settings,
        applied,
        needs_restart,
    }
}
