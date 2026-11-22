//! scribed configuration: find, parse, check and resolve `scribe.toml` (config format version 1).
//!
//! Order of lookup: `--config`, then `SCRIBE_CONFIG`, then the OS default path; with no file,
//! the built-in defaults, which equal `config/scribe.toml`.

mod load;
mod model;
pub mod reload;
mod resolve;

#[cfg(test)]
mod tests;

use std::ffi::OsString;
use std::path::Path;

use scribe_core::platform::{DefaultPaths, Os};
use scribe_storage_manager::Registry;

pub use load::{discover, load, parse, validate, ConfigError, Context, Source};
pub use model::*;
pub use resolve::{resolve, HostFacts, Limits, LogSettings, Settings, SystemFacts};

/// Checks for this binary on this OS.
pub fn context() -> Context {
    Context {
        os: Os::current(),
        storage_kinds: Registry::with_builtin().kinds().collect(),
        modules: crate::modules::builtin(),
    }
}

/// Finds, reads, checks and resolves the config for this host.
pub fn load_settings(flag: Option<&Path>, env: Option<OsString>) -> Result<Settings, ConfigError> {
    let defaults = DefaultPaths::current().map_err(|e| {
        ConfigError::new(
            &Source::BuiltIn,
            format!("cannot locate scribed's default paths: {e}"),
        )
    })?;
    let source = discover(flag, env, &defaults.config_file)?;
    let ctx = context();
    let (config, text) = load(&source, &ctx)?;
    let mut settings = resolve(config, source, &defaults, &HostFacts)?;
    settings.modules = resolve::module_settings(&settings.config, &text, &ctx);
    settings.text = text;
    Ok(settings)
}
