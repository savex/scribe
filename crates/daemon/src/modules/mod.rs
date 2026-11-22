//! The modules built into this scribed (Cargo features, specs 7.4.1), the host that runs them and
//! the queue that carries their output to storage.

mod host;
mod output;

pub use host::{ModuleHost, ModuleStatus, RunState, HOOK_BUDGET};
pub use output::{Output, OutputQueue, QueueEmitter, QUEUE};

use std::fmt;

use scribe_module_api::Module;

/// A built-in module: its id and how to make a fresh instance.
#[derive(Clone, Copy)]
pub struct ModuleSpec {
    pub id: &'static str,
    pub make: fn() -> Box<dyn Module>,
}

impl fmt::Debug for ModuleSpec {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ModuleSpec").field("id", &self.id).finish()
    }
}

impl ModuleSpec {
    /// The record kinds this module declares, e.g. `url.request`.
    pub fn record_kinds(&self) -> Vec<&'static str> {
        (self.make)()
            .manifest()
            .records
            .iter()
            .map(|r| r.name)
            .collect()
    }
}

/// Fresh instances of the enabled modules, in `enabled` order; unknown ids are skipped (the
/// config check has rejected them already).
pub fn instantiate(specs: &[ModuleSpec], enabled: &[String]) -> Vec<Box<dyn Module>> {
    enabled
        .iter()
        .filter_map(|id| specs.iter().find(|s| s.id == id))
        .map(|s| (s.make)())
        .collect()
}

/// Every module compiled into this binary, in a stable order.
#[allow(clippy::vec_init_then_push)] // one feature-gated `push` per module
pub fn builtin() -> Vec<ModuleSpec> {
    #[allow(unused_mut)]
    let mut specs = Vec::new();
    #[cfg(feature = "url")]
    specs.push(ModuleSpec {
        id: scribe_module_url::ID,
        make: || Box::new(scribe_module_url::UrlModule::default()),
    });
    specs
}
