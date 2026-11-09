//! Interface between `scribed` and its modules (specs 7.4).
//!
//! A module is compiled in, chosen by Cargo feature, and registered with the daemon's
//! `ModuleRegistry`. It describes itself with a [`Manifest`], reads its own config section through
//! [`ConfigDoc`], and produces data only through the generic outputs: flow notes (from a
//! [`FlowHook`]), module records, metric samples and module state (through the [`Emitter`]).
//! New modules must pass `scribe-module-conformance`.

mod config;
mod manifest;

use std::collections::BTreeMap;
use std::sync::Arc;
use std::time::{Duration, SystemTime};

use scribe_core::{Clock, FlowEvent};
use serde_json::Value;

pub use config::{ConfigDoc, SectionError};
pub use manifest::{Access, Call, Manifest, ManifestError, Needs, Privilege, RecordKind};
pub use scribe_core::{MetricSample, ModuleRecord, Notes};

/// How a new config was applied.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Reload {
    /// Every change took effect.
    Live,
    /// These settings changed but only apply after a restart (the old values stay in use).
    NeedsRestart(Vec<String>),
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ModuleHealth {
    Healthy,
    Degraded(String),
    Unhealthy(String),
}

#[derive(Debug, thiserror::Error)]
pub enum ModuleError {
    #[error(transparent)]
    Config(#[from] SectionError),
    #[error("cannot start: {0}")]
    Start(String),
    #[error("unsupported: {0}")]
    Unsupported(String),
}

/// Where a module sends what it produces. Calls never block: the daemon queues the data and
/// counts drops when a queue is full.
pub trait Emitter: Send + Sync {
    fn record(&self, record: ModuleRecord);
    fn metric(&self, sample: MetricSample);
    /// Store `value` under `key` in this module's state (`module_state`).
    fn put_state(&self, key: &str, value: Value);
}

/// What a module gets when it starts.
#[derive(Clone)]
pub struct ModuleContext {
    pub clock: Arc<dyn Clock>,
    pub emitter: Arc<dyn Emitter>,
    /// This module's state as stored, read by the daemon before `start`.
    pub state: BTreeMap<String, Value>,
}

impl ModuleContext {
    pub fn now(&self) -> SystemTime {
        self.clock.now()
    }
}

/// A flow as a hook sees it.
#[derive(Debug, Clone, Copy)]
pub struct FlowContext<'a> {
    pub event: &'a FlowEvent,
    /// The first client bytes of the flow or of this payload chunk (`FlowKind::Payload`),
    /// when the sensor saw them and some enabled module needs payload.
    pub head: Option<&'a [u8]>,
}

/// A policy input from a module. `reason` is namespaced with the module id
/// (e.g. `url.credentials_in_query`); its score comes from `[policy.scores]`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Signal {
    pub reason: String,
    pub detail: Option<String>,
}

/// What a hook returns for one flow.
#[derive(Debug, Clone, Default, PartialEq)]
pub struct HookOutput {
    /// Attached to the flow under the module's id.
    pub note: Option<Value>,
    pub signals: Vec<Signal>,
}

impl HookOutput {
    pub fn none() -> Self {
        Self::default()
    }

    pub fn note(value: Value) -> Self {
        Self {
            note: Some(value),
            signals: Vec::new(),
        }
    }
}

/// Sees each flow. Must be fast (the daemon enforces a time budget) and must never panic on
/// any input; a panic disables the module.
pub trait FlowHook: Send + Sync {
    fn on_flow(&self, flow: &FlowContext<'_>) -> HookOutput;
}

/// Produces data on its own schedule (timers, kernel feeds).
pub trait Source: Send {
    /// How often the daemon calls [`Source::tick`].
    fn interval(&self) -> Duration;
    fn tick(&mut self, now: SystemTime);
}

/// A scribed module. Lifecycle: `configure` → `start` → (`pause` ↔ `resume`, `configure`)* → `stop`;
/// `start` may follow `stop` again.
pub trait Module: Send + Sync {
    fn manifest(&self) -> &Manifest;
    /// Read this module's section (`[modules.<id>]`); called before `start` and on every reload.
    fn configure(&mut self, doc: &ConfigDoc<'_>) -> Result<Reload, ModuleError>;
    fn start(&mut self, ctx: ModuleContext) -> Result<(), ModuleError>;
    /// Stop producing anything until `resume` (hibernation).
    fn pause(&mut self);
    fn resume(&mut self);
    fn stop(&mut self);
    fn health(&self) -> ModuleHealth;
    /// The settings in use, as the `[modules.<id>]` table `scribed --check-config` prints.
    fn effective_config(&self) -> Option<toml::Table> {
        None
    }
    fn flow_hook(&self) -> Option<&dyn FlowHook> {
        None
    }
    fn source(&mut self) -> Option<&mut dyn Source> {
        None
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn hook_output_helpers() {
        assert_eq!(HookOutput::none(), HookOutput::default());
        let out = HookOutput::note(json!("x"));
        assert_eq!(out.note, Some(json!("x")));
        assert!(out.signals.is_empty());
    }

    #[test]
    fn errors_read_well() {
        assert_eq!(
            ModuleError::Start("no probe host".into()).to_string(),
            "cannot start: no probe host"
        );
        assert_eq!(
            ModuleError::Unsupported("kernel probes on macOS".into()).to_string(),
            "unsupported: kernel probes on macOS"
        );
    }
}
