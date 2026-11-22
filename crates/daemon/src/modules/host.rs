//! Runs the enabled modules: lifecycle, flow hooks with a time budget, sources on their
//! schedule, and isolation (a panicking module is switched off, the rest keep running; NFR-20).

use std::collections::BTreeMap;
use std::panic::{self, AssertUnwindSafe};
use std::path::PathBuf;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant, SystemTime};

use scribe_core::{Clock, Notes, Observation};
use scribe_module_api::{
    ConfigDoc, Emitter, FlowContext, Module, ModuleContext, ModuleError, ModuleHealth, Reload,
    Signal,
};
use serde_json::Value;

/// Default time budget for one flow-hook call.
pub const HOOK_BUDGET: Duration = Duration::from_millis(1);

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RunState {
    Configured,
    Running,
    Paused,
    /// Switched off after a fault; the reason is kept for status.
    Failed(String),
    Stopped,
}

/// What `scribe daemon status` and `scribe modules` show per module.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ModuleStatus {
    pub id: &'static str,
    pub version: u32,
    pub state: RunState,
    pub health: ModuleHealth,
    /// Hook calls over the time budget.
    pub over_budget: u64,
}

struct Slot {
    module: Box<dyn Module>,
    state: RunState,
    failed: AtomicBool,
    failure: std::sync::Mutex<Option<String>>,
    over_budget: AtomicU64,
    next_tick: Option<SystemTime>,
}

impl Slot {
    fn active(&self) -> bool {
        self.state == RunState::Running && !self.failed.load(Ordering::Relaxed)
    }
}

pub struct ModuleHost {
    slots: Vec<Slot>,
    budget: Duration,
    clock: Option<Arc<dyn Clock>>,
    data_dir: Option<PathBuf>,
}

impl ModuleHost {
    /// Configure each module from `doc`. The config was checked already, so an error here is a bug
    /// in the module; it is returned with the module's id.
    pub fn new(modules: Vec<Box<dyn Module>>, doc: &ConfigDoc<'_>) -> Result<Self, String> {
        let mut slots = Vec::new();
        for mut module in modules {
            let id = module.manifest().id;
            module
                .configure(doc)
                .map_err(|e| format!("module {id}: {e}"))?;
            slots.push(Slot {
                module,
                state: RunState::Configured,
                failed: AtomicBool::new(false),
                failure: std::sync::Mutex::new(None),
                over_budget: AtomicU64::new(0),
                next_tick: None,
            });
        }
        Ok(Self {
            slots,
            budget: HOOK_BUDGET,
            clock: None,
            data_dir: None,
        })
    }

    pub fn with_budget(mut self, budget: Duration) -> Self {
        self.budget = budget;
        self
    }

    /// The directory modules keep their files in (`data_dir`).
    pub fn with_data_dir(mut self, dir: PathBuf) -> Self {
        self.data_dir = Some(dir);
        self
    }

    pub fn ids(&self) -> Vec<&'static str> {
        self.slots.iter().map(|s| s.module.manifest().id).collect()
    }

    /// Whether any running module needs payload bytes past the ClientHello / `Host` header.
    pub fn needs_payload(&self) -> bool {
        self.slots
            .iter()
            .any(|s| s.active() && s.module.manifest().needs.payload)
    }

    /// Start every module. `emitter` gives each module its output channel; `state` its stored
    /// state. A module that fails to start is marked failed; the others still start.
    pub fn start(
        &mut self,
        clock: Arc<dyn Clock>,
        emitter: impl Fn(&'static str) -> Arc<dyn Emitter>,
        mut state: BTreeMap<String, BTreeMap<String, Value>>,
    ) -> Vec<(&'static str, Result<(), ModuleError>)> {
        let now = clock.now();
        let mut results = Vec::new();
        for slot in &mut self.slots {
            let id = slot.module.manifest().id;
            let ctx = ModuleContext {
                clock: clock.clone(),
                emitter: emitter(id),
                state: state.remove(id).unwrap_or_default(),
                data_dir: self.data_dir.clone(),
            };
            let started = guarded(|| slot.module.start(ctx)).unwrap_or_else(|why| {
                Err(ModuleError::Start(format!(
                    "panicked while starting: {why}"
                )))
            });
            match &started {
                Ok(()) => {
                    slot.state = RunState::Running;
                    slot.failed.store(false, Ordering::Relaxed);
                    slot.next_tick = slot.module.source().map(|s| now + s.interval());
                }
                Err(e) => slot.state = RunState::Failed(e.to_string()),
            }
            results.push((id, started));
        }
        self.clock = Some(clock);
        results
    }

    /// Run every active flow hook on one observation. Notes are keyed by module id.
    pub fn on_flow(&self, obs: &Observation) -> (Notes, Vec<Signal>) {
        let mut notes = Notes::new();
        let mut signals = Vec::new();
        let flow = FlowContext {
            event: &obs.event,
            head: obs.head.as_deref(),
        };
        for slot in self.slots.iter().filter(|s| s.active()) {
            let Some(hook) = slot.module.flow_hook() else {
                continue;
            };
            let started = Instant::now();
            match guarded(|| hook.on_flow(&flow)) {
                Ok(out) => {
                    if started.elapsed() > self.budget {
                        slot.over_budget.fetch_add(1, Ordering::Relaxed);
                    }
                    if let Some(note) = out.note {
                        notes.insert(slot.module.manifest().id, note);
                    }
                    signals.extend(out.signals);
                }
                Err(why) => {
                    slot.failed.store(true, Ordering::Relaxed);
                    *slot.failure.lock().unwrap() = Some(format!("flow hook panicked: {why}"));
                    tracing::error!(
                        module = slot.module.manifest().id,
                        "flow hook panicked ({why}); module switched off"
                    );
                }
            }
        }
        (notes, signals)
    }

    /// Tick every source whose interval has passed.
    pub fn tick(&mut self) {
        let Some(clock) = self.clock.clone() else {
            return;
        };
        let now = clock.now();
        for slot in &mut self.slots {
            if !slot.active() || slot.next_tick.is_none_or(|t| t > now) {
                continue;
            }
            let Some(source) = slot.module.source() else {
                continue;
            };
            let interval = source.interval();
            if let Err(why) = guarded(|| source.tick(now)) {
                slot.failed.store(true, Ordering::Relaxed);
                *slot.failure.lock().unwrap() = Some(format!("source panicked: {why}"));
            }
            slot.next_tick = Some(now + interval);
        }
    }

    /// Re-read every module's section; returns what needs a restart.
    pub fn reconfigure(&mut self, doc: &ConfigDoc<'_>) -> Result<Vec<String>, String> {
        let mut restart = Vec::new();
        for slot in &mut self.slots {
            let id = slot.module.manifest().id;
            match slot.module.configure(doc) {
                Ok(Reload::Live) => {}
                Ok(Reload::NeedsRestart(keys)) => restart.extend(keys),
                Err(e) => return Err(format!("module {id}: {e}")),
            }
        }
        Ok(restart)
    }

    pub fn pause(&mut self) {
        for slot in self
            .slots
            .iter_mut()
            .filter(|s| s.state == RunState::Running)
        {
            slot.module.pause();
            slot.state = RunState::Paused;
        }
    }

    pub fn resume(&mut self) {
        for slot in self
            .slots
            .iter_mut()
            .filter(|s| s.state == RunState::Paused)
        {
            slot.module.resume();
            slot.state = RunState::Running;
        }
    }

    pub fn stop(&mut self) {
        for slot in &mut self.slots {
            if matches!(slot.state, RunState::Running | RunState::Paused) {
                let _ = guarded(|| slot.module.stop());
                slot.state = RunState::Stopped;
            }
        }
    }

    pub fn status(&self) -> Vec<ModuleStatus> {
        self.slots
            .iter()
            .map(|slot| {
                let failure = slot.failure.lock().unwrap().clone();
                let (state, health) = match failure {
                    Some(why) if slot.failed.load(Ordering::Relaxed) => {
                        (RunState::Failed(why.clone()), ModuleHealth::Degraded(why))
                    }
                    _ => {
                        let health = match &slot.state {
                            RunState::Failed(why) => ModuleHealth::Unhealthy(why.clone()),
                            _ => slot.module.health(),
                        };
                        (slot.state.clone(), health)
                    }
                };
                ModuleStatus {
                    id: slot.module.manifest().id,
                    version: slot.module.manifest().version,
                    state,
                    health,
                    over_budget: slot.over_budget.load(Ordering::Relaxed),
                }
            })
            .collect()
    }
}

/// Run `f`, turning a panic into its message (printed once through tracing, not stderr).
fn guarded<T>(f: impl FnOnce() -> T) -> Result<T, String> {
    panic::catch_unwind(AssertUnwindSafe(f)).map_err(|p| {
        p.downcast_ref::<&str>()
            .map(|s| s.to_string())
            .or_else(|| p.downcast_ref::<String>().cloned())
            .unwrap_or_else(|| "panic".into())
    })
}
