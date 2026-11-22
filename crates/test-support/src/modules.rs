//! Module doubles: a recording [`Emitter`], well-behaved test modules (a flow hook and a metrics
//! source) and [`MisbehavingModule`], which proves the module conformance suite catches faults.

use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, SystemTime};

use scribe_core::{HumanDuration, MetricSample, ModuleRecord};
use scribe_module_api::{
    ConfigDoc, FlowContext, FlowHook, HookOutput, Manifest, Module, ModuleContext, ModuleError,
    ModuleHealth, RecordKind, Reload, SectionError, Signal, Source,
};
use serde::Deserialize;
use serde_json::{json, Value};

use crate::FakeClock;

/// Keeps everything a module emits.
#[derive(Debug, Default)]
pub struct RecordingEmitter {
    records: Mutex<Vec<ModuleRecord>>,
    metrics: Mutex<Vec<MetricSample>>,
    state: Mutex<Vec<(String, Value)>>,
}

impl RecordingEmitter {
    pub fn records(&self) -> Vec<ModuleRecord> {
        self.records.lock().unwrap().clone()
    }

    pub fn metrics(&self) -> Vec<MetricSample> {
        self.metrics.lock().unwrap().clone()
    }

    pub fn state(&self) -> Vec<(String, Value)> {
        self.state.lock().unwrap().clone()
    }

    /// Records + metrics + state writes so far.
    pub fn total(&self) -> usize {
        self.records.lock().unwrap().len()
            + self.metrics.lock().unwrap().len()
            + self.state.lock().unwrap().len()
    }
}

impl scribe_module_api::Emitter for RecordingEmitter {
    fn record(&self, record: ModuleRecord) {
        self.records.lock().unwrap().push(record);
    }

    fn metric(&self, sample: MetricSample) {
        self.metrics.lock().unwrap().push(sample);
    }

    fn put_state(&self, key: &str, value: Value) {
        self.state.lock().unwrap().push((key.to_owned(), value));
    }
}

/// A context backed by a [`FakeClock`] and a fresh [`RecordingEmitter`].
pub fn module_context(clock: &FakeClock) -> (ModuleContext, Arc<RecordingEmitter>) {
    let emitter = Arc::new(RecordingEmitter::default());
    let ctx = ModuleContext {
        clock: Arc::new(clock.clone()),
        emitter: emitter.clone(),
        state: Default::default(),
        data_dir: None,
    };
    (ctx, emitter)
}

/// A module that declares nothing and does nothing.
pub struct NoopModule {
    manifest: Manifest,
}

impl Default for NoopModule {
    fn default() -> Self {
        Self {
            manifest: Manifest::new("noop", 1, "does nothing"),
        }
    }
}

impl Module for NoopModule {
    fn manifest(&self) -> &Manifest {
        &self.manifest
    }
    fn configure(&mut self, _doc: &ConfigDoc<'_>) -> Result<Reload, ModuleError> {
        Ok(Reload::Live)
    }
    fn start(&mut self, _ctx: ModuleContext) -> Result<(), ModuleError> {
        Ok(())
    }
    fn pause(&mut self) {}
    fn resume(&mut self) {}
    fn stop(&mut self) {}
    fn health(&self) -> ModuleHealth {
        ModuleHealth::Healthy
    }
}

#[derive(Debug, Clone, Default, PartialEq, Deserialize)]
#[serde(default, deny_unknown_fields)]
struct TagConfig {
    /// Applies live.
    label: Option<String>,
    /// Needs a restart.
    strict: bool,
}

struct TagHook {
    ctx: Mutex<Option<ModuleContext>>,
    label: Mutex<String>,
    paused: AtomicBool,
    seen: AtomicU64,
}

impl FlowHook for TagHook {
    fn on_flow(&self, flow: &FlowContext<'_>) -> HookOutput {
        if self.paused.load(Ordering::SeqCst) {
            return HookOutput::none();
        }
        let Some(ctx) = self.ctx.lock().unwrap().clone() else {
            return HookOutput::none();
        };
        let n = self.seen.fetch_add(1, Ordering::SeqCst) + 1;
        let bytes = flow.head.map_or(0, <[u8]>::len);
        ctx.emitter.record(ModuleRecord {
            ts: ctx.now(),
            module: "tag".into(),
            kind: "tag.seen".into(),
            schema: 1,
            host: flow.event.hostname.clone(),
            payload: json!({ "bytes": bytes }),
        });
        ctx.emitter.put_state("seen", json!(n));
        let mut out = HookOutput::note(json!(self.label.lock().unwrap().clone()));
        if bytes > 1024 {
            out.signals.push(Signal {
                reason: "tag.large_head".into(),
                detail: Some(bytes.to_string()),
            });
        }
        out
    }
}

/// A well-behaved flow-hook module: notes each flow with its label and records `tag.seen`.
/// `[modules.tag] label` applies live; `strict` needs a restart.
pub struct TagModule {
    manifest: Manifest,
    config: TagConfig,
    started: bool,
    hook: Arc<TagHook>,
}

impl Default for TagModule {
    fn default() -> Self {
        let mut manifest = Manifest::new("tag", 1, "test module: tags flows");
        manifest.records.push(RecordKind {
            name: "tag.seen",
            schema: 1,
        });
        manifest.needs.payload = true;
        Self {
            manifest,
            config: TagConfig::default(),
            started: false,
            hook: Arc::new(TagHook {
                ctx: Mutex::new(None),
                label: Mutex::new("tagged".into()),
                paused: AtomicBool::new(false),
                seen: AtomicU64::new(0),
            }),
        }
    }
}

impl Module for TagModule {
    fn manifest(&self) -> &Manifest {
        &self.manifest
    }

    fn configure(&mut self, doc: &ConfigDoc<'_>) -> Result<Reload, ModuleError> {
        let new: TagConfig = doc.section("tag")?;
        if new.label.as_deref() == Some("") {
            return Err(SectionError::new(
                "label must not be empty",
                doc.span_of(&["modules", "tag", "label"]),
            )
            .into());
        }
        let reload = if self.started && new.strict != self.config.strict {
            Reload::NeedsRestart(vec!["modules.tag.strict".into()])
        } else {
            Reload::Live
        };
        *self.hook.label.lock().unwrap() = new.label.clone().unwrap_or_else(|| "tagged".into());
        let strict = if matches!(reload, Reload::NeedsRestart(_)) {
            self.config.strict
        } else {
            new.strict
        };
        self.config = TagConfig { strict, ..new };
        Ok(reload)
    }

    fn start(&mut self, ctx: ModuleContext) -> Result<(), ModuleError> {
        *self.hook.ctx.lock().unwrap() = Some(ctx);
        self.hook.seen.store(0, Ordering::SeqCst);
        self.hook.paused.store(false, Ordering::SeqCst);
        self.started = true;
        Ok(())
    }

    fn pause(&mut self) {
        self.hook.paused.store(true, Ordering::SeqCst);
    }

    fn resume(&mut self) {
        self.hook.paused.store(false, Ordering::SeqCst);
    }

    fn stop(&mut self) {
        *self.hook.ctx.lock().unwrap() = None;
        self.started = false;
    }

    fn health(&self) -> ModuleHealth {
        ModuleHealth::Healthy
    }

    fn flow_hook(&self) -> Option<&dyn FlowHook> {
        Some(self.hook.as_ref())
    }
}

#[derive(Debug, Clone, Deserialize)]
#[serde(default, deny_unknown_fields)]
struct TicksConfig {
    every: HumanDuration,
}

impl Default for TicksConfig {
    fn default() -> Self {
        Self {
            every: "10s".parse().unwrap(),
        }
    }
}

/// A well-behaved source module with no flow hook: emits metric `ticks.count` on every tick,
/// like a kernel metrics module would. `[modules.ticks] every` sets the interval (restart).
#[derive(Default)]
pub struct TicksModule {
    manifest: Option<Manifest>,
    config: TicksConfig,
    ctx: Option<ModuleContext>,
    paused: bool,
    count: u64,
}

impl TicksModule {
    pub fn new() -> Self {
        let mut manifest = Manifest::new("ticks", 1, "test module: metric source");
        manifest.metrics.push("ticks.count");
        Self {
            manifest: Some(manifest),
            ..Default::default()
        }
    }
}

impl Module for TicksModule {
    fn manifest(&self) -> &Manifest {
        self.manifest.as_ref().expect("use TicksModule::new()")
    }

    fn configure(&mut self, doc: &ConfigDoc<'_>) -> Result<Reload, ModuleError> {
        let new: TicksConfig = doc.section("ticks")?;
        let reload = if self.ctx.is_some()
            && Duration::from(new.every) != Duration::from(self.config.every)
        {
            Reload::NeedsRestart(vec!["modules.ticks.every".into()])
        } else {
            self.config = new;
            Reload::Live
        };
        Ok(reload)
    }

    fn start(&mut self, ctx: ModuleContext) -> Result<(), ModuleError> {
        self.ctx = Some(ctx);
        self.paused = false;
        Ok(())
    }

    fn pause(&mut self) {
        self.paused = true;
    }

    fn resume(&mut self) {
        self.paused = false;
    }

    fn stop(&mut self) {
        self.ctx = None;
    }

    fn health(&self) -> ModuleHealth {
        ModuleHealth::Healthy
    }

    fn source(&mut self) -> Option<&mut dyn Source> {
        Some(self)
    }
}

impl Source for TicksModule {
    fn interval(&self) -> Duration {
        self.config.every.into()
    }

    fn tick(&mut self, now: SystemTime) {
        if self.paused {
            return;
        }
        let Some(ctx) = &self.ctx else { return };
        self.count += 1;
        ctx.emitter.metric(MetricSample {
            ts: now,
            module: "ticks".into(),
            name: "ticks.count".into(),
            labels: Default::default(),
            value: self.count as f64,
        });
    }
}

/// One way a module can break the module contract.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Fault {
    /// The manifest breaks the naming rules.
    BadManifest,
    /// The flow hook panics on some payloads.
    PanicsOnPayload,
    /// Emits a record kind the manifest doesn't declare.
    UndeclaredRecord,
    /// Keeps emitting while paused.
    IgnoresPause,
    /// Accepts any config, so bad configs pass.
    AcceptsBadConfig,
    /// Takes 20 ms per flow.
    Slow,
    /// Fails to start a second time.
    NoRestart,
}

/// [`TagModule`] with one [`Fault`] injected.
pub struct MisbehavingModule {
    inner: TagModule,
    fault: Fault,
    hook: FaultyHook,
    starts: usize,
}

struct FaultyHook {
    fault: Fault,
    inner: Arc<TagHook>,
}

impl MisbehavingModule {
    pub fn new(fault: Fault) -> Self {
        let mut inner = TagModule::default();
        if fault == Fault::BadManifest {
            inner.manifest.records[0].name = "seen";
        }
        let hook = FaultyHook {
            fault,
            inner: inner.hook.clone(),
        };
        Self {
            inner,
            fault,
            hook,
            starts: 0,
        }
    }
}

impl FlowHook for FaultyHook {
    fn on_flow(&self, flow: &FlowContext<'_>) -> HookOutput {
        let inner = &self.inner;
        match self.fault {
            Fault::PanicsOnPayload if flow.head.is_some_and(|h| h.first() == Some(&0xff)) => {
                panic!("cannot parse")
            }
            Fault::UndeclaredRecord => {
                if let Some(ctx) = inner.ctx.lock().unwrap().clone() {
                    ctx.emitter.record(ModuleRecord {
                        ts: ctx.now(),
                        module: "tag".into(),
                        kind: "tag.undeclared".into(),
                        schema: 1,
                        host: None,
                        payload: Value::Null,
                    });
                }
                inner.on_flow(flow)
            }
            Fault::IgnoresPause => {
                let was = inner.paused.swap(false, Ordering::SeqCst);
                let out = inner.on_flow(flow);
                inner.paused.store(was, Ordering::SeqCst);
                out
            }
            Fault::Slow => {
                std::thread::sleep(Duration::from_millis(20));
                inner.on_flow(flow)
            }
            _ => inner.on_flow(flow),
        }
    }
}

impl Module for MisbehavingModule {
    fn manifest(&self) -> &Manifest {
        self.inner.manifest()
    }

    fn configure(&mut self, doc: &ConfigDoc<'_>) -> Result<Reload, ModuleError> {
        match self.inner.configure(doc) {
            Err(_) if self.fault == Fault::AcceptsBadConfig => Ok(Reload::Live),
            other => other,
        }
    }

    fn start(&mut self, ctx: ModuleContext) -> Result<(), ModuleError> {
        self.starts += 1;
        if self.fault == Fault::NoRestart && self.starts > 1 {
            return Err(ModuleError::Start("already used".into()));
        }
        self.inner.start(ctx)
    }

    fn pause(&mut self) {
        self.inner.pause();
    }

    fn resume(&mut self) {
        self.inner.resume();
    }

    fn stop(&mut self) {
        self.inner.stop();
    }

    fn health(&self) -> ModuleHealth {
        self.inner.health()
    }

    fn flow_hook(&self) -> Option<&dyn FlowHook> {
        Some(&self.hook)
    }
}
