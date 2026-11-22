//! Backend-independent test suite for [`Module`] implementations (specs 7.4.7).
//!
//! A module crate describes its configs and sample traffic in a [`ModuleCase`] and calls
//! [`run_module_suite`]. The suite collects every failure instead of stopping at the first one.
//! A module must pass it before it can be registered in the daemon's `ModuleRegistry`.

use std::cell::Cell;
use std::collections::BTreeSet;
use std::panic::{self, AssertUnwindSafe};
use std::sync::Once;
use std::time::{Duration, Instant};

use scribe_core::{Observation, HEAD_MAX};
use scribe_module_api::{ConfigDoc, FlowContext, HookOutput, Module, ModuleError, Reload};
use scribe_test_support::{module_context, FakeClock, RecordingEmitter};

/// A config that must be rejected: the text, the 1-based line of the error, and a piece of the
/// message.
#[derive(Debug, Clone)]
pub struct BadConfig {
    pub text: &'static str,
    pub line: usize,
    pub contains: &'static str,
}

pub struct ModuleCase {
    /// Builds a fresh, unconfigured module.
    pub make: Box<dyn Fn() -> Box<dyn Module>>,
    /// A valid config file (it may include other sections).
    pub config: &'static str,
    /// A second config applied while running, and what `configure` must report.
    pub reload: Option<(&'static str, Reload)>,
    pub bad_configs: Vec<BadConfig>,
    /// Sample traffic for the flow hook.
    pub flows: Vec<Observation>,
    /// Longest average time per hook call (debug builds).
    pub hook_budget: Duration,
    /// Random payloads to feed the hook.
    pub fuzz_runs: usize,
}

impl ModuleCase {
    pub fn new(make: impl Fn() -> Box<dyn Module> + 'static) -> Self {
        Self {
            make: Box::new(make),
            config: "",
            reload: None,
            bad_configs: Vec::new(),
            flows: default_flows(),
            hook_budget: Duration::from_millis(2),
            fuzz_runs: 500,
        }
    }
}

/// TLS, plaintext HTTP, payload-only and closing flows, with and without payload bytes.
pub fn default_flows() -> Vec<Observation> {
    use scribe_test_support::flow;
    vec![
        flow("192.0.2.10:443")
            .host("api.example.com")
            .tls()
            .observe(),
        flow("192.0.2.20:80")
            .http_get("http://plain.example.com/download?id=42")
            .observe(),
        flow("192.0.2.20:80")
            .http_get("http://plain.example.com/a?token=secret&b=2")
            .observe(),
        flow("198.51.100.7:8443")
            .plaintext()
            .payload(b"\x00\x01binary")
            .observe(),
        flow("192.0.2.11:53").udp().plaintext().observe(),
        flow("192.0.2.20:80").close().observe(),
    ]
}

/// Runs every check; returns all failures.
pub fn run_module_suite(case: &ModuleCase) -> Result<(), Vec<String>> {
    let mut failures = Vec::new();
    let mut fail = |msg: String| failures.push(msg);

    // Manifest.
    let mut module = (case.make)();
    let manifest = module.manifest().clone();
    let id = manifest.id;
    if let Err(err) = manifest.validate() {
        fail(err.to_string());
    }
    if manifest.needs.payload && module.flow_hook().is_none() {
        fail(format!("{id}: needs payload but has no flow hook"));
    }

    // Config: defaults, the given config, bad configs with their lines.
    match module.configure(&ConfigDoc::new("")) {
        Ok(Reload::Live) => {}
        other => fail(format!("{id}: empty config must apply live, got {other:?}")),
    }
    match module.configure(&ConfigDoc::new(case.config)) {
        Ok(Reload::Live) => {}
        other => fail(format!("{id}: first config must apply live, got {other:?}")),
    }
    for bad in &case.bad_configs {
        let mut fresh = (case.make)();
        match fresh.configure(&ConfigDoc::new(bad.text)) {
            Err(ModuleError::Config(err)) => {
                if !err.message.contains(bad.contains) {
                    fail(format!(
                        "{id}: bad config {:?}: message {:?} lacks {:?}",
                        bad.text, err.message, bad.contains
                    ));
                }
                let line = err.span.as_ref().map(|s| line_of(bad.text, s.start));
                if line != Some(bad.line) {
                    fail(format!(
                        "{id}: bad config {:?}: error at line {line:?}, expected {}",
                        bad.text, bad.line
                    ));
                }
            }
            other => fail(format!(
                "{id}: bad config {:?} must fail with a config error, got {other:?}",
                bad.text
            )),
        }
    }

    // Start and run.
    let clock = FakeClock::default();
    let (ctx, emitter) = module_context(&clock);
    if let Err(err) = module.start(ctx) {
        fail(format!("{id}: start failed: {err}"));
        return Err(failures);
    }
    let first = run_flows(module.as_ref(), &case.flows, &manifest, &mut fail);
    tick(module.as_mut(), &clock);
    check_outputs(&emitter, &manifest, &mut fail);
    if let scribe_module_api::ModuleHealth::Unhealthy(why) = module.health() {
        fail(format!("{id}: unhealthy after start: {why}"));
    }

    // Reload while running.
    if let Some((text, expected)) = &case.reload {
        match module.configure(&ConfigDoc::new(text)) {
            Ok(got) if &got == expected => {}
            other => fail(format!(
                "{id}: reload must report {expected:?}, got {other:?}"
            )),
        }
        let _ = module.configure(&ConfigDoc::new(case.config));
    }

    // Pause: nothing comes out.
    module.pause();
    let before = emitter.total();
    let paused = run_flows(module.as_ref(), &case.flows, &manifest, &mut fail);
    tick(module.as_mut(), &clock);
    if emitter.total() != before {
        fail(format!(
            "{id}: emitted {} items while paused",
            emitter.total() - before
        ));
    }
    if paused.iter().any(|o| o != &HookOutput::none()) {
        fail(format!("{id}: flow hook returned output while paused"));
    }
    module.resume();
    let resumed = run_flows(module.as_ref(), &case.flows, &manifest, &mut fail);
    if notes(&resumed) != notes(&first) {
        fail(format!("{id}: notes differ after resume"));
    }

    // Time budget.
    if let Some(hook) = module.flow_hook() {
        let started = Instant::now();
        let mut calls = 0u32;
        for _ in 0..50 {
            for obs in &case.flows {
                let _ = hook.on_flow(&context(obs));
                calls += 1;
            }
            // Clearly over budget already: no need to keep measuring.
            if started.elapsed() > case.hook_budget * calls * 2 {
                break;
            }
        }
        let average = started.elapsed() / calls.max(1);
        if average > case.hook_budget {
            fail(format!(
                "{id}: flow hook takes {average:?} per flow, budget {:?}",
                case.hook_budget
            ));
        }
    }

    // Random payloads never panic.
    if module.flow_hook().is_some() {
        let mut rng = 0x2545_f491_4f6c_dd1d_u64;
        let mut heads: Vec<Vec<u8>> = vec![
            Vec::new(),
            vec![0xff; HEAD_MAX],
            b"GET ".to_vec(),
            b"GET / HTTP/1.1\r\nHost:".to_vec(),
            b"GET http://[::1 HTTP/1.1\r\n\r\n".to_vec(),
        ];
        for _ in 0..case.fuzz_runs {
            rng ^= rng << 13;
            rng ^= rng >> 7;
            rng ^= rng << 17;
            let len = (rng % 300) as usize;
            heads.push((0..len).map(|i| (rng >> (i % 56)) as u8).collect());
        }
        for head in &heads {
            let obs = scribe_test_support::flow("192.0.2.20:80")
                .plaintext()
                .payload(head)
                .observe();
            if let Some(why) = call_hook(module.as_ref(), &obs) {
                fail(format!(
                    "{id}: flow hook panicked on {} random bytes: {why}",
                    head.len()
                ));
                break;
            }
        }
    }

    // Stop, then start again.
    module.stop();
    let (ctx, emitter) = module_context(&clock);
    match module.start(ctx) {
        Ok(()) => {
            let again = run_flows(module.as_ref(), &case.flows, &manifest, &mut fail);
            if notes(&again) != notes(&first) {
                fail(format!("{id}: notes differ after a restart"));
            }
            check_outputs(&emitter, &manifest, &mut fail);
            module.stop();
        }
        Err(err) => fail(format!("{id}: cannot start again after stop: {err}")),
    }

    if failures.is_empty() {
        Ok(())
    } else {
        Err(failures)
    }
}

fn context(obs: &Observation) -> FlowContext<'_> {
    FlowContext {
        event: &obs.event,
        head: obs.head.as_deref(),
    }
}

thread_local! {
    /// Set while this thread runs code whose panics are expected.
    static QUIET: Cell<bool> = const { Cell::new(false) };
}

/// Run `f`, catching a panic without printing it. The panic hook is installed once and stays
/// quiet only on the thread that asked, so tests running in parallel keep their own panic output
/// (workfiles/test-list.md, rule I-4).
fn quietly<T>(f: impl FnOnce() -> T) -> Result<T, String> {
    static INSTALL: Once = Once::new();
    INSTALL.call_once(|| {
        let previous = panic::take_hook();
        panic::set_hook(Box::new(move |info| {
            if !QUIET.with(Cell::get) {
                previous(info);
            }
        }));
    });
    QUIET.with(|q| q.set(true));
    let result = panic::catch_unwind(AssertUnwindSafe(f));
    QUIET.with(|q| q.set(false));
    result.map_err(|p| {
        p.downcast_ref::<&str>()
            .map(|s| s.to_string())
            .or_else(|| p.downcast_ref::<String>().cloned())
            .unwrap_or_else(|| "panic".into())
    })
}

/// `Some(message)` if the hook panicked.
fn call_hook(module: &dyn Module, obs: &Observation) -> Option<String> {
    let hook = module.flow_hook()?;
    quietly(|| hook.on_flow(&context(obs))).err()
}

fn run_flows(
    module: &dyn Module,
    flows: &[Observation],
    manifest: &scribe_module_api::Manifest,
    fail: &mut impl FnMut(String),
) -> Vec<HookOutput> {
    let Some(hook) = module.flow_hook() else {
        return Vec::new();
    };
    let mut out = Vec::new();
    for obs in flows {
        match quietly(|| hook.on_flow(&context(obs))) {
            Ok(output) => {
                for signal in &output.signals {
                    if !signal.reason.starts_with(&format!("{}.", manifest.id)) {
                        fail(format!(
                            "{}: signal '{}' must be named '{}.<reason>'",
                            manifest.id, signal.reason, manifest.id
                        ));
                    }
                }
                out.push(output);
            }
            Err(_) => {
                fail(format!(
                    "{}: flow hook panicked on {:?} {:?}",
                    manifest.id, obs.event.kind, obs.event.security
                ));
                out.push(HookOutput::none());
            }
        }
    }
    out
}

fn tick(module: &mut dyn Module, clock: &FakeClock) {
    if let Some(source) = module.source() {
        let every = source.interval();
        for _ in 0..3 {
            clock.advance(every);
            source.tick(scribe_core::Clock::now(clock));
        }
    }
}

/// Everything emitted is declared, owned by this module and uses its declared schema.
fn check_outputs(
    emitter: &RecordingEmitter,
    manifest: &scribe_module_api::Manifest,
    fail: &mut impl FnMut(String),
) {
    let id = manifest.id;
    let mut reported = BTreeSet::new();
    for r in emitter.records() {
        let problem = if r.module != id {
            Some(format!("record from module '{}'", r.module))
        } else {
            match manifest.record(&r.kind) {
                None => Some(format!("undeclared record kind '{}'", r.kind)),
                Some(k) if k.schema != r.schema => Some(format!(
                    "record '{}' with schema {}, declared {}",
                    r.kind, r.schema, k.schema
                )),
                Some(_) => None,
            }
        };
        if let Some(p) = problem {
            if reported.insert(p.clone()) {
                fail(format!("{id}: {p}"));
            }
        }
    }
    for m in emitter.metrics() {
        if m.module != id || !manifest.metrics.contains(&m.name.as_ref()) {
            let p = format!("undeclared metric '{}'", m.name);
            if reported.insert(p.clone()) {
                fail(format!("{id}: {p}"));
            }
        }
    }
    for (key, _) in emitter.state() {
        if key.is_empty() {
            fail(format!("{id}: empty module state key"));
        }
    }
}

fn notes(outputs: &[HookOutput]) -> Vec<Option<&serde_json::Value>> {
    outputs.iter().map(|o| o.note.as_ref()).collect()
}

fn line_of(text: &str, offset: usize) -> usize {
    text[..offset.min(text.len())].matches('\n').count() + 1
}

/// For module crates that build their own sample flows.
pub use scribe_test_support::{flow, FlowBuilder};
